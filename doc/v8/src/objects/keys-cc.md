Response:
The user wants a summary of the provided C++ code snippet from `v8/src/objects/keys.cc`. The summary should cover:

1. **Functionality:** What does this code do?
2. **Torque Source:** Is it related to Torque (indicated by `.tq` extension)?
3. **JavaScript Relationship:** How does it relate to JavaScript, and provide a JavaScript example if applicable.
4. **Code Logic Inference:**  Provide example input and output if there's a clear logic.
5. **Common Programming Errors:**  Mention potential errors related to this code's functionality.
6. **Overall Function:** A concise summarization of the code's purpose.

Let's go through the code and break down its functionality:

- **Includes:**  It includes various V8 headers related to objects, API, execution, and heap management. This suggests it's involved in low-level object manipulation within V8.
- **Namespaces:** It operates within the `v8::internal` namespace, confirming its internal V8 nature.
- **Macros:** `RETURN_NOTHING_IF_NOT_SUCCESSFUL` and `RETURN_FAILURE_IF_NOT_SUCCESSFUL` are used for early returns based on the success of function calls.
- **Helper Functions:**
    - `ContainsOnlyValidKeys`: Checks if a `FixedArray` contains only names or numbers.
    - `AddKey`: Adds a key to a `FixedArray` if it's not already present in the `DescriptorArray`.
    - `CombineKeys`: Merges keys from an object's own properties and its prototype chain, avoiding duplicates.
- **`KeyAccumulator` Class:** This seems to be the core component. It's responsible for accumulating keys of an object based on different modes and filters.
    - `GetKeys`:  The main method to retrieve keys. It uses an internal `OrderedHashSet` to store keys.
    - `AddKey`: Adds a single key to the accumulator, handling filtering and potential conversion to array indices.
    - `AddKeys`: Adds multiple keys from a `FixedArray` or an array-like object.
    - `FilterProxyKeys`: Filters keys obtained from a `JSProxy` based on the provided filter.
    - `AddKeysFromJSProxy`: Specifically handles adding keys from a `JSProxy`.
    - `CollectKeys`: Iterates through the prototype chain and collects keys from each object.
    - `HasShadowingKeys`, `IsShadowed`, `AddShadowingKey`:  Deal with tracking shadowed properties.
    - `FilterForEnumerableProperties`, `CollectInterceptorKeysInternal`, `CollectInterceptorKeys`, `CollectOwnElementIndices`: Handle keys provided by interceptors.
- **`FastKeyAccumulator` Class:**  An optimized version of `KeyAccumulator` for faster key retrieval in common cases.
    - `Prepare`: Sets up for fast key collection.
    - `GetKeysFast`:  Attempts to retrieve keys using an optimized path, potentially leveraging the enum cache.
    - `InitializeFastPropertyEnumCache`:  Initializes the fast property enumeration cache for a given map.
    - `GetOwnKeysWithUninitializedEnumLength`: Handles the case where the enum length hasn't been initialized yet.
    - `GetKeysSlow`: Falls back to the regular `KeyAccumulator` if the fast path isn't applicable.
    - `GetKeysWithPrototypeInfoCache`: Leverages the prototype info cache for faster key retrieval.
    - `MayHaveElements`, `TryPrototypeInfoCache`: Helper functions for the fast path.
- **Helper Namespaces:** The anonymous namespace contains functions related to managing the enumeration cache.

**Summary Plan:**

1. **Functionality:** Focus on `KeyAccumulator` and `FastKeyAccumulator` being responsible for collecting object keys, with optimizations for common cases.
2. **Torque:** Clearly state that the file extension is `.cc`, not `.tq`, so it's C++.
3. **JavaScript Relationship:** Explain how this relates to JavaScript's mechanisms for getting object keys (e.g., `Object.keys()`, `for...in` loops). Provide JavaScript examples.
4. **Code Logic Inference:**  Use a simple example of adding properties to an object and how the accumulators would collect them. Show how the prototype chain is considered.
5. **Common Programming Errors:** Think about mistakes developers make when dealing with object properties and enumeration (e.g., expecting a specific order, not considering inherited properties).
6. **Overall Function:**  Summarize its role in V8's property enumeration process.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/keys.h"

#include <optional>

#include "src/api/api-arguments-inl.h"
#include "src/api/api.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/elements-inl.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/prototype-info.h"
#include "src/objects/prototype.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/utils/identity-map.h"
#include "src/zone/zone-hashmap.h"

namespace v8::internal {

#define RETURN_NOTHING_IF_NOT_SUCCESSFUL(call) \
  do {                                         \
    if (!(call)) return Nothing<bool>();       \
  } while (false)

#define RETURN_FAILURE_IF_NOT_SUCCESSFUL(call)          \
  do {                                                  \
    ExceptionStatus status_enum_result = (call);        \
    if (!status_enum_result) return status_enum_result; \
  } while (false)

namespace {

static bool ContainsOnlyValidKeys(DirectHandle<FixedArray> array) {
  int len = array->length();
  for (int i = 0; i < len; i++) {
    Tagged<Object> e = array->get(i);
    if (!(IsName(e) || IsNumber(e))) return false;
  }
  return true;
}

static int AddKey(Tagged<Object> key, DirectHandle<FixedArray> combined_keys,
                  DirectHandle<DescriptorArray> descs, int nof_descriptors,
                  int target) {
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    if (descs->GetKey(i) == key) return 0;
  }
  combined_keys->set(target, key);
  return 1;
}

static Handle<FixedArray> CombineKeys(Isolate* isolate,
                                      Handle<FixedArray> own_keys,
                                      Handle<FixedArray> prototype_chain_keys,
                                      DirectHandle<JSReceiver> receiver,
                                      bool may_have_elements) {
  int prototype_chain_keys_length = prototype_chain_keys->length();
  if (prototype_chain_keys_length == 0) return own_keys;

  Tagged<Map> map = receiver->map();
  int nof_descriptors = map->NumberOfOwnDescriptors();
  if (nof_descriptors == 0 && !may_have_elements) return prototype_chain_keys;

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  int own_keys_length = own_keys.is_null() ? 0 : own_keys->length();
  Handle<FixedArray> combined_keys = isolate->factory()->NewFixedArray(
      own_keys_length + prototype_chain_keys_length);
  if (own_keys_length != 0) {
    FixedArray::CopyElements(isolate, *combined_keys, 0, *own_keys, 0,
                             own_keys_length);
  }
  int target_keys_length = own_keys_length;
  for (int i = 0; i < prototype_chain_keys_length; i++) {
    target_keys_length += AddKey(prototype_chain_keys->get(i), combined_keys,
                                 descs, nof_descriptors, target_keys_length);
  }
  return FixedArray::RightTrimOrEmpty(isolate, combined_keys,
                                      target_keys_length);
}

}  // namespace

// static
MaybeHandle<FixedArray> KeyAccumulator::GetKeys(
    Isolate* isolate, Handle<JSReceiver> object, KeyCollectionMode mode,
    PropertyFilter filter, GetKeysConversion keys_conversion, bool is_for_in,
    bool skip_indices) {
  FastKeyAccumulator accumulator(isolate, object, mode, filter, is_for_in,
                                 skip_indices);
  return accumulator.GetKeys(keys_conversion);
}

Handle<FixedArray> KeyAccumulator::GetKeys(GetKeysConversion convert) {
  if (keys_.is_null()) {
    return isolate_->factory()->empty_fixed_array();
  }
  USE(ContainsOnlyValidKeys);
  Handle<FixedArray> result =
      OrderedHashSet::ConvertToKeysArray(isolate(), keys(), convert);
  DCHECK(ContainsOnlyValidKeys(result));

  if (try_prototype_info_cache_ && !first_prototype_map_.is_null()) {
    Cast<PrototypeInfo>(first_prototype_map_->prototype_info())
        ->set_prototype_chain_enum_cache(*result);
    Map::GetOrCreatePrototypeChainValidityCell(
        Handle<Map>(receiver_->map(), isolate_), isolate_);
    DCHECK(first_prototype_map_->IsPrototypeValidityCellValid());
  }
  return result;
}

Handle<OrderedHashSet> KeyAccumulator::keys() {
  return Cast<OrderedHashSet>(keys_);
}

ExceptionStatus KeyAccumulator::AddKey(Tagged<Object> key,
                                       AddKeyConversion convert) {
  return AddKey(handle(key, isolate_), convert);
}

ExceptionStatus KeyAccumulator::AddKey(Handle<Object> key,
                                       AddKeyConversion convert) {
  if (filter_ == PRIVATE_NAMES_ONLY) {
    if (!IsSymbol(*key)) return ExceptionStatus::kSuccess;
    if (!Cast<Symbol>(*key)->is_private_name())
      return ExceptionStatus::kSuccess;
  } else if (IsSymbol(*key)) {
    if (filter_ & SKIP_SYMBOLS) return ExceptionStatus::kSuccess;
    if (Cast<Symbol>(*key)->is_private()) return ExceptionStatus::kSuccess;
  } else if (filter_ & SKIP_STRINGS) {
    return ExceptionStatus::kSuccess;
  }

  if (IsShadowed(key)) return ExceptionStatus::kSuccess;
  if (keys_.is_null()) {
    keys_ = OrderedHashSet::Allocate(isolate_, 16).ToHandleChecked();
  }
  uint32_t index;
  if (convert == CONVERT_TO_ARRAY_INDEX && IsString(*key) &&
      Cast<String>(key)->AsArrayIndex(&index)) {
    key = isolate_->factory()->NewNumberFromUint(index);
  }
  MaybeHandle<OrderedHashSet> new_set_candidate =
      OrderedHashSet::Add(isolate(), keys(), key);
  Handle<OrderedHashSet> new_set;
  if (!new_set_candidate.ToHandle(&new_set)) {
    CHECK(isolate_->has_exception());
    return ExceptionStatus::kException;
  }
  if (*new_set != *keys_) {
    // The keys_ Set is converted directly to a FixedArray in GetKeys which can
    // be left-trimmer. Hence the previous Set should not keep a pointer to the
    // new one.
    keys_->set(OrderedHashSet::NextTableIndex(), Smi::zero());
    keys_ = new_set;
  }
  return ExceptionStatus::kSuccess;
}

ExceptionStatus KeyAccumulator::AddKeys(DirectHandle<FixedArray> array,
                                        AddKeyConversion convert) {
  int add_length = array->length();
  for (int i = 0; i < add_length; i++) {
    Handle<Object> current(array->get(i), isolate_);
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(AddKey(current, convert));
  }
  return ExceptionStatus::kSuccess;
}

ExceptionStatus KeyAccumulator::AddKeys(Handle<JSObject> array_like,
                                        AddKeyConversion convert) {
  DCHECK(IsJSArray(*array_like) || array_like->HasSloppyArgumentsElements());
  ElementsAccessor* accessor = array_like->GetElementsAccessor();
  return accessor->AddElementsToKeyAccumulator(array_like, this, convert);
}

MaybeHandle<FixedArray> FilterProxyKeys(KeyAccumulator* accumulator,
                                        DirectHandle<JSProxy> owner,
                                        Handle<FixedArray> keys,
                                        PropertyFilter filter,
                                        bool skip_indices) {
  if (filter == ALL_PROPERTIES) {
    // Nothing to do.
    return keys;
  }
  Isolate* isolate = accumulator->isolate();
  int store_position = 0;
  for (int i = 0; i < keys->length(); ++i) {
    Handle<Name> key(Cast<Name>(keys->get(i)), isolate);
    if (Object::FilterKey(*key, filter)) continue;  // Skip this key.
    if (skip_indices) {
      uint32_t index;
      if (key->AsArrayIndex(&index)) continue;  // Skip this key.
    }
    if (filter & ONLY_ENUMERABLE) {
      PropertyDescriptor desc;
      Maybe<bool> found =
          JSProxy::GetOwnPropertyDescriptor(isolate, owner, key, &desc);
      MAYBE_RETURN(found, MaybeHandle<FixedArray>());
      if (!found.FromJust()) continue;
      if (!desc.enumerable()) {
        accumulator->AddShadowingKey(key);
        continue;
      }
    }
    // Keep this key.
    if (store_position != i) {
      keys->set(store_position, *key);
    }
    store_position++;
  }
  return FixedArray::RightTrimOrEmpty(isolate, keys, store_position);
}

// Returns "nothing" in case of exception, "true" on success.
Maybe<bool> KeyAccumulator::AddKeysFromJSProxy(DirectHandle<JSProxy> proxy,
                                               Handle<FixedArray> keys) {
  // Postpone the enumerable check for for-in to the ForInFilter step.
  if (!is_for_in_) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, keys,
        FilterProxyKeys(this, proxy, keys, filter_, skip_indices_),
        Nothing<bool>());
  }
  // https://tc39.es/ecma262/#sec-proxy-object-internal-methods-and-internal-slots-ownpropertykeys
  // As of 10.5.11.9 says, the keys collected from Proxy should not contain
  // any duplicates. And the order of the keys is preserved by the
  // OrderedHashTable.
  RETURN_NOTHING_IF_NOT_SUCCESSFUL(AddKeys(keys, CONVERT_TO_ARRAY_INDEX));
  return Just(true);
}

Maybe<bool> KeyAccumulator::CollectKeys(DirectHandle<JSReceiver> receiver,
                                        Handle<JSReceiver> object) {
  // Proxies have no hidden prototype and we should not trigger the
  // [[GetPrototypeOf]] trap on the last iteration when using
  // AdvanceFollowingProxies.
  if (mode_ == KeyCollectionMode::kOwnOnly && IsJSProxy(*object)) {
    MAYBE_RETURN(CollectOwnJSProxyKeys(receiver, Cast<JSProxy>(object)),
                 Nothing<bool>());
    return Just(true);
  }

  PrototypeIterator::WhereToEnd end = mode_ == KeyCollectionMode::kOwnOnly
                                          ? PrototypeIterator::END_AT_NON_HIDDEN
                                          : PrototypeIterator::END_AT_NULL;
  for (PrototypeIterator iter(isolate_, object, kStartAtReceiver, end);
       !iter.IsAtEnd();) {
    // Start the shadow checks only after the first prototype has added
    // shadowing keys.
    if (HasShadowingKeys()) skip_shadow_check_ = false;
    Handle<JSReceiver> current =
        PrototypeIterator::GetCurrent<JSReceiver>(iter);
    Maybe<bool> result = Just(false);  // Dummy initialization.
    if (IsJSProxy(*current)) {
      result = CollectOwnJSProxyKeys(receiver, Cast<JSProxy>(current));
    } else if (IsWasmObject(*current)) {
      if (mode_ == KeyCollectionMode::kIncludePrototypes) {
        RETURN_FAILURE(isolate_, kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
      } else {
        DCHECK_EQ(KeyCollectionMode::kOwnOnly, mode_);
        DCHECK_EQ(result, Just(false));  // Stop iterating.
      }
    } else {
      DCHECK(IsJSObject(*current));
      result = CollectOwnKeys(receiver, Cast<JSObject>(current));
    }
    MAYBE_RETURN(result, Nothing<bool>());
    if (!result.FromJust()) break;  // |false| means "stop iterating".
    // Iterate through proxies but ignore access checks case on API objects for
    // OWN_ONLY keys handled in CollectOwnKeys.
    if (!iter.AdvanceFollowingProxiesIgnoringAccessChecks()) {
      return Nothing<bool>();
    }
    if (!last_non_empty_prototype_.is_null() &&
        *last_non_empty_prototype_ == *current) {
      break;
    }
  }
  return Just(true);
}

bool KeyAccumulator::HasShadowingKeys() { return !shadowing_keys_.is_null(); }

bool KeyAccumulator::IsShadowed(Handle<Object> key) {
  if (!HasShadowingKeys() || skip_shadow_check_) return false;
  return shadowing_keys_->Has(isolate_, key);
}

void KeyAccumulator::AddShadowingKey(Tagged<Object> key,
                                     AllowGarbageCollection* allow_gc) {
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  AddShadowingKey(handle(key, isolate_));
}
void KeyAccumulator::AddShadowingKey(Handle<Object> key) {
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  if (shadowing_keys_.is_null()) {
    shadowing_keys_ = ObjectHashSet::New(isolate_, 16);
  }
  shadowing_keys_ = ObjectHashSet::Add(isolate(), shadowing_keys_, key);
}

namespace {

void TrySettingEmptyEnumCache(Tagged<JSReceiver> object) {
  Tagged<Map> map = object->map();
  DCHECK_EQ(kInvalidEnumCacheSentinel, map->EnumLength());
  if (!map->OnlyHasSimpleProperties()) return;
  DCHECK(IsJSObjectMap(map));  // Implied by {OnlyHasSimpleProperties}.
  if (map->NumberOfEnumerableProperties() > 0) return;
  map->SetEnumLength(0);
}

bool CheckAndInitializeEmptyEnumCache(Tagged<JSReceiver> object) {
  if (object->map()->EnumLength() == kInvalidEnumCacheSentinel) {
    TrySettingEmptyEnumCache(object);
  }
  if (object->map()->EnumLength() != 0) return false;
  DCHECK(IsJSObject(object));
  return !Cast<JSObject>(object)->HasEnumerableElements();
}
}  // namespace

void FastKeyAccumulator::Prepare() {
  DisallowGarbageCollection no_gc;
  // Directly go for the fast path for OWN_ONLY keys.
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  // Fully walk the prototype chain and find the last prototype with keys.
  is_receiver_simple_enum_ = false;
  has_empty_prototype_ = true;
  only_own_has_simple_elements_ =
      !IsCustomElementsReceiverMap(receiver_->map());
  Tagged<JSReceiver> last_prototype;
  may_have_elements_ = MayHaveElements(*receiver_);
  for (PrototypeIterator iter(isolate_, *receiver_); !iter.IsAtEnd();
       iter.Advance()) {
    Tagged<JSReceiver> current = iter.GetCurrent<JSReceiver>();
    if (!may_have_elements_ || only_own_has_simple_elements_) {
      if (MayHaveElements(current)) {
        may_have_elements_ = true;
        only_own_has_simple_elements_ = false;
      }
    }
    bool has_no_properties = CheckAndInitializeEmptyEnumCache(current);
    if (has_no_properties) continue;
    last_prototype = current;
    has_empty_prototype_ = false;
  }
  // Check if we should try to create/use prototype info cache.
  try_prototype_info_cache_ = TryPrototypeInfoCache(receiver_);
  if (has_prototype_info_cache_) return;
  if (has_empty_prototype_) {
    is_receiver_simple_enum_ =
        receiver_->map()->EnumLength() != kInvalidEnumCacheSentinel &&
        !Cast<JSObject>(*receiver_)->HasEnumerableElements();
  } else if (!last_prototype.is_null()) {
    last_non_empty_prototype_ = handle(last_prototype, isolate_);
  }
}

namespace {

Handle<FixedArray> ReduceFixedArrayTo(Isolate* isolate,
                                      Handle<FixedArray> array, int length) {
  DCHECK_LE(length, array->length());
  if (array->length() == length) return array;
  return isolate->factory()->CopyFixedArrayUpTo(array, length);
}

// Initializes and directly returns the enum cache. Users of this function
// have to make sure to never directly leak the enum cache.
Handle<FixedArray> GetFastEnumPropertyKeys(Isolate* isolate,
                                           DirectHandle<JSObject> object) {
  DirectHandle<Map> map(object->map(), isolate);
  Handle<FixedArray> keys(
      map->instance_descriptors(isolate)->enum_cache()->keys(), isolate);

  // Check if the {map} has a valid enum length, which implies that it
  // must have a valid enum cache as well.
  int enum_length = map->EnumLength();
  if (enum_length != kInvalidEnumCacheSentinel) {
    DCHECK(map->OnlyHasSimpleProperties());
    DCHECK_LE(enum_length, keys->length());
    DCHECK_EQ(enum_length, map->NumberOfEnumerableProperties());
    isolate->counters()->enum_cache_hits()->Increment();
    return ReduceFixedArrayTo(isolate, keys, enum_length);
  }

  // Determine the actual number of enumerable properties of the {map}.
  enum_length = map->NumberOfEnumerableProperties();

  // Check if there's already a shared enum cache on the {map}s
  // DescriptorArray with sufficient number of entries.
  if (enum_length <= keys->length()) {
    if (map->OnlyHasSimpleProperties()) map->SetEnumLength(enum_length);
    isolate->counters()->enum_cache_hits()->Increment();
    return ReduceFixedArrayTo(isolate, keys, enum_length);
  }

  return FastKeyAccumulator::InitializeFastPropertyEnumCache(isolate, map,
                                                             enum_length);
}

template <bool fast_properties>
MaybeHandle<FixedArray> GetOwnKeysWithElements(Isolate* isolate,
                                               Handle<JSObject> object,
                                               GetKeysConversion convert,
                                               bool skip_indices) {
  Handle<FixedArray> keys;
  if (fast_properties) {
    keys = GetFastEnumPropertyKeys(isolate, object);
  } else {
    // TODO(cbruni): preallocate big enough array to also hold elements.
    keys = KeyAccumulator::GetOwnEnumPropertyKeys(isolate, object);
  }

  MaybeHandle<FixedArray> result;
  if (skip_indices) {
    result = keys;
  } else {
    ElementsAccessor* accessor = object->GetElementsAccessor(isolate);
    result = accessor->PrependElementIndices(isolate, object, keys, convert,
                                             ONLY_ENUMERABLE);
  }

  if (v8_flags.trace_for_in_enumerate) {
    PrintF("| strings=%d symbols=0 elements=%u || prototypes>=1 ||\n",
           keys->length(), result.ToHandleChecked()->length() - keys->length());
  }
  return result;
}

}  // namespace

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeys(
    GetKeysConversion keys_conversion) {
  // TODO(v8:9401): We should extend the fast path of KeyAccumulator::GetKeys to
  // also use fast path even when filter = SKIP_SYMBOLS. We used to pass wrong
  // filter to use fast path in cases where we tried to verify all properties
  // are enumerable. However these checks weren't correct and passing the wrong
  // filter led to wrong behaviour.
  if (filter_ == ENUMERABLE_STRINGS) {
    Handle<FixedArray> keys;
    if (GetKeysFast(keys_conversion).ToHandle(&keys)) {
      return keys;
    }
    if (isolate_->has_exception()) return MaybeHandle<FixedArray>();
  }

  if (try_prototype_info_cache_) {
    return GetKeysWithPrototypeInfoCache(keys_conversion);
  }
  return GetKeysSlow(keys_conversion);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysFast(
    GetKeysConversion keys_conversion) {
  bool own_only = has_empty_prototype_ || mode_ == KeyCollectionMode::kOwnOnly;
  Tagged<Map> map = receiver_->map();
  if (!own_only || IsCustomElementsReceiverMap(map)) {
    return MaybeHandle<FixedArray>();
  }

  // From this point on we are certain to only collect own keys.
  DCHECK(IsJSObject(*receiver_));
  Handle<JSObject> object = Cast<JSObject>(receiver_);

  // Do not try to use the enum-cache for dict-mode objects.
  if (map->is_dictionary_map()) {
    return GetOwnKeysWithElements<false>(isolate_, object, keys_conversion,
                                         skip_indices_);
  }
  int enum_length = receiver_->map()->EnumLength();
  if (enum_length == kInvalidEnumCacheSentinel) {
    Handle<FixedArray> keys;
    // Try initializing the enum cache and return own properties.
    if (GetOwnKeysWithUninitializedEnumLength().ToHandle(&keys)) {
      if (v8_flags.trace_for_in_enumerate) {
        PrintF("| strings=%d symbols=0 elements=0 || prototypes>=1 ||\n",
               keys->length());
      }
      is_receiver_simple_enum_ =
          object->map()->EnumLength() != kInvalidEnumCacheSentinel;
      return keys;
    }
  }
  // The properties-only case failed because there were probably elements on the
  // receiver.
  return GetOwnKeysWithElements<true>(isolate_, object, keys_conversion,
                                      skip_indices_);
}

// static
Handle<FixedArray> FastKeyAccumulator::InitializeFastPropertyEnumCache(
    Isolate* isolate, DirectHandle<Map> map, int enum_length,
    AllocationType allocation) {
  DCHECK_EQ(kInvalidEnumCacheSentinel, map->EnumLength());
  DCHECK_GT(enum_length, 0);
  DCHECK_EQ(enum_length, map->NumberOfEnumerableProperties());
  DCHECK(!map->is_dictionary_map());

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);

  // The enum cache should have been a hit if the number of enumerable
  // properties is fewer than what's already in the cache.
  DCHECK_LT(descriptors->enum_cache()->keys()->length(), enum_length);
  isolate->counters()->enum_cache_misses()->Increment();

  // Create the keys array.
  int index = 0;
  bool fields_only = true;
  Handle<FixedArray> keys =
      isolate->factory()->NewFixedArray(enum_length, allocation);
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    DisallowGarbageCollection no_gc;
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.IsDontEnum()) continue;
    Tagged<Object> key = descriptors->GetKey(i);
    if (IsSymbol(key)) continue;
    keys->set(index, key);
    if (details.location() != PropertyLocation::kField) fields_only = false;
    index++;
  }
  DCHECK_EQ(index, keys->length());

  // Optionally also create the indices array.
  DirectHandle<FixedArray> indices = isolate->factory()->empty_fixed_array();
  if (fields_only) {
    indices = isolate->factory()->NewFixedArray(enum_length, allocation);
    index = 0;
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    Tagged<FixedArray> raw_indices = *indices;
    Tagged<DescriptorArray> raw_descriptors = *descriptors;
    for (InternalIndex i : raw_map->IterateOwnDescriptors()) {
      PropertyDetails details = raw_descriptors->GetDetails(i);
      if (details.IsDontEnum()) continue;
      Tagged<Object> key = raw_descriptors->GetKey(i);
      if (IsSymbol(key)) continue;
      DCHECK_EQ(PropertyKind::kData, details.kind());
      DCHECK_EQ(PropertyLocation::kField, details.location());
      FieldIndex field_index = FieldIndex::ForDetails(raw_map, details);
      raw_indices->set(index, Smi::FromInt(field_index.GetLoadByFieldIndex()));
      index++;
    }
    DCHECK_EQ(index, indices->length());
  }

  DescriptorArray::InitializeOrChangeEnumCache(descriptors, isolate, keys,
                                               indices, allocation);
  if (map->OnlyHasSimpleProperties()) map->SetEnumLength(enum_length);
  return keys;
}

MaybeHandle<FixedArray>
FastKeyAccumulator::GetOwnKeysWithUninitializedEnumLength() {
  auto object = Cast<JSObject>(receiver_);
  // Uninitialized enum length
  Tagged<Map> map = object->map();
  if (object->elements() != ReadOnlyRoots(isolate_).empty_fixed_array() &&
      object->elements() !=
          ReadOnlyRoots(isolate_).empty_slow_element_dictionary()) {
    // Assume that there are elements.
    return MaybeHandle<FixedArray>();
  }
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) {
    map->SetEnumLength(0);
    return isolate_->factory()->empty_fixed_array();
  }
  // We have no elements but possibly enumerable property keys, hence we can
  // directly initialize the enum cache.
  Handle<FixedArray> keys = GetFastEnumPropertyKeys(isolate_, object);
  if (is_for_in_) return keys;
  // Do not leak the enum cache as it might end up as an elements backing store.
  return isolate_->factory()->CopyFixedArray(keys);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysSlow(
    GetKeysConversion keys_conversion) {
  KeyAccumulator accumulator(isolate_, mode_, filter_);
  accumulator.set_is_for_in(is_for_in_);
  accumulator.set_skip_indices(skip_indices_);
  accumulator.set_last_non_empty_prototype(last_non_empty_prototype_);
  accumulator.set_may_have_elements(may_have_elements_);
  accumulator.set_first_prototype_map(first_prototype_map_);
  accumulator.set_try_prototype_info_cache(try_prototype_info_cache_);

  MAYBE_RETURN(accumulator.CollectKeys(receiver_, receiver_),
               MaybeHandle<FixedArray>());
  return accumulator.GetKeys(keys_conversion);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysWithPrototypeInfoCache(
    GetKeysConversion keys_conversion) {
  Handle<FixedArray> own_keys;
  if (may_have_elements_) {
    MaybeHandle<FixedArray> maybe_own_keys;
    if (receiver_->map()->is_dictionary_map()) {
      maybe_own_keys = GetOwnKeysWithElements<false>(
          isolate_, Cast<JSObject>(receiver_), keys_conversion, skip_indices_);
    } else {
      maybe_own_keys = GetOwnKeysWithElements<true>(
          isolate_, Cast<JSObject>(receiver_), keys_conversion, skip_indices_);
    }
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, own_keys, maybe_own_keys);
  } else {
    own_keys = KeyAccumulator::GetOwnEnumPropertyKeys(
        isolate_, Cast<JSObject>(receiver_));
  }
  Handle<FixedArray> prototype_chain_keys;
  if (has_prototype_info_cache_) {
    prototype_chain_keys =
        handle(Cast<FixedArray>(
                   Cast<PrototypeInfo>(first_prototype_map_->prototype_info())
                       ->prototype_chain_enum_cache()),
               isolate_);
  } else {
    KeyAccumulator accumulator(isolate_, mode_, filter_);
    accumulator.set_is_for_in(is_for_in_);
    accumulator.set_skip_indices(skip_indices_);
    accumulator.set_last_non_empty_prototype(last_non_empty_prototype_);
    accumulator.set_may_have_elements(may_have_elements_);
    accumulator.set_receiver(receiver_);
    accumulator.set_first_prototype_map(first_prototype_map_);
    accumulator.set_try_prototype_info_cache(try_prototype_info_cache_);
    MAYBE_RETURN(accumulator.CollectKeys(first_prototype_, first_prototype_),
                 MaybeHandle<FixedArray>());
    prototype_chain_keys =
Prompt: 
```
这是目录为v8/src/objects/keys.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/keys.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/keys.h"

#include <optional>

#include "src/api/api-arguments-inl.h"
#include "src/api/api.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/elements-inl.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/prototype-info.h"
#include "src/objects/prototype.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/utils/identity-map.h"
#include "src/zone/zone-hashmap.h"

namespace v8::internal {

#define RETURN_NOTHING_IF_NOT_SUCCESSFUL(call) \
  do {                                         \
    if (!(call)) return Nothing<bool>();       \
  } while (false)

#define RETURN_FAILURE_IF_NOT_SUCCESSFUL(call)          \
  do {                                                  \
    ExceptionStatus status_enum_result = (call);        \
    if (!status_enum_result) return status_enum_result; \
  } while (false)

namespace {

static bool ContainsOnlyValidKeys(DirectHandle<FixedArray> array) {
  int len = array->length();
  for (int i = 0; i < len; i++) {
    Tagged<Object> e = array->get(i);
    if (!(IsName(e) || IsNumber(e))) return false;
  }
  return true;
}

static int AddKey(Tagged<Object> key, DirectHandle<FixedArray> combined_keys,
                  DirectHandle<DescriptorArray> descs, int nof_descriptors,
                  int target) {
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    if (descs->GetKey(i) == key) return 0;
  }
  combined_keys->set(target, key);
  return 1;
}

static Handle<FixedArray> CombineKeys(Isolate* isolate,
                                      Handle<FixedArray> own_keys,
                                      Handle<FixedArray> prototype_chain_keys,
                                      DirectHandle<JSReceiver> receiver,
                                      bool may_have_elements) {
  int prototype_chain_keys_length = prototype_chain_keys->length();
  if (prototype_chain_keys_length == 0) return own_keys;

  Tagged<Map> map = receiver->map();
  int nof_descriptors = map->NumberOfOwnDescriptors();
  if (nof_descriptors == 0 && !may_have_elements) return prototype_chain_keys;

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  int own_keys_length = own_keys.is_null() ? 0 : own_keys->length();
  Handle<FixedArray> combined_keys = isolate->factory()->NewFixedArray(
      own_keys_length + prototype_chain_keys_length);
  if (own_keys_length != 0) {
    FixedArray::CopyElements(isolate, *combined_keys, 0, *own_keys, 0,
                             own_keys_length);
  }
  int target_keys_length = own_keys_length;
  for (int i = 0; i < prototype_chain_keys_length; i++) {
    target_keys_length += AddKey(prototype_chain_keys->get(i), combined_keys,
                                 descs, nof_descriptors, target_keys_length);
  }
  return FixedArray::RightTrimOrEmpty(isolate, combined_keys,
                                      target_keys_length);
}

}  // namespace

// static
MaybeHandle<FixedArray> KeyAccumulator::GetKeys(
    Isolate* isolate, Handle<JSReceiver> object, KeyCollectionMode mode,
    PropertyFilter filter, GetKeysConversion keys_conversion, bool is_for_in,
    bool skip_indices) {
  FastKeyAccumulator accumulator(isolate, object, mode, filter, is_for_in,
                                 skip_indices);
  return accumulator.GetKeys(keys_conversion);
}

Handle<FixedArray> KeyAccumulator::GetKeys(GetKeysConversion convert) {
  if (keys_.is_null()) {
    return isolate_->factory()->empty_fixed_array();
  }
  USE(ContainsOnlyValidKeys);
  Handle<FixedArray> result =
      OrderedHashSet::ConvertToKeysArray(isolate(), keys(), convert);
  DCHECK(ContainsOnlyValidKeys(result));

  if (try_prototype_info_cache_ && !first_prototype_map_.is_null()) {
    Cast<PrototypeInfo>(first_prototype_map_->prototype_info())
        ->set_prototype_chain_enum_cache(*result);
    Map::GetOrCreatePrototypeChainValidityCell(
        Handle<Map>(receiver_->map(), isolate_), isolate_);
    DCHECK(first_prototype_map_->IsPrototypeValidityCellValid());
  }
  return result;
}

Handle<OrderedHashSet> KeyAccumulator::keys() {
  return Cast<OrderedHashSet>(keys_);
}

ExceptionStatus KeyAccumulator::AddKey(Tagged<Object> key,
                                       AddKeyConversion convert) {
  return AddKey(handle(key, isolate_), convert);
}

ExceptionStatus KeyAccumulator::AddKey(Handle<Object> key,
                                       AddKeyConversion convert) {
  if (filter_ == PRIVATE_NAMES_ONLY) {
    if (!IsSymbol(*key)) return ExceptionStatus::kSuccess;
    if (!Cast<Symbol>(*key)->is_private_name())
      return ExceptionStatus::kSuccess;
  } else if (IsSymbol(*key)) {
    if (filter_ & SKIP_SYMBOLS) return ExceptionStatus::kSuccess;
    if (Cast<Symbol>(*key)->is_private()) return ExceptionStatus::kSuccess;
  } else if (filter_ & SKIP_STRINGS) {
    return ExceptionStatus::kSuccess;
  }

  if (IsShadowed(key)) return ExceptionStatus::kSuccess;
  if (keys_.is_null()) {
    keys_ = OrderedHashSet::Allocate(isolate_, 16).ToHandleChecked();
  }
  uint32_t index;
  if (convert == CONVERT_TO_ARRAY_INDEX && IsString(*key) &&
      Cast<String>(key)->AsArrayIndex(&index)) {
    key = isolate_->factory()->NewNumberFromUint(index);
  }
  MaybeHandle<OrderedHashSet> new_set_candidate =
      OrderedHashSet::Add(isolate(), keys(), key);
  Handle<OrderedHashSet> new_set;
  if (!new_set_candidate.ToHandle(&new_set)) {
    CHECK(isolate_->has_exception());
    return ExceptionStatus::kException;
  }
  if (*new_set != *keys_) {
    // The keys_ Set is converted directly to a FixedArray in GetKeys which can
    // be left-trimmer. Hence the previous Set should not keep a pointer to the
    // new one.
    keys_->set(OrderedHashSet::NextTableIndex(), Smi::zero());
    keys_ = new_set;
  }
  return ExceptionStatus::kSuccess;
}

ExceptionStatus KeyAccumulator::AddKeys(DirectHandle<FixedArray> array,
                                        AddKeyConversion convert) {
  int add_length = array->length();
  for (int i = 0; i < add_length; i++) {
    Handle<Object> current(array->get(i), isolate_);
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(AddKey(current, convert));
  }
  return ExceptionStatus::kSuccess;
}

ExceptionStatus KeyAccumulator::AddKeys(Handle<JSObject> array_like,
                                        AddKeyConversion convert) {
  DCHECK(IsJSArray(*array_like) || array_like->HasSloppyArgumentsElements());
  ElementsAccessor* accessor = array_like->GetElementsAccessor();
  return accessor->AddElementsToKeyAccumulator(array_like, this, convert);
}

MaybeHandle<FixedArray> FilterProxyKeys(KeyAccumulator* accumulator,
                                        DirectHandle<JSProxy> owner,
                                        Handle<FixedArray> keys,
                                        PropertyFilter filter,
                                        bool skip_indices) {
  if (filter == ALL_PROPERTIES) {
    // Nothing to do.
    return keys;
  }
  Isolate* isolate = accumulator->isolate();
  int store_position = 0;
  for (int i = 0; i < keys->length(); ++i) {
    Handle<Name> key(Cast<Name>(keys->get(i)), isolate);
    if (Object::FilterKey(*key, filter)) continue;  // Skip this key.
    if (skip_indices) {
      uint32_t index;
      if (key->AsArrayIndex(&index)) continue;  // Skip this key.
    }
    if (filter & ONLY_ENUMERABLE) {
      PropertyDescriptor desc;
      Maybe<bool> found =
          JSProxy::GetOwnPropertyDescriptor(isolate, owner, key, &desc);
      MAYBE_RETURN(found, MaybeHandle<FixedArray>());
      if (!found.FromJust()) continue;
      if (!desc.enumerable()) {
        accumulator->AddShadowingKey(key);
        continue;
      }
    }
    // Keep this key.
    if (store_position != i) {
      keys->set(store_position, *key);
    }
    store_position++;
  }
  return FixedArray::RightTrimOrEmpty(isolate, keys, store_position);
}

// Returns "nothing" in case of exception, "true" on success.
Maybe<bool> KeyAccumulator::AddKeysFromJSProxy(DirectHandle<JSProxy> proxy,
                                               Handle<FixedArray> keys) {
  // Postpone the enumerable check for for-in to the ForInFilter step.
  if (!is_for_in_) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, keys,
        FilterProxyKeys(this, proxy, keys, filter_, skip_indices_),
        Nothing<bool>());
  }
  // https://tc39.es/ecma262/#sec-proxy-object-internal-methods-and-internal-slots-ownpropertykeys
  // As of 10.5.11.9 says, the keys collected from Proxy should not contain
  // any duplicates. And the order of the keys is preserved by the
  // OrderedHashTable.
  RETURN_NOTHING_IF_NOT_SUCCESSFUL(AddKeys(keys, CONVERT_TO_ARRAY_INDEX));
  return Just(true);
}

Maybe<bool> KeyAccumulator::CollectKeys(DirectHandle<JSReceiver> receiver,
                                        Handle<JSReceiver> object) {
  // Proxies have no hidden prototype and we should not trigger the
  // [[GetPrototypeOf]] trap on the last iteration when using
  // AdvanceFollowingProxies.
  if (mode_ == KeyCollectionMode::kOwnOnly && IsJSProxy(*object)) {
    MAYBE_RETURN(CollectOwnJSProxyKeys(receiver, Cast<JSProxy>(object)),
                 Nothing<bool>());
    return Just(true);
  }

  PrototypeIterator::WhereToEnd end = mode_ == KeyCollectionMode::kOwnOnly
                                          ? PrototypeIterator::END_AT_NON_HIDDEN
                                          : PrototypeIterator::END_AT_NULL;
  for (PrototypeIterator iter(isolate_, object, kStartAtReceiver, end);
       !iter.IsAtEnd();) {
    // Start the shadow checks only after the first prototype has added
    // shadowing keys.
    if (HasShadowingKeys()) skip_shadow_check_ = false;
    Handle<JSReceiver> current =
        PrototypeIterator::GetCurrent<JSReceiver>(iter);
    Maybe<bool> result = Just(false);  // Dummy initialization.
    if (IsJSProxy(*current)) {
      result = CollectOwnJSProxyKeys(receiver, Cast<JSProxy>(current));
    } else if (IsWasmObject(*current)) {
      if (mode_ == KeyCollectionMode::kIncludePrototypes) {
        RETURN_FAILURE(isolate_, kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
      } else {
        DCHECK_EQ(KeyCollectionMode::kOwnOnly, mode_);
        DCHECK_EQ(result, Just(false));  // Stop iterating.
      }
    } else {
      DCHECK(IsJSObject(*current));
      result = CollectOwnKeys(receiver, Cast<JSObject>(current));
    }
    MAYBE_RETURN(result, Nothing<bool>());
    if (!result.FromJust()) break;  // |false| means "stop iterating".
    // Iterate through proxies but ignore access checks case on API objects for
    // OWN_ONLY keys handled in CollectOwnKeys.
    if (!iter.AdvanceFollowingProxiesIgnoringAccessChecks()) {
      return Nothing<bool>();
    }
    if (!last_non_empty_prototype_.is_null() &&
        *last_non_empty_prototype_ == *current) {
      break;
    }
  }
  return Just(true);
}

bool KeyAccumulator::HasShadowingKeys() { return !shadowing_keys_.is_null(); }

bool KeyAccumulator::IsShadowed(Handle<Object> key) {
  if (!HasShadowingKeys() || skip_shadow_check_) return false;
  return shadowing_keys_->Has(isolate_, key);
}

void KeyAccumulator::AddShadowingKey(Tagged<Object> key,
                                     AllowGarbageCollection* allow_gc) {
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  AddShadowingKey(handle(key, isolate_));
}
void KeyAccumulator::AddShadowingKey(Handle<Object> key) {
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  if (shadowing_keys_.is_null()) {
    shadowing_keys_ = ObjectHashSet::New(isolate_, 16);
  }
  shadowing_keys_ = ObjectHashSet::Add(isolate(), shadowing_keys_, key);
}

namespace {

void TrySettingEmptyEnumCache(Tagged<JSReceiver> object) {
  Tagged<Map> map = object->map();
  DCHECK_EQ(kInvalidEnumCacheSentinel, map->EnumLength());
  if (!map->OnlyHasSimpleProperties()) return;
  DCHECK(IsJSObjectMap(map));  // Implied by {OnlyHasSimpleProperties}.
  if (map->NumberOfEnumerableProperties() > 0) return;
  map->SetEnumLength(0);
}

bool CheckAndInitializeEmptyEnumCache(Tagged<JSReceiver> object) {
  if (object->map()->EnumLength() == kInvalidEnumCacheSentinel) {
    TrySettingEmptyEnumCache(object);
  }
  if (object->map()->EnumLength() != 0) return false;
  DCHECK(IsJSObject(object));
  return !Cast<JSObject>(object)->HasEnumerableElements();
}
}  // namespace

void FastKeyAccumulator::Prepare() {
  DisallowGarbageCollection no_gc;
  // Directly go for the fast path for OWN_ONLY keys.
  if (mode_ == KeyCollectionMode::kOwnOnly) return;
  // Fully walk the prototype chain and find the last prototype with keys.
  is_receiver_simple_enum_ = false;
  has_empty_prototype_ = true;
  only_own_has_simple_elements_ =
      !IsCustomElementsReceiverMap(receiver_->map());
  Tagged<JSReceiver> last_prototype;
  may_have_elements_ = MayHaveElements(*receiver_);
  for (PrototypeIterator iter(isolate_, *receiver_); !iter.IsAtEnd();
       iter.Advance()) {
    Tagged<JSReceiver> current = iter.GetCurrent<JSReceiver>();
    if (!may_have_elements_ || only_own_has_simple_elements_) {
      if (MayHaveElements(current)) {
        may_have_elements_ = true;
        only_own_has_simple_elements_ = false;
      }
    }
    bool has_no_properties = CheckAndInitializeEmptyEnumCache(current);
    if (has_no_properties) continue;
    last_prototype = current;
    has_empty_prototype_ = false;
  }
  // Check if we should try to create/use prototype info cache.
  try_prototype_info_cache_ = TryPrototypeInfoCache(receiver_);
  if (has_prototype_info_cache_) return;
  if (has_empty_prototype_) {
    is_receiver_simple_enum_ =
        receiver_->map()->EnumLength() != kInvalidEnumCacheSentinel &&
        !Cast<JSObject>(*receiver_)->HasEnumerableElements();
  } else if (!last_prototype.is_null()) {
    last_non_empty_prototype_ = handle(last_prototype, isolate_);
  }
}

namespace {

Handle<FixedArray> ReduceFixedArrayTo(Isolate* isolate,
                                      Handle<FixedArray> array, int length) {
  DCHECK_LE(length, array->length());
  if (array->length() == length) return array;
  return isolate->factory()->CopyFixedArrayUpTo(array, length);
}

// Initializes and directly returns the enum cache. Users of this function
// have to make sure to never directly leak the enum cache.
Handle<FixedArray> GetFastEnumPropertyKeys(Isolate* isolate,
                                           DirectHandle<JSObject> object) {
  DirectHandle<Map> map(object->map(), isolate);
  Handle<FixedArray> keys(
      map->instance_descriptors(isolate)->enum_cache()->keys(), isolate);

  // Check if the {map} has a valid enum length, which implies that it
  // must have a valid enum cache as well.
  int enum_length = map->EnumLength();
  if (enum_length != kInvalidEnumCacheSentinel) {
    DCHECK(map->OnlyHasSimpleProperties());
    DCHECK_LE(enum_length, keys->length());
    DCHECK_EQ(enum_length, map->NumberOfEnumerableProperties());
    isolate->counters()->enum_cache_hits()->Increment();
    return ReduceFixedArrayTo(isolate, keys, enum_length);
  }

  // Determine the actual number of enumerable properties of the {map}.
  enum_length = map->NumberOfEnumerableProperties();

  // Check if there's already a shared enum cache on the {map}s
  // DescriptorArray with sufficient number of entries.
  if (enum_length <= keys->length()) {
    if (map->OnlyHasSimpleProperties()) map->SetEnumLength(enum_length);
    isolate->counters()->enum_cache_hits()->Increment();
    return ReduceFixedArrayTo(isolate, keys, enum_length);
  }

  return FastKeyAccumulator::InitializeFastPropertyEnumCache(isolate, map,
                                                             enum_length);
}

template <bool fast_properties>
MaybeHandle<FixedArray> GetOwnKeysWithElements(Isolate* isolate,
                                               Handle<JSObject> object,
                                               GetKeysConversion convert,
                                               bool skip_indices) {
  Handle<FixedArray> keys;
  if (fast_properties) {
    keys = GetFastEnumPropertyKeys(isolate, object);
  } else {
    // TODO(cbruni): preallocate big enough array to also hold elements.
    keys = KeyAccumulator::GetOwnEnumPropertyKeys(isolate, object);
  }

  MaybeHandle<FixedArray> result;
  if (skip_indices) {
    result = keys;
  } else {
    ElementsAccessor* accessor = object->GetElementsAccessor(isolate);
    result = accessor->PrependElementIndices(isolate, object, keys, convert,
                                             ONLY_ENUMERABLE);
  }

  if (v8_flags.trace_for_in_enumerate) {
    PrintF("| strings=%d symbols=0 elements=%u || prototypes>=1 ||\n",
           keys->length(), result.ToHandleChecked()->length() - keys->length());
  }
  return result;
}

}  // namespace

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeys(
    GetKeysConversion keys_conversion) {
  // TODO(v8:9401): We should extend the fast path of KeyAccumulator::GetKeys to
  // also use fast path even when filter = SKIP_SYMBOLS. We used to pass wrong
  // filter to use fast path in cases where we tried to verify all properties
  // are enumerable. However these checks weren't correct and passing the wrong
  // filter led to wrong behaviour.
  if (filter_ == ENUMERABLE_STRINGS) {
    Handle<FixedArray> keys;
    if (GetKeysFast(keys_conversion).ToHandle(&keys)) {
      return keys;
    }
    if (isolate_->has_exception()) return MaybeHandle<FixedArray>();
  }

  if (try_prototype_info_cache_) {
    return GetKeysWithPrototypeInfoCache(keys_conversion);
  }
  return GetKeysSlow(keys_conversion);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysFast(
    GetKeysConversion keys_conversion) {
  bool own_only = has_empty_prototype_ || mode_ == KeyCollectionMode::kOwnOnly;
  Tagged<Map> map = receiver_->map();
  if (!own_only || IsCustomElementsReceiverMap(map)) {
    return MaybeHandle<FixedArray>();
  }

  // From this point on we are certain to only collect own keys.
  DCHECK(IsJSObject(*receiver_));
  Handle<JSObject> object = Cast<JSObject>(receiver_);

  // Do not try to use the enum-cache for dict-mode objects.
  if (map->is_dictionary_map()) {
    return GetOwnKeysWithElements<false>(isolate_, object, keys_conversion,
                                         skip_indices_);
  }
  int enum_length = receiver_->map()->EnumLength();
  if (enum_length == kInvalidEnumCacheSentinel) {
    Handle<FixedArray> keys;
    // Try initializing the enum cache and return own properties.
    if (GetOwnKeysWithUninitializedEnumLength().ToHandle(&keys)) {
      if (v8_flags.trace_for_in_enumerate) {
        PrintF("| strings=%d symbols=0 elements=0 || prototypes>=1 ||\n",
               keys->length());
      }
      is_receiver_simple_enum_ =
          object->map()->EnumLength() != kInvalidEnumCacheSentinel;
      return keys;
    }
  }
  // The properties-only case failed because there were probably elements on the
  // receiver.
  return GetOwnKeysWithElements<true>(isolate_, object, keys_conversion,
                                      skip_indices_);
}

// static
Handle<FixedArray> FastKeyAccumulator::InitializeFastPropertyEnumCache(
    Isolate* isolate, DirectHandle<Map> map, int enum_length,
    AllocationType allocation) {
  DCHECK_EQ(kInvalidEnumCacheSentinel, map->EnumLength());
  DCHECK_GT(enum_length, 0);
  DCHECK_EQ(enum_length, map->NumberOfEnumerableProperties());
  DCHECK(!map->is_dictionary_map());

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);

  // The enum cache should have been a hit if the number of enumerable
  // properties is fewer than what's already in the cache.
  DCHECK_LT(descriptors->enum_cache()->keys()->length(), enum_length);
  isolate->counters()->enum_cache_misses()->Increment();

  // Create the keys array.
  int index = 0;
  bool fields_only = true;
  Handle<FixedArray> keys =
      isolate->factory()->NewFixedArray(enum_length, allocation);
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    DisallowGarbageCollection no_gc;
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.IsDontEnum()) continue;
    Tagged<Object> key = descriptors->GetKey(i);
    if (IsSymbol(key)) continue;
    keys->set(index, key);
    if (details.location() != PropertyLocation::kField) fields_only = false;
    index++;
  }
  DCHECK_EQ(index, keys->length());

  // Optionally also create the indices array.
  DirectHandle<FixedArray> indices = isolate->factory()->empty_fixed_array();
  if (fields_only) {
    indices = isolate->factory()->NewFixedArray(enum_length, allocation);
    index = 0;
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    Tagged<FixedArray> raw_indices = *indices;
    Tagged<DescriptorArray> raw_descriptors = *descriptors;
    for (InternalIndex i : raw_map->IterateOwnDescriptors()) {
      PropertyDetails details = raw_descriptors->GetDetails(i);
      if (details.IsDontEnum()) continue;
      Tagged<Object> key = raw_descriptors->GetKey(i);
      if (IsSymbol(key)) continue;
      DCHECK_EQ(PropertyKind::kData, details.kind());
      DCHECK_EQ(PropertyLocation::kField, details.location());
      FieldIndex field_index = FieldIndex::ForDetails(raw_map, details);
      raw_indices->set(index, Smi::FromInt(field_index.GetLoadByFieldIndex()));
      index++;
    }
    DCHECK_EQ(index, indices->length());
  }

  DescriptorArray::InitializeOrChangeEnumCache(descriptors, isolate, keys,
                                               indices, allocation);
  if (map->OnlyHasSimpleProperties()) map->SetEnumLength(enum_length);
  return keys;
}

MaybeHandle<FixedArray>
FastKeyAccumulator::GetOwnKeysWithUninitializedEnumLength() {
  auto object = Cast<JSObject>(receiver_);
  // Uninitialized enum length
  Tagged<Map> map = object->map();
  if (object->elements() != ReadOnlyRoots(isolate_).empty_fixed_array() &&
      object->elements() !=
          ReadOnlyRoots(isolate_).empty_slow_element_dictionary()) {
    // Assume that there are elements.
    return MaybeHandle<FixedArray>();
  }
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors == 0) {
    map->SetEnumLength(0);
    return isolate_->factory()->empty_fixed_array();
  }
  // We have no elements but possibly enumerable property keys, hence we can
  // directly initialize the enum cache.
  Handle<FixedArray> keys = GetFastEnumPropertyKeys(isolate_, object);
  if (is_for_in_) return keys;
  // Do not leak the enum cache as it might end up as an elements backing store.
  return isolate_->factory()->CopyFixedArray(keys);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysSlow(
    GetKeysConversion keys_conversion) {
  KeyAccumulator accumulator(isolate_, mode_, filter_);
  accumulator.set_is_for_in(is_for_in_);
  accumulator.set_skip_indices(skip_indices_);
  accumulator.set_last_non_empty_prototype(last_non_empty_prototype_);
  accumulator.set_may_have_elements(may_have_elements_);
  accumulator.set_first_prototype_map(first_prototype_map_);
  accumulator.set_try_prototype_info_cache(try_prototype_info_cache_);

  MAYBE_RETURN(accumulator.CollectKeys(receiver_, receiver_),
               MaybeHandle<FixedArray>());
  return accumulator.GetKeys(keys_conversion);
}

MaybeHandle<FixedArray> FastKeyAccumulator::GetKeysWithPrototypeInfoCache(
    GetKeysConversion keys_conversion) {
  Handle<FixedArray> own_keys;
  if (may_have_elements_) {
    MaybeHandle<FixedArray> maybe_own_keys;
    if (receiver_->map()->is_dictionary_map()) {
      maybe_own_keys = GetOwnKeysWithElements<false>(
          isolate_, Cast<JSObject>(receiver_), keys_conversion, skip_indices_);
    } else {
      maybe_own_keys = GetOwnKeysWithElements<true>(
          isolate_, Cast<JSObject>(receiver_), keys_conversion, skip_indices_);
    }
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, own_keys, maybe_own_keys);
  } else {
    own_keys = KeyAccumulator::GetOwnEnumPropertyKeys(
        isolate_, Cast<JSObject>(receiver_));
  }
  Handle<FixedArray> prototype_chain_keys;
  if (has_prototype_info_cache_) {
    prototype_chain_keys =
        handle(Cast<FixedArray>(
                   Cast<PrototypeInfo>(first_prototype_map_->prototype_info())
                       ->prototype_chain_enum_cache()),
               isolate_);
  } else {
    KeyAccumulator accumulator(isolate_, mode_, filter_);
    accumulator.set_is_for_in(is_for_in_);
    accumulator.set_skip_indices(skip_indices_);
    accumulator.set_last_non_empty_prototype(last_non_empty_prototype_);
    accumulator.set_may_have_elements(may_have_elements_);
    accumulator.set_receiver(receiver_);
    accumulator.set_first_prototype_map(first_prototype_map_);
    accumulator.set_try_prototype_info_cache(try_prototype_info_cache_);
    MAYBE_RETURN(accumulator.CollectKeys(first_prototype_, first_prototype_),
                 MaybeHandle<FixedArray>());
    prototype_chain_keys = accumulator.GetKeys(keys_conversion);
  }
  Handle<FixedArray> result = CombineKeys(
      isolate_, own_keys, prototype_chain_keys, receiver_, may_have_elements_);
  if (is_for_in_ && own_keys.is_identical_to(result)) {
    // Don't leak the enumeration cache without the receiver since it might get
    // trimmed otherwise.
    return isolate_->factory()->CopyFixedArrayUpTo(result, result->length());
  }
  return result;
}

bool FastKeyAccumulator::MayHaveElements(Tagged<JSReceiver> receiver) {
  if (!IsJSObject(receiver)) return true;
  Tagged<JSObject> object = Cast<JSObject>(receiver);
  if (object->HasEnumerableElements()) return true;
  if (object->HasIndexedInterceptor()) return true;
  return false;
}

bool FastKeyAccumulator::TryPrototypeInfoCache(Handle<JSReceiver> receiver) {
  if (may_have_elements_ && !only_own_has_simple_elements_) return false;
  Handle<JSObject> object = Cast<JSObject>(receiver);
  if (!object->HasFastProperties()) return false;
  if (object->HasNamedInterceptor()) return false;
  if (IsAccessCheckNeeded(*object) &&
      !isolate_->MayAccess(isolate_->native_context(), object)) {
    return false;
  }
  DisallowGarbageCollection no_gc;
  Tagged<HeapObject> prototype = receiver->map(isolate_)->prototype();
  if (prototype.is_null()) return false;
  Tagged<Map> maybe_proto_map = prototype->map(isolate_);
  if (!maybe_proto_map->is_prototype_map()) return false;
  Tagged<PrototypeInfo> prototype_info;
  if (!maybe_proto_map->TryGetPrototypeInfo(&prototype_info)) return false;

  first_prototype_ = handle(Cast<JSReceiver>(prototype), isolate_);
  first_prototype_map_ = handle(maybe_proto_map, isolate_);
  has_prototype_info_cache_ =
      maybe_proto_map->IsPrototypeValidityCellValid() &&
      IsFixedArray(prototype_info->prototype_chain_enum_cache());
  return true;
}

V8_WARN_UNUSED_RESULT ExceptionStatus
KeyAccumulator::FilterForEnumerableProperties(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object,
    Handle<InterceptorInfo> interceptor, Handle<JSObject> result,
    IndexedOrNamed type) {
  DCHECK(IsJSArray(*result) || result->HasSloppyArgumentsElements());
  ElementsAccessor* accessor = result->GetElementsAccessor();

  size_t length = accessor->GetCapacity(*result, result->elements());
  for (InternalIndex entry : InternalIndex::Range(length)) {
    if (!accessor->HasEntry(*result, entry)) continue;

    // args are invalid after args.Call(), create a new one in every iteration.
    // Query callbacks are not expected to have side effects.
    PropertyCallbackArguments args(isolate_, interceptor->data(), *receiver,
                                   *object, Just(kDontThrow));
    Handle<Object> element = accessor->Get(isolate_, result, entry);
    Handle<Object> attributes;
    if (type == kIndexed) {
      uint32_t number;
      CHECK(Object::ToUint32(*element, &number));
      attributes = args.CallIndexedQuery(interceptor, number);
    } else {
      CHECK(IsName(*element));
      attributes = args.CallNamedQuery(interceptor, Cast<Name>(element));
    }
    // An exception was thrown in the interceptor. Propagate.
    RETURN_VALUE_IF_EXCEPTION(isolate_, ExceptionStatus::kException);

    if (!attributes.is_null()) {
      int32_t value;
      CHECK(Object::ToInt32(*attributes, &value));
      if ((value & DONT_ENUM) == 0) {
        RETURN_FAILURE_IF_NOT_SUCCESSFUL(AddKey(element, DO_NOT_CONVERT));
      }
    }
  }
  return ExceptionStatus::kSuccess;
}

// Returns |true| on success, |nothing| on exception.
Maybe<bool> KeyAccumulator::CollectInterceptorKeysInternal(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object,
    Handle<InterceptorInfo> interceptor, IndexedOrNamed type) {
  PropertyCallbackArguments enum_args(isolate_, interceptor->data(), *receiver,
                                      *object, Just(kDontThrow));

  if (IsUndefined(interceptor->enumerator(), isolate_)) {
    return Just(true);
  }
  Handle<JSObjectOrUndefined> maybe_result;
  if (type == kIndexed) {
    maybe_result = enum_args.CallIndexedEnumerator(interceptor);
  } else {
    DCHECK_EQ(type, kNamed);
    maybe_result = enum_args.CallNamedEnumerator(interceptor);
  }
  // An exception was thrown in the interceptor. Propagate.
  RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate_, enum_args, Nothing<bool>());
  if (IsUndefined(*maybe_result)) return Just(true);
  DCHECK(IsJSObject(*maybe_result));
  Handle<JSObject> result = Cast<JSObject>(maybe_result);

  // Request was successfully intercepted, so accept potential side effects
  // happened up to this point.
  enum_args.AcceptSideEffects();

  if ((filter_ & ONLY_ENUMERABLE) &&
      !IsUndefined(interceptor->query(), isolate_)) {
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(FilterForEnumerableProperties(
        receiver, object, interceptor, result, type));
  } else {
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(AddKeys(
        result, type == kIndexed ? CONVERT_TO_ARRAY_INDEX : DO_NOT_CONVERT));
  }
  return Just(true);
}

Maybe<bool> KeyAccumulator::CollectInterceptorKeys(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object,
    IndexedOrNamed type) {
  if (type == kIndexed) {
    if (!object->HasIndexedInterceptor()) return Just(true);
  } else {
    if (!object->HasNamedInterceptor()) return Just(true);
  }
  Handle<InterceptorInfo> interceptor(type == kIndexed
                                          ? object->GetIndexedInterceptor()
                                          : object->GetNamedInterceptor(),
                                      isolate_);
  return CollectInterceptorKeysInternal(receiver, object, interceptor, type);
}

Maybe<bool> KeyAccumulator::CollectOwnElementIndices(
    DirectHandle<JSReceiver> receiver, Handle<JSObject> object) {
  if (filter_ & SKIP_STRINGS || skip_indices_) return Just(true);

  ElementsAccessor* accessor = object->GetElementsAccessor();
  RETURN_NOTHING_IF_NOT_SUCCESSFUL(
      accessor->CollectElementIndices(object, this));
  return CollectInterceptorKeys(receiver, object, kIndexed);
}

namespace {

template <bool skip_symbols>
std::optional<int> CollectOwnPropertyNamesInternal(
    DirectHandle<JSObject> object, KeyAccumulator* keys,
    DirectHandle<DescriptorArray> descs, int start_index, int limit) {
  AllowGarbageCollection allow_gc;
  int first_skipped = -1;
  PropertyFilter filter = keys->filter();
  KeyCollectionMode mode = keys->mode();
  for (InternalIndex i : InternalIndex::Range(start_index, limit)) {
    bool is_shadowing_key = false;
    PropertyDetails details = descs->GetDetails(i);

    if ((int{details.attributes()} & filter) != 0) {
      if (mode == KeyCollectionMode::kIncludePrototypes) {
        is_shadowing_key = true;
      } else {
        continue;
      }
    }

    Tagged<Name> key = descs->GetKey(i);
    if (skip_symbols == IsSymbol(key)) {
      if (first_skipped == -1) first_skipped = i.as_int();
      continue;
    }
    if (Object::FilterKey(key, keys->filter())) continue;

    if (is_shadowing_key) {
      // This might allocate, but {key} is not used afterwards.
      keys->AddShadowingKey(key, &allow_gc);
     
"""


```