Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The core request is to understand the purpose of the `keys.cc` file in V8 and its connection to JavaScript. This means we need to figure out what functionality it implements and how that functionality manifests in JavaScript.

2. **Initial Code Scan - Identifying Key Data Structures and Functions:**  The first step is to quickly scan the code, looking for keywords and patterns that suggest the file's purpose.

    * **Namespace `v8::internal`:**  This tells us the code is internal to the V8 engine, not part of the public API.
    * **Includes:** The included header files (`objects/keys.h`, `api/api.h`, `objects/objects-inl.h`, etc.) strongly suggest the file deals with object properties and keys within V8's internal object representation. Specific includes like `objects/hash-table-inl.h`, `objects/ordered-hash-table-inl.h`, and `objects/property-descriptor.h` are particularly relevant.
    * **Class `KeyAccumulator` and `FastKeyAccumulator`:** These are the central classes. Their names directly suggest they are responsible for collecting and managing keys.
    * **Functions like `GetKeys`, `AddKey`, `CollectKeys`, `CombineKeys`, `FilterProxyKeys`:** These names provide direct clues about the operations performed.
    * **Macros like `RETURN_NOTHING_IF_NOT_SUCCESSFUL` and `RETURN_FAILURE_IF_NOT_SUCCESSFUL`:** These indicate the code deals with potential failure scenarios and error handling.
    * **Enums like `KeyCollectionMode`, `PropertyFilter`, `GetKeysConversion`, `AddKeyConversion`:** These suggest different ways keys can be collected and filtered.

3. **Focus on Key Concepts and Algorithms:**  After the initial scan, focus on understanding the core logic:

    * **Key Accumulation:** How are keys collected?  The `KeyAccumulator` class is clearly the central component. It uses an `OrderedHashSet` to store keys, ensuring uniqueness and maintaining insertion order.
    * **Fast Path vs. Slow Path:** The presence of `FastKeyAccumulator` suggests performance optimization. The code tries to take a faster path for common cases, especially when dealing with simple objects.
    * **Prototype Chain Traversal:** The code iterates through the prototype chain using `PrototypeIterator`. This is fundamental to JavaScript's inheritance model.
    * **Property Filtering:** The `PropertyFilter` enum and related logic indicate that the code can filter keys based on enumerability, symbol status, etc. This directly relates to JavaScript concepts like `for...in` loops and `Object.keys()`.
    * **Proxy Handling:** The code explicitly handles `JSProxy` objects and their specific behavior related to key retrieval. This is an important aspect of JavaScript's meta-programming capabilities.
    * **Enum Cache:** The code talks about an "enum cache," which is a V8 optimization to speed up property enumeration for objects with simple property structures.
    * **Dictionary vs. Fast Properties:** The code distinguishes between objects with "fast properties" (stored inline in the object) and "dictionary properties" (stored in a separate hash table).

4. **Relating C++ to JavaScript:**  This is the crucial step. Think about how the C++ concepts and functions map to JavaScript behavior:

    * **`Object.keys()`:** This is the most direct JavaScript equivalent to the core functionality of `keys.cc`. It retrieves the enumerable string keys of an object.
    * **`Object.getOwnPropertyNames()`:**  This JavaScript function gets *all* own property names (enumerable and non-enumerable), including strings and symbols.
    * **`Object.getOwnPropertySymbols()`:**  This specifically retrieves symbol properties.
    * **`for...in` loop:** This loop iterates over the enumerable properties of an object and its prototype chain. The `is_for_in` flag and the handling of prototype chains in the C++ code are directly related to this.
    * **Proxies:** The proxy-related code in C++ directly supports the behavior of JavaScript proxies when accessing their keys. The checks for revoked proxies and the interaction with the `ownKeys` trap are crucial.

5. **Crafting the JavaScript Examples:** Once the connection between C++ and JavaScript is clear, create concrete examples to illustrate the relationship:

    * **Basic `Object.keys()` example:** Show how the C++ code's logic results in the output of `Object.keys()`.
    * **`for...in` loop example:** Demonstrate how the prototype chain traversal and enumerability filtering in the C++ code match the behavior of `for...in`.
    * **Proxy example:** Illustrate how the proxy-specific logic in C++ impacts the result of `Object.keys()` on a proxy, including the `ownKeys` trap.

6. **Structuring the Explanation:** Organize the information logically:

    * **Summary of Functionality:** Start with a concise overview of what the file does.
    * **Key Components:** Explain the main classes and their roles.
    * **Relationship to JavaScript:** Clearly link the C++ functionality to corresponding JavaScript features.
    * **JavaScript Examples:** Provide concrete code examples.

7. **Refinement and Review:**  Read through the explanation and examples. Ensure clarity, accuracy, and completeness. Are there any edge cases or nuances that should be mentioned? (For instance, the different filters and collection modes).

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:** "This file just implements `Object.keys()`."
* **Realization:** "Wait, the code also handles `for...in`, `Object.getOwnPropertyNames()`, and proxies. The `KeyCollectionMode` and `PropertyFilter` enums suggest more than just `Object.keys()`."
* **Correction:**  Broaden the scope of the explanation to include these related JavaScript features.

By following this systematic approach, we can effectively analyze the C++ code and connect it to the user-facing behavior of JavaScript. The key is to move from the low-level C++ implementation to the high-level JavaScript concepts it enables.
这个C++源代码文件 `keys.cc`，位于 V8 引擎的 `v8/src/objects` 目录下，其主要功能是**实现 JavaScript 中获取对象属性键（keys）的相关操作**。它负责收集、过滤和处理各种情况下对象的键，并支持不同的键类型和过滤模式。

更具体地说，`keys.cc` 实现了以下核心功能：

1. **键的收集 (Key Collection):**
   - 提供了 `KeyAccumulator` 和 `FastKeyAccumulator` 两个类来负责收集对象的键。
   - `KeyAccumulator` 是一个通用的键收集器，能够处理各种复杂情况，包括原型链的遍历、访问器属性、拦截器等。
   - `FastKeyAccumulator` 则是针对性能优化的键收集器，在满足特定条件（例如，只收集自身属性，且对象结构简单）时，可以采用更快速的路径。
   - 支持不同的 `KeyCollectionMode`，例如：
     - `kOwnOnly`: 只收集对象自身的键。
     - `kIncludePrototypes`: 收集对象自身以及原型链上的可枚举键（用于 `for...in` 循环）。
   - 支持不同的 `PropertyFilter`，用于过滤特定类型的键，例如：
     - `ALL_PROPERTIES`: 所有属性键。
     - `ONLY_ENUMERABLE`: 只收集可枚举的属性键。
     - `SKIP_SYMBOLS`: 排除 Symbol 类型的键。
     - `PRIVATE_NAMES_ONLY`: 只收集私有符号（Private Symbols）。

2. **键的转换 (Key Conversion):**
   - 提供了 `GetKeysConversion` 和 `AddKeyConversion` 来控制键的转换方式。
   - 例如，可以将数字字符串形式的键转换为 Number 类型。

3. **代理对象的键处理 (Proxy Key Handling):**
   - 专门处理 `JSProxy` 对象的键收集，包括调用代理对象的 `ownKeys` 陷阱（trap），并进行相应的验证和处理，以确保符合 ES6 规范。

4. **原型链的处理 (Prototype Chain Handling):**
   - 能够遍历对象的原型链，收集原型链上的键（用于 `for...in` 循环）。
   - 提供了原型链枚举缓存（Prototype Chain Enum Cache）的优化机制，以提高性能。

5. **拦截器 (Interceptor) 的处理:**
   - 能够处理对象上的命名和索引拦截器，调用拦截器的枚举器（enumerator）来获取动态生成的键。

6. **与哈希表和描述符数组的交互:**
   - 与 V8 内部的对象属性存储结构（例如 `DescriptorArray` 和各种哈希表）交互，以高效地获取对象的键。

**与 JavaScript 的功能关系以及示例：**

`keys.cc` 中的功能直接对应了 JavaScript 中获取对象键的几种主要方式：

**1. `Object.keys(obj)`:**

   - JavaScript 的 `Object.keys()` 方法返回一个由给定对象自身的可枚举**字符串**属性名组成的数组。
   - 在 V8 内部，当调用 `Object.keys()` 时，会使用 `KeyAccumulator` 或 `FastKeyAccumulator`，并设置 `KeyCollectionMode::kOwnOnly` 和 `PropertyFilter::ENUMERABLE_STRINGS` (或者类似的功能)，最终返回收集到的字符串键。

   ```javascript
   const obj = { a: 1, b: 2, [Symbol('c')]: 3 };
   Object.defineProperty(obj, 'd', { value: 4, enumerable: false });

   const keys = Object.keys(obj);
   console.log(keys); // 输出: ["a", "b"]
   ```

**2. `Object.getOwnPropertyNames(obj)`:**

   - JavaScript 的 `Object.getOwnPropertyNames()` 方法返回一个由给定对象自身的所有**字符串**属性名组成的数组，包括不可枚举的属性。
   - 在 V8 内部，会使用 `KeyAccumulator` 或 `FastKeyAccumulator`，并设置 `KeyCollectionMode::kOwnOnly` 和 `PropertyFilter::SKIP_SYMBOLS` 来收集所有字符串键。

   ```javascript
   const obj = { a: 1, b: 2, [Symbol('c')]: 3 };
   Object.defineProperty(obj, 'd', { value: 4, enumerable: false });

   const ownPropertyNames = Object.getOwnPropertyNames(obj);
   console.log(ownPropertyNames); // 输出: ["a", "b", "d"]
   ```

**3. `Object.getOwnPropertySymbols(obj)`:**

   - JavaScript 的 `Object.getOwnPropertySymbols()` 方法返回一个由给定对象自身的所有 **Symbol** 属性名组成的数组。
   - 在 V8 内部，会使用 `KeyAccumulator` 或 `FastKeyAccumulator`，并设置 `KeyCollectionMode::kOwnOnly` 和 `PropertyFilter::PRIVATE_NAMES_ONLY` (或类似机制，可能需要调整 filter 以仅包含 Symbol) 来收集 Symbol 键。

   ```javascript
   const obj = { a: 1, b: 2, [Symbol('c')]: 3 };
   Object.defineProperty(obj, 'd', { value: 4, enumerable: false });

   const ownPropertySymbols = Object.getOwnPropertySymbols(obj);
   console.log(ownPropertySymbols); // 输出: [Symbol(c)]
   ```

**4. `for...in` 循环:**

   - JavaScript 的 `for...in` 循环遍历对象及其原型链上所有可枚举的**字符串**属性名。
   - 在 V8 内部，当执行 `for...in` 循环时，会使用 `KeyAccumulator` 并设置 `KeyCollectionMode::kIncludePrototypes` 和 `PropertyFilter::ENUMERABLE_STRINGS` 来收集键。

   ```javascript
   const proto = { protoProp: 5 };
   const obj = Object.create(proto);
   obj.a = 1;
   Object.defineProperty(obj, 'b', { value: 2, enumerable: false });

   for (let key in obj) {
     console.log(key); // 输出: "a", "protoProp"
   }
   ```

**5. Proxy 对象的 `ownKeys` 陷阱:**

   - 当对一个 Proxy 对象调用 `Object.getOwnPropertyNames()` 或 `Object.getOwnPropertySymbols()` 等获取键的方法时，如果 Proxy 的 handler 定义了 `ownKeys` 陷阱，V8 会调用该陷阱来获取键。
   - `keys.cc` 中专门处理 `JSProxy` 的逻辑就负责处理这种情况，包括调用 `ownKeys` 陷阱，并验证其返回结果是否符合规范。

   ```javascript
   const target = { a: 1, b: 2 };
   const handler = {
     ownKeys() {
       console.log('ownKeys trap called');
       return ['a', Symbol('c')];
     }
   };
   const proxy = new Proxy(target, handler);

   const proxyKeys = Reflect.ownKeys(proxy); // 或者 Object.getOwnPropertyNames(proxy) + Object.getOwnPropertySymbols(proxy)
   console.log(proxyKeys); // 输出: "ownKeys trap called", ["a", Symbol(c)]
   ```

总而言之，`v8/src/objects/keys.cc` 文件是 V8 引擎中实现 JavaScript 对象键操作的核心部分，它负责高效、准确地收集和处理各种场景下的对象键，并与 JavaScript 的相关 API 和语言特性紧密关联。理解这个文件的工作原理有助于深入理解 JavaScript 对象的属性访问机制。

Prompt: 
```
这是目录为v8/src/objects/keys.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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
      continue;
    } else {
      if (keys->AddKey(key, DO_NOT_CONVERT) != ExceptionStatus::kSuccess) {
        return std::optional<int>();
      }
    }
  }
  return first_skipped;
}

// Logic shared between different specializations of CopyEnumKeysTo.
template <typename Dictionary>
void CommonCopyEnumKeysTo(Isolate* isolate, Handle<Dictionary> dictionary,
                          DirectHandle<FixedArray> storage,
                          KeyCollectionMode mode, KeyAccumulator* accumulator) {
  DCHECK_IMPLIES(mode != KeyCollectionMode::kOwnOnly, accumulator != nullptr);
  int length = storage->length();
  int properties = 0;
  ReadOnlyRoots roots(isolate);

  AllowGarbageCollection allow_gc;
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> key;
    if (!dictionary->ToKey(roots, i, &key)) continue;
    bool is_shadowing_key = false;
    if (IsSymbol(key)) continue;
    PropertyDetails details = dictionary->DetailsAt(i);
    if (details.IsDontEnum()) {
      if (mode == KeyCollectionMode::kIncludePrototypes) {
        is_shadowing_key = true;
      } else {
        continue;
      }
    }
    if (is_shadowing_key) {
      // This might allocate, but {key} is not used afterwards.
      accumulator->AddShadowingKey(key, &allow_gc);
      continue;
    } else {
      if (Dictionary::kIsOrderedDictionaryType) {
        storage->set(properties, Cast<Name>(key));
      } else {
        // If the dictionary does not store elements in enumeration order,
        // we need to sort it afterwards in CopyEnumKeysTo. To enable this we
        // need to store indices at this point, rather than the values at the
        // given indices.
        storage->set(properties, Smi::FromInt(i.as_int()));
      }
    }
    properties++;
    if (mode == KeyCollectionMode::kOwnOnly && properties == length) break;
  }

  CHECK_EQ(length, properties);
}

// Copies enumerable keys to preallocated fixed array.
// Does not throw for uninitialized exports in module namespace objects, so
// this has to be checked separately.
template <typename Dictionary>
void CopyEnumKeysTo(Isolate* isolate, Handle<Dictionary> dictionary,
                    Handle<FixedArray> storage, KeyCollectionMode mode,
                    KeyAccumulator* accumulator) {
  static_assert(!Dictionary::kIsOrderedDictionaryType);

  CommonCopyEnumKeysTo<Dictionary>(isolate, dictionary, storage, mode,
                                   accumulator);

  int length = storage->length();

  DisallowGarbageCollection no_gc;
  Tagged<Dictionary> raw_dictionary = *dictionary;
  Tagged<FixedArray> raw_storage = *storage;
  EnumIndexComparator<Dictionary> cmp(raw_dictionary);
  // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
  // store operations that are safe for concurrent marking.
  AtomicSlot start(storage->RawFieldOfFirstElement());
  std::sort(start, start + length, cmp);
  for (int i = 0; i < length; i++) {
    InternalIndex index(Smi::ToInt(raw_storage->get(i)));
    raw_storage->set(i, raw_dictionary->NameAt(index));
  }
}

template <>
void CopyEnumKeysTo(Isolate* isolate, Handle<SwissNameDictionary> dictionary,
                    Handle<FixedArray> storage, KeyCollectionMode mode,
                    KeyAccumulator* accumulator) {
  CommonCopyEnumKeysTo<SwissNameDictionary>(isolate, dictionary, storage, mode,
                                            accumulator);

  // No need to sort, as CommonCopyEnumKeysTo on OrderedNameDictionary
  // adds entries to |storage| in the dict's insertion order
  // Further, the template argument true above means that |storage|
  // now contains the actual values from |dictionary|, rather than indices.
}

template <class T>
Handle<FixedArray> GetOwnEnumPropertyDictionaryKeys(
    Isolate* isolate, KeyCollectionMode mode, KeyAccumulator* accumulator,
    DirectHandle<JSObject> object, Tagged<T> raw_dictionary) {
  Handle<T> dictionary(raw_dictionary, isolate);
  if (dictionary->NumberOfElements() == 0) {
    return isolate->factory()->empty_fixed_array();
  }
  int length = dictionary->NumberOfEnumerableProperties();
  Handle<FixedArray> storage = isolate->factory()->NewFixedArray(length);
  CopyEnumKeysTo(isolate, dictionary, storage, mode, accumulator);
  return storage;
}

// Collect the keys from |dictionary| into |keys|, in ascending chronological
// order of property creation.
template <typename Dictionary>
ExceptionStatus CollectKeysFromDictionary(Handle<Dictionary> dictionary,
                                          KeyAccumulator* keys) {
  Isolate* isolate = keys->isolate();
  ReadOnlyRoots roots(isolate);
  // TODO(jkummerow): Consider using a std::unique_ptr<InternalIndex[]> instead.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(dictionary->NumberOfElements());
  int array_size = 0;
  PropertyFilter filter = keys->filter();
  // Handle enumerable strings in CopyEnumKeysTo.
  DCHECK_NE(keys->filter(), ENUMERABLE_STRINGS);
  {
    DisallowGarbageCollection no_gc;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> key;
      Tagged<Dictionary> raw_dictionary = *dictionary;
      if (!raw_dictionary->ToKey(roots, i, &key)) continue;
      if (Object::FilterKey(key, filter)) continue;
      PropertyDetails details = raw_dictionary->DetailsAt(i);
      if ((int{details.attributes()} & filter) != 0) {
        AllowGarbageCollection gc;
        // This might allocate, but {key} is not used afterwards.
        keys->AddShadowingKey(key, &gc);
        continue;
      }
      // TODO(emrich): consider storing keys instead of indices into the array
      // in case of ordered dictionary type.
      array->set(array_size++, Smi::FromInt(i.as_int()));
    }
    if (!Dictionary::kIsOrderedDictionaryType) {
      // Sorting only needed if it's an unordered dictionary,
      // otherwise we traversed elements in insertion order

      EnumIndexComparator<Dictionary> cmp(*dictionary);
      // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
      // store operations that are safe for concurrent marking.
      AtomicSlot start(array->RawFieldOfFirstElement());
      std::sort(start, start + array_size, cmp);
    }
  }

  bool has_seen_symbol = false;
  for (int i = 0; i < array_size; i++) {
    InternalIndex index(Smi::ToInt(array->get(i)));
    Tagged<Object> key = dictionary->NameAt(index);
    if (IsSymbol(key)) {
      has_seen_symbol = true;
      continue;
    }
    ExceptionStatus status = keys->AddKey(key, DO_NOT_CONVERT);
    if (!status) return status;
  }
  if (has_seen_symbol) {
    for (int i = 0; i < array_size; i++) {
      InternalIndex index(Smi::ToInt(array->get(i)));
      Tagged<Object> key = dictionary->NameAt(index);
      if (!IsSymbol(key)) continue;
      ExceptionStatus status = keys->AddKey(key, DO_NOT_CONVERT);
      if (!status) return status;
    }
  }
  return ExceptionStatus::kSuccess;
}

}  // namespace

Maybe<bool> KeyAccumulator::CollectOwnPropertyNames(
    DirectHandle<JSReceiver> receiver, Handle<JSObject> object) {
  if (filter_ == ENUMERABLE_STRINGS) {
    DirectHandle<FixedArray> enum_keys;
    if (object->HasFastProperties()) {
      enum_keys = KeyAccumulator::GetOwnEnumPropertyKeys(isolate_, object);
      // If the number of properties equals the length of enumerable properties
      // we do not have to filter out non-enumerable ones
      Tagged<Map> map = object->map();
      int nof_descriptors = map->NumberOfOwnDescriptors();
      if (enum_keys->length() != nof_descriptors) {
        if (map->prototype(isolate_) != ReadOnlyRoots(isolate_).null_value()) {
          AllowGarbageCollection allow_gc;
          DirectHandle<DescriptorArray> descs(
              map->instance_descriptors(isolate_), isolate_);
          for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
            PropertyDetails details = descs->GetDetails(i);
            if (!details.IsDontEnum()) continue;
            this->AddShadowingKey(descs->GetKey(i), &allow_gc);
          }
        }
      }
    } else if (IsJSGlobalObject(*object)) {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object,
          Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad));
    } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object, object->property_dictionary_swiss());
    } else {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object, object->property_dictionary());
    }
    if (IsJSModuleNamespace(*object)) {
      // Simulate [[GetOwnProperty]] for establishing enumerability, which
      // throws for uninitialized exports.
      for (int i = 0, n = enum_keys->length(); i < n; ++i) {
        Handle<String> key(Cast<String>(enum_keys->get(i)), isolate_);
        if (Cast<JSModuleNamespace>(object)
                ->GetExport(isolate(), key)
                .is_null()) {
          return Nothing<bool>();
        }
      }
    }
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(AddKeys(enum_keys, DO_NOT_CONVERT));
  } else {
    if (object->HasFastProperties()) {
      int limit = object->map()->NumberOfOwnDescriptors();
      DirectHandle<DescriptorArray> descs(
          object->map()->instance_descriptors(isolate_), isolate_);
      // First collect the strings,
      std::optional<int> first_symbol =
          CollectOwnPropertyNamesInternal<true>(object, this, descs, 0, limit);
      // then the symbols.
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(first_symbol);
      if (first_symbol.value() != -1) {
        RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectOwnPropertyNamesInternal<false>(
            object, this, descs, first_symbol.value(), limit));
      }
    } else if (IsJSGlobalObject(*object)) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
                 isolate_),
          this));
    } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(object->property_dictionary_swiss(), isolate_), this));
    } else {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(object->property_dictionary(), isolate_), this));
    }
  }
  // Add the property keys from the interceptor.
  return CollectInterceptorKeys(receiver, object, kNamed);
}

ExceptionStatus KeyAccumulator::CollectPrivateNames(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object) {
  DCHECK_EQ(mode_, KeyCollectionMode::kOwnOnly);
  if (object->HasFastProperties()) {
    int limit = object->map()->NumberOfOwnDescriptors();
    DirectHandle<DescriptorArray> descs(
        object->map()->instance_descriptors(isolate_), isolate_);
    CollectOwnPropertyNamesInternal<false>(object, this, descs, 0, limit);
  } else if (IsJSGlobalObject(*object)) {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
               isolate_),
        this));
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(object->property_dictionary_swiss(), isolate_), this));
  } else {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(object->property_dictionary(), isolate_), this));
  }
  return ExceptionStatus::kSuccess;
}

Maybe<bool> KeyAccumulator::CollectAccessCheckInterceptorKeys(
    DirectHandle<AccessCheckInfo> access_check_info,
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object) {
  if (!skip_indices_) {
    MAYBE_RETURN((CollectInterceptorKeysInternal(
                     receiver, object,
                     handle(Cast<InterceptorInfo>(
                                access_check_info->indexed_interceptor()),
                            isolate_),
                     kIndexed)),
                 Nothing<bool>());
  }
  MAYBE_RETURN(
      (CollectInterceptorKeysInternal(
          receiver, object,
          handle(Cast<InterceptorInfo>(access_check_info->named_interceptor()),
                 isolate_),
          kNamed)),
      Nothing<bool>());
  return Just(true);
}

// Returns |true| on success, |false| if prototype walking should be stopped,
// |nothing| if an exception was thrown.
Maybe<bool> KeyAccumulator::CollectOwnKeys(DirectHandle<JSReceiver> receiver,
                                           Handle<JSObject> object) {
  // Check access rights if required.
  if (IsAccessCheckNeeded(*object) &&
      !isolate_->MayAccess(isolate_->native_context(), object)) {
    // The cross-origin spec says that [[Enumerate]] shall return an empty
    // iterator when it doesn't have access...
    if (mode_ == KeyCollectionMode::kIncludePrototypes) {
      return Just(false);
    }
    // ...whereas [[OwnPropertyKeys]] shall return allowlisted properties.
    DCHECK_EQ(KeyCollectionMode::kOwnOnly, mode_);
    Handle<AccessCheckInfo> access_check_info;
    {
      DisallowGarbageCollection no_gc;
      Tagged<AccessCheckInfo> maybe_info =
          AccessCheckInfo::Get(isolate_, object);
      if (!maybe_info.is_null()) {
        access_check_info = handle(maybe_info, isolate_);
      }
    }
    // We always have both kinds of interceptors or none.
    if (!access_check_info.is_null() &&
        access_check_info->named_interceptor() != Tagged<Object>()) {
      MAYBE_RETURN(CollectAccessCheckInterceptorKeys(access_check_info,
                                                     receiver, object),
                   Nothing<bool>());
    }
    return Just(false);
  }
  if (filter_ & PRIVATE_NAMES_ONLY) {
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectPrivateNames(receiver, object));
    return Just(true);
  }

  if (may_have_elements_) {
    MAYBE_RETURN(CollectOwnElementIndices(receiver, object), Nothing<bool>());
  }
  MAYBE_RETURN(CollectOwnPropertyNames(receiver, object), Nothing<bool>());
  return Just(true);
}

// static
Handle<FixedArray> KeyAccumulator::GetOwnEnumPropertyKeys(
    Isolate* isolate, DirectHandle<JSObject> object) {
  if (object->HasFastProperties()) {
    return GetFastEnumPropertyKeys(isolate, object);
  } else if (IsJSGlobalObject(*object)) {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad));
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        object->property_dictionary_swiss());
  } else {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        object->property_dictionary());
  }
}

namespace {

class NameComparator {
 public:
  explicit NameComparator(Isolate* isolate) : isolate_(isolate) {}

  bool operator()(uint32_t hash1, uint32_t hash2, const Handle<Name>& key1,
                  const Handle<Name>& key2) const {
    return Name::Equals(isolate_, key1, key2);
  }

 private:
  Isolate* isolate_;
};

}  // namespace

// ES6 #sec-proxy-object-internal-methods-and-internal-slots-ownpropertykeys
// Returns |true| on success, |nothing| in case of exception.
Maybe<bool> KeyAccumulator::CollectOwnJSProxyKeys(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSProxy> proxy) {
  STACK_CHECK(isolate_, Nothing<bool>());
  if (filter_ == PRIVATE_NAMES_ONLY) {
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(proxy->property_dictionary_swiss(), isolate_), this));
    } else {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(proxy->property_dictionary(), isolate_), this));
    }
    return Just(true);
  }

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate_);
  // 2. If handler is null, throw a TypeError exception.
  // 3. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, isolate_->factory()->ownKeys_string()));
    return Nothing<bool>();
  }
  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate_);
  // 5. Let trap be ? GetMethod(handler, "ownKeys").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap,
      Object::GetMethod(isolate_, Cast<JSReceiver>(handler),
                        isolate_->factory()->ownKeys_string()),
      Nothing<bool>());
  // 6. If trap is undefined, then
  if (IsUndefined(*trap, isolate_)) {
    // 6a. Return target.[[OwnPropertyKeys]]().
    return CollectOwnJSProxyTargetKeys(proxy, target);
  }
  // 7. Let trapResultArray be Call(trap, handler, «target»).
  Handle<Object> trap_result_array;
  Handle<Object> args[] = {target};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap_result_array,
      Execution::Call(isolate_, trap, handler, arraysize(args), args),
      Nothing<bool>());
  // 8. Let trapResult be ? CreateListFromArrayLike(trapResultArray,
  //    «String, Symbol»).
  Handle<FixedArray> trap_result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap_result,
      Object::CreateListFromArrayLike(isolate_, trap_result_array,
                                      ElementTypes::kStringAndSymbol),
      Nothing<bool>());
  // 9. If trapResult contains any duplicate entries, throw a TypeError
  // exception. Combine with step 18
  // 18. Let uncheckedResultKeys be a new List which is a copy of trapResult.
  Zone set_zone(isolate_->allocator(), ZONE_NAME);

  const int kPresent = 1;
  const int kGone = 0;
  using ZoneHashMapImpl =
      base::TemplateHashMapImpl<Handle<Name>, int, NameComparator,
                                ZoneAllocationPolicy>;
  ZoneHashMapImpl unchecked_result_keys(
      ZoneHashMapImpl::kDefaultHashMapCapacity, NameComparator(isolate_),
      ZoneAllocationPolicy(&set_zone));
  int unchecked_result_keys_size = 0;
  for (int i = 0; i < trap_result->length(); ++i) {
    Handle<Name> key(Cast<Name>(trap_result->get(i)), isolate_);
    auto entry = unchecked_result_keys.LookupOrInsert(key, key->EnsureHash());
    if (entry->value != kPresent) {
      entry->value = kPresent;
      unchecked_result_keys_size++;
    } else {
      // found dupes, throw exception
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysDuplicateEntries));
      return Nothing<bool>();
    }
  }
  // 10. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> maybe_extensible = JSReceiver::IsExtensible(isolate_, target);
  MAYBE_RETURN(maybe_extensible, Nothing<bool>());
  bool extensible_target = maybe_extensible.FromJust();
  // 11. Let targetKeys be ? target.[[OwnPropertyKeys]]().
  Handle<FixedArray> target_keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, target_keys, JSReceiver::OwnPropertyKeys(isolate_, target),
      Nothing<bool>());
  // 12, 13. (Assert)
  // 14. Let targetConfigurableKeys be an empty List.
  // To save memory, we're re-using target_keys and will modify it in-place.
  DirectHandle<FixedArray> target_configurable_keys = target_keys;
  // 15. Let targetNonconfigurableKeys be an empty List.
  DirectHandle<FixedArray> target_nonconfigurable_keys =
      isolate_->factory()->NewFixedArray(target_keys->length());
  int nonconfigurable_keys_length = 0;
  // 16. Repeat, for each element key of targetKeys:
  for (int i = 0; i < target_keys->length(); ++i) {
    // 16a. Let desc be ? target.[[GetOwnProperty]](key).
    PropertyDescriptor desc;
    Maybe<bool> found = JSReceiver::GetOwnPropertyDescriptor(
        isolate_, target, handle(target_keys->get(i), isolate_), &desc);
    MAYBE_RETURN(found, Nothing<bool>());
    // 16b. If desc is not undefined and desc.[[Configurable]] is false, then
    if (found.FromJust() && !desc.configurable()) {
      // 16b i. Append key as an element of targetNonconfigurableKeys.
      target_nonconfigurable_keys->set(nonconfigurable_keys_length,
                                       target_keys->get(i));
      nonconfigurable_keys_length++;
      // The key was moved, null it out in the original list.
      target_keys->set(i, Smi::zero());
    } else {
      // 16c. Else,
      // 16c i. Append key as an element of targetConfigurableKeys.
      // (No-op, just keep it in |target_keys|.)
    }
  }
  // 17. If extensibleTarget is true and targetNonconfigurableKeys is empty,
  //     then:
  if (extensible_target && nonconfigurable_keys_length == 0) {
    // 17a. Return trapResult.
    return AddKeysFromJSProxy(proxy, trap_result);
  }
  // 18. (Done in step 9)
  // 19. Repeat, for each key that is an element of targetNonconfigurableKeys:
  for (int i = 0; i < nonconfigurable_keys_length; ++i) {
    Tagged<Object> raw_key = target_nonconfigurable_keys->get(i);
    Handle<Name> key(Cast<Name>(raw_key), isolate_);
    // 19a. If key is not an element of uncheckedResultKeys, throw a
    //      TypeError exception.
    auto found = unchecked_result_keys.Lookup(key, key->hash());
    if (found == nullptr || found->value == kGone) {
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysMissing, key));
      return Nothing<bool>();
    }
    // 19b. Remove key from uncheckedResultKeys.
    found->value = kGone;
    unchecked_result_keys_size--;
  }
  // 20. If extensibleTarget is true, return trapResult.
  if (extensible_target) {
    return AddKeysFromJSProxy(proxy, trap_result);
  }
  // 21. Repeat, for each key that is an element of targetConfigurableKeys:
  for (int i = 0; i < target_configurable_keys->length(); ++i) {
    Tagged<Object> raw_key = target_configurable_keys->get(i);
    if (IsSmi(raw_key)) continue;  // Zapped entry, was nonconfigurable.
    Handle<Name> key(Cast<Name>(raw_key), isolate_);
    // 21a. If key is not an element of uncheckedResultKeys, throw a
    //      TypeError exception.
    auto found = unchecked_result_keys.Lookup(key, key->hash());
    if (found == nullptr || found->value == kGone) {
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysMissing, key));
      return Nothing<bool>();
    }
    // 21b. Remove key from uncheckedResultKeys.
    found->value = kGone;
    unchecked_result_keys_size--;
  }
  // 22. If uncheckedResultKeys is not empty, throw a TypeError exception.
  if (unchecked_result_keys_size != 0) {
    DCHECK_GT(unchecked_result_keys_size, 0);
    isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kProxyOwnKeysNonExtensible));
    return Nothing<bool>();
  }
  // 23. Return trapResult.
  return AddKeysFromJSProxy(proxy, trap_result);
}

Maybe<bool> KeyAccumulator::CollectOwnJSProxyTargetKeys(
    DirectHandle<JSProxy> proxy, Handle<JSReceiver> target) {
  // TODO(cbruni): avoid creating another KeyAccumulator
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, keys,
      KeyAccumulator::GetKeys(
          isolate_, target, KeyCollectionMode::kOwnOnly, ALL_PROPERTIES,
          GetKeysConversion::kConvertToString, is_for_in_, skip_indices_),
      Nothing<bool>());
  Maybe<bool> result = AddKeysFromJSProxy(proxy, keys);
  return result;
}

#undef RETURN_NOTHING_IF_NOT_SUCCESSFUL
#undef RETURN_FAILURE_IF_NOT_SUCCESSFUL
}  // namespace v8::internal

"""

```