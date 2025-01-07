Response:
The user wants to understand the functionality of the `v8/src/objects/lookup.cc` file. I need to analyze the provided C++ code and summarize its purpose.

Here's a breakdown of the functionalities I can identify from the code:

1. **Property Lookup:** The code heavily revolves around looking up properties on JavaScript objects. The `LookupIterator` class seems to be the core component for this.
2. **Property Key Handling:** The `PropertyKey` class appears to handle different types of property keys (integer indices and names).
3. **Prototype Chain Traversal:** The `LookupIterator` has logic to traverse the prototype chain of objects during property lookups.
4. **Property Details:** The code deals with `PropertyDetails`, which likely stores information about a property (e.g., attributes, kind).
5. **Interceptor Handling:** There's mention of interceptors and handling their presence during lookups.
6. **Transitioning Object Maps:**  The code includes logic for transitioning object maps when adding or modifying properties, especially concerning fast and slow (dictionary) property modes.
7. **Element Access:**  The code handles lookups for indexed properties (elements) of objects, including typed arrays.
8. **Special Objects:** There's specific handling for lookups on special receiver types like strings.
9. **Protector Invalidation:** The code includes logic to invalidate "protectors" when certain properties related to built-in objects (like Array, Promise, RegExp) are modified. This suggests an optimization mechanism.
10. **Data Property Preparation and Modification:**  The code provides methods to prepare objects for data properties and to reconfigure existing data properties.
11. **Global Object Handling:** There's special handling for property lookups and modifications on global objects.
12. **Property Deletion:**  The `Delete()` method indicates functionality for deleting properties.

Based on these observations, I can now formulate a summary of the file's functionality.
`v8/src/objects/lookup.cc` 是 V8 引擎中负责**属性查找**的核心组件。它提供了一种机制，用于在 JavaScript 对象及其原型链上查找属性（包括命名字段和索引元素）。

由于该文件以 `.cc` 结尾，它是一个 **V8 C++ 源代码**，而不是 Torque 源代码。

**主要功能归纳：**

1. **`PropertyKey` 类：**
    *   负责将传入的属性键（可以是字符串或数字）转换为内部表示形式。
    *   尝试将键转换为整数索引或内部化的字符串名称。
    *   如果转换失败（例如，键不是有效的属性名），则会设置错误状态。

2. **`LookupIterator` 类：**
    *   **核心类，用于执行属性查找操作。**
    *   支持在对象自身以及其原型链上查找属性。
    *   区分命名字段和索引元素（例如数组的元素）。
    *   处理不同类型的对象，包括普通对象、数组、字符串以及特殊对象（例如 Proxy）。
    *   维护查找过程中的状态，例如当前查找的对象 (`holder_`) 和查找到的属性信息 (`property_details_`)。
    *   处理查找未找到的情况。
    *   处理访问器属性（getter 和 setter）。
    *   处理拦截器（interceptors）。
    *   在查找过程中，会考虑对象的属性存储方式（例如，快速属性与字典属性）。
    *   在添加或修改属性时，可能触发对象形状的转换（map transition）。
    *   提供方法来重新加载属性信息，例如在对象形状发生变化后。
    *   包含用于更新“保护器”（protectors）的逻辑，这些保护器用于优化特定内置对象的属性查找。

**与 JavaScript 功能的关系（并用 JavaScript 举例说明）：**

`v8/src/objects/lookup.cc` 的功能直接对应于 JavaScript 中访问对象属性的操作，例如：

```javascript
const obj = { a: 1, b: 2 };
console.log(obj.a); // 属性查找：查找 obj 对象的 "a" 属性

const arr = [10, 20, 30];
console.log(arr[1]); // 属性查找：查找 arr 对象的索引为 1 的元素

const proto = { c: 3 };
const inheritedObj = Object.create(proto);
console.log(inheritedObj.c); // 属性查找：在 inheritedObj 及其原型 proto 上查找 "c" 属性
```

在 V8 引擎内部，当我们执行这些 JavaScript 代码时，`LookupIterator` 类会被用来执行实际的属性查找过程。

**代码逻辑推理（假设输入与输出）：**

假设有以下 JavaScript 代码：

```javascript
const obj = { x: 10 };
```

当我们尝试访问 `obj.x` 时，`LookupIterator` 的 `Start()` 方法会被调用，`lookup_start_object_` 指向 `obj` 对象，`index_` 为 `LookupIterator::kInvalidIndex`（因为是命名字段 "x"）。

**假设输入：**

*   `lookup_start_object_`: 指向 JavaScript 对象 `{ x: 10 }` 的指针。
*   `index_`: `LookupIterator::kInvalidIndex`
*   属性名: "x"

**可能的输出（取决于对象的内部表示）：**

*   `state_`: `DATA` (表示找到了一个数据属性)
*   `holder_`: 指向 `obj` 对象的指针。
*   `property_details_`: 包含属性 "x" 的详细信息，例如其属性（可写、可枚举等）。
*   `number_`: 属性在对象内部描述符数组中的索引。

**用户常见的编程错误（举例说明）：**

1. **访问未定义的属性导致错误：**

    ```javascript
    const obj = { a: 1 };
    console.log(obj.b.toUpperCase()); // TypeError: Cannot read properties of undefined (reading 'toUpperCase')
    ```

    在这个例子中，尝试访问 `obj.b` 会导致 `LookupIterator` 找不到属性 "b"，返回 `undefined`。然后对 `undefined` 调用 `toUpperCase()` 会抛出 `TypeError`。

2. **意外地屏蔽了原型链上的属性：**

    ```javascript
    const parent = { name: 'Parent' };
    const child = Object.create(parent);
    console.log(child.name); // 输出 "Parent"
    child.name = 'Child';
    console.log(child.name); // 输出 "Child"，child 自身有了 name 属性，屏蔽了 parent 的 name 属性
    ```

    `LookupIterator` 会先在 `child` 对象自身查找 `name` 属性，如果找到则停止查找。只有当 `child` 对象自身没有 `name` 属性时，才会继续在 `parent` 原型对象上查找。

**功能归纳（第 1 部分）：**

`v8/src/objects/lookup.cc` 的第一部分主要定义了用于属性查找的基础结构和起始流程。它包含了：

*   `PropertyKey` 类，用于表示和转换属性键。
*   `LookupIterator` 类，作为属性查找的核心迭代器，其 `Start()` 方法负责初始化查找过程，确定查找的起始对象和属性键，并尝试在起始对象上找到该属性。
*   定义了 `LookupIterator` 的一些基本方法和模板，为后续的查找和属性处理逻辑奠定了基础。
*   处理了在非 `JSReceiver` 对象（例如原始值包装器）上进行属性查找的特殊情况。

总而言之，这一部分的代码专注于**属性查找的启动和初步定位**，为后续的查找、访问和修改属性操作提供了必要的上下文和工具。

Prompt: 
```
这是目录为v8/src/objects/lookup.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/lookup.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/lookup.h"

#include <optional>

#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/elements.h"
#include "src/objects/field-type.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/property-details.h"
#include "src/objects/struct-inl.h"

namespace v8::internal {

PropertyKey::PropertyKey(Isolate* isolate, Handle<Object> key, bool* success) {
  if (Object::ToIntegerIndex(*key, &index_)) {
    *success = true;
    return;
  }
  *success = Object::ToName(isolate, key).ToHandle(&name_);
  if (!*success) {
    DCHECK(isolate->has_exception());
    index_ = LookupIterator::kInvalidIndex;
    return;
  }
  if (!name_->AsIntegerIndex(&index_)) {
    // Make sure the name is internalized.
    name_ = isolate->factory()->InternalizeName(name_);
    // {AsIntegerIndex} may modify {index_} before deciding to fail.
    index_ = LookupIterator::kInvalidIndex;
  }
}

template <bool is_element>
void LookupIterator::Start() {
  // GetRoot might allocate if lookup_start_object_ is a string.
  MaybeHandle<JSReceiver> maybe_holder =
      GetRoot(isolate_, lookup_start_object_, index_, configuration_);
  if (!maybe_holder.ToHandle(&holder_)) {
    // This is an attempt to perform an own property lookup on a non-JSReceiver
    // that doesn't have any properties.
    DCHECK(!IsJSReceiver(*lookup_start_object_));
    DCHECK(!check_prototype_chain());
    has_property_ = false;
    state_ = NOT_FOUND;
    return;
  }

  {
    DisallowGarbageCollection no_gc;

    has_property_ = false;
    state_ = NOT_FOUND;

    Tagged<JSReceiver> holder = *holder_;
    Tagged<Map> map = holder->map(isolate_);

    state_ = LookupInHolder<is_element>(map, holder);
    if (IsFound()) return;

    NextInternal<is_element>(map, holder);
  }
}

template void LookupIterator::Start<true>();
template void LookupIterator::Start<false>();

void LookupIterator::Next() {
  DCHECK_NE(JSPROXY, state_);
  DCHECK_NE(TRANSITION, state_);
  DCHECK_NE(NOT_FOUND, state_);
  DisallowGarbageCollection no_gc;
  has_property_ = false;

  Tagged<JSReceiver> holder = *holder_;
  Tagged<Map> map = holder->map(isolate_);

  if (IsSpecialReceiverMap(map)) {
    state_ = IsElement() ? LookupInSpecialHolder<true>(map, holder)
                         : LookupInSpecialHolder<false>(map, holder);
    if (IsFound()) return;
  }

  IsElement() ? NextInternal<true>(map, holder)
              : NextInternal<false>(map, holder);
}

template <bool is_element>
void LookupIterator::NextInternal(Tagged<Map> map, Tagged<JSReceiver> holder) {
  do {
    Tagged<JSReceiver> maybe_holder = NextHolder(map);
    if (maybe_holder.is_null()) {
      if (interceptor_state_ == InterceptorState::kSkipNonMasking) {
        RestartLookupForNonMaskingInterceptors<is_element>();
        return;
      }
      state_ = NOT_FOUND;
      if (holder != *holder_) holder_ = handle(holder, isolate_);
      return;
    }
    holder = maybe_holder;
    map = holder->map(isolate_);
    state_ = LookupInHolder<is_element>(map, holder);
  } while (!IsFound());

  holder_ = handle(holder, isolate_);
}

template <bool is_element>
void LookupIterator::RestartInternal(InterceptorState interceptor_state) {
  interceptor_state_ = interceptor_state;
  property_details_ = PropertyDetails::Empty();
  number_ = InternalIndex::NotFound();
  Start<is_element>();
}

template void LookupIterator::RestartInternal<true>(InterceptorState);
template void LookupIterator::RestartInternal<false>(InterceptorState);

void LookupIterator::RecheckTypedArrayBounds() {
  DCHECK(IsJSTypedArray(*holder_, isolate_));
  DCHECK_EQ(state_, TYPED_ARRAY_INDEX_NOT_FOUND);

  if (!IsElement(*holder_)) {
    // This happens when the index is not an allowed index.
    return;
  }

  Tagged<JSObject> js_object = Cast<JSObject>(*holder_);
  ElementsAccessor* accessor = js_object->GetElementsAccessor(isolate_);
  Tagged<FixedArrayBase> backing_store = js_object->elements(isolate_);
  number_ =
      accessor->GetEntryForIndex(isolate_, js_object, backing_store, index_);

  if (number_.is_not_found()) {
    // The state is already TYPED_ARRAY_INDEX_NOT_FOUND.
    return;
  }
  property_details_ = accessor->GetDetails(js_object, number_);
#ifdef DEBUG
  Tagged<Map> map = holder_->map(isolate_);
  DCHECK(!map->has_frozen_elements());
  DCHECK(!map->has_sealed_elements());
#endif  // DEBUG
  has_property_ = true;
  DCHECK_EQ(property_details_.kind(), v8::internal::PropertyKind::kData);
  state_ = DATA;
}

// static
MaybeHandle<JSReceiver> LookupIterator::GetRootForNonJSReceiver(
    Isolate* isolate, DirectHandle<JSPrimitive> lookup_start_object,
    size_t index, Configuration configuration) {
  // Strings are the only non-JSReceiver objects with properties (only elements
  // and 'length') directly on the wrapper. Hence we can skip generating
  // the wrapper for all other cases.
  bool own_property_lookup = (configuration & kPrototypeChain) == 0;
  if (IsString(*lookup_start_object, isolate)) {
    if (own_property_lookup ||
        index <
            static_cast<size_t>(Cast<String>(*lookup_start_object)->length())) {
      // TODO(verwaest): Speed this up. Perhaps use a cached wrapper on the
      // native context, ensuring that we don't leak it into JS?
      Handle<JSFunction> constructor = isolate->string_function();
      Handle<JSObject> result = isolate->factory()->NewJSObject(constructor);
      Cast<JSPrimitiveWrapper>(result)->set_value(*lookup_start_object);
      return result;
    }
  } else if (own_property_lookup) {
    // Signal that the lookup will not find anything.
    return {};
  }
  Handle<HeapObject> root(
      Object::GetPrototypeChainRootMap(*lookup_start_object, isolate)
          ->prototype(isolate),
      isolate);
  if (IsNull(*root, isolate)) {
    isolate->PushStackTraceAndDie(
        reinterpret_cast<void*>((*lookup_start_object).ptr()));
  }
  return Cast<JSReceiver>(root);
}

Handle<Map> LookupIterator::GetReceiverMap() const {
  if (IsNumber(*receiver_, isolate_)) return factory()->heap_number_map();
  return handle(Cast<HeapObject>(receiver_)->map(isolate_), isolate_);
}

bool LookupIterator::HasAccess() const {
  // TRANSITION is true when being called from DefineNamedOwnIC.
  DCHECK(state_ == ACCESS_CHECK || state_ == TRANSITION);
  return isolate_->MayAccess(isolate_->native_context(), GetHolder<JSObject>());
}

template <bool is_element>
void LookupIterator::ReloadPropertyInformation() {
  state_ = BEFORE_PROPERTY;
  interceptor_state_ = InterceptorState::kUninitialized;
  state_ = LookupInHolder<is_element>(holder_->map(isolate_), *holder_);
  DCHECK(IsFound() || !holder_->HasFastProperties(isolate_));
}

// static
void LookupIterator::InternalUpdateProtector(Isolate* isolate,
                                             Handle<JSAny> receiver_generic,
                                             DirectHandle<Name> name) {
  if (isolate->bootstrapper()->IsActive()) return;
  if (!IsJSObject(*receiver_generic)) return;
  auto receiver = Cast<JSObject>(receiver_generic);

  ReadOnlyRoots roots(isolate);
  if (*name == roots.constructor_string()) {
    // Setting the constructor property could change an instance's @@species
    if (IsJSArray(*receiver, isolate)) {
      if (!Protectors::IsArraySpeciesLookupChainIntact(isolate)) return;
      isolate->CountUsage(
          v8::Isolate::UseCounterFeature::kArrayInstanceConstructorModified);
      Protectors::InvalidateArraySpeciesLookupChain(isolate);
      return;
    } else if (IsJSPromise(*receiver, isolate)) {
      if (!Protectors::IsPromiseSpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidatePromiseSpeciesLookupChain(isolate);
      return;
    } else if (IsJSRegExp(*receiver, isolate)) {
      if (!Protectors::IsRegExpSpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidateRegExpSpeciesLookupChain(isolate);
      return;
    } else if (IsJSTypedArray(*receiver, isolate)) {
      if (!Protectors::IsTypedArraySpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidateTypedArraySpeciesLookupChain(isolate);
      return;
    }
    if (receiver->map(isolate)->is_prototype_map()) {
      DisallowGarbageCollection no_gc;
      // Setting the constructor of any prototype with the @@species protector
      // (of any realm) also needs to invalidate the protector.
      if (isolate->IsInCreationContext(
              Cast<JSObject>(*receiver),
              Context::INITIAL_ARRAY_PROTOTYPE_INDEX)) {
        if (!Protectors::IsArraySpeciesLookupChainIntact(isolate)) return;
        isolate->CountUsage(
            v8::Isolate::UseCounterFeature::kArrayPrototypeConstructorModified);
        Protectors::InvalidateArraySpeciesLookupChain(isolate);
      } else if (IsJSPromisePrototype(*receiver)) {
        if (!Protectors::IsPromiseSpeciesLookupChainIntact(isolate)) return;
        Protectors::InvalidatePromiseSpeciesLookupChain(isolate);
      } else if (IsJSRegExpPrototype(*receiver)) {
        if (!Protectors::IsRegExpSpeciesLookupChainIntact(isolate)) return;
        Protectors::InvalidateRegExpSpeciesLookupChain(isolate);
      } else if (IsJSTypedArrayPrototype(*receiver)) {
        if (!Protectors::IsTypedArraySpeciesLookupChainIntact(isolate)) return;
        Protectors::InvalidateTypedArraySpeciesLookupChain(isolate);
      }
    }
  } else if (*name == roots.next_string()) {
    if (IsJSArrayIterator(*receiver) || IsJSArrayIteratorPrototype(*receiver)) {
      // Setting the next property of %ArrayIteratorPrototype% also needs to
      // invalidate the array iterator protector.
      if (!Protectors::IsArrayIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateArrayIteratorLookupChain(isolate);
    } else if (IsJSMapIterator(*receiver) ||
               IsJSMapIteratorPrototype(*receiver)) {
      if (!Protectors::IsMapIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateMapIteratorLookupChain(isolate);
    } else if (IsJSSetIterator(*receiver) ||
               IsJSSetIteratorPrototype(*receiver)) {
      if (!Protectors::IsSetIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateSetIteratorLookupChain(isolate);
    } else if (IsJSStringIterator(*receiver) ||
               IsJSStringIteratorPrototype(*receiver)) {
      // Setting the next property of %StringIteratorPrototype% invalidates the
      // string iterator protector.
      if (!Protectors::IsStringIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateStringIteratorLookupChain(isolate);
    }
  } else if (*name == roots.species_symbol()) {
    // Setting the Symbol.species property of any Array, Promise or TypedArray
    // constructor invalidates the @@species protector
    if (IsJSArrayConstructor(*receiver)) {
      if (!Protectors::IsArraySpeciesLookupChainIntact(isolate)) return;
      isolate->CountUsage(
          v8::Isolate::UseCounterFeature::kArraySpeciesModified);
      Protectors::InvalidateArraySpeciesLookupChain(isolate);
    } else if (IsJSPromiseConstructor(*receiver)) {
      if (!Protectors::IsPromiseSpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidatePromiseSpeciesLookupChain(isolate);
    } else if (IsJSRegExpConstructor(*receiver)) {
      if (!Protectors::IsRegExpSpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidateRegExpSpeciesLookupChain(isolate);
    } else if (IsTypedArrayConstructor(*receiver)) {
      if (!Protectors::IsTypedArraySpeciesLookupChainIntact(isolate)) return;
      Protectors::InvalidateTypedArraySpeciesLookupChain(isolate);
    }
  } else if (*name == roots.is_concat_spreadable_symbol()) {
    if (!Protectors::IsIsConcatSpreadableLookupChainIntact(isolate)) return;
    Protectors::InvalidateIsConcatSpreadableLookupChain(isolate);
  } else if (*name == roots.iterator_symbol()) {
    if (IsJSArray(*receiver, isolate)) {
      if (!Protectors::IsArrayIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateArrayIteratorLookupChain(isolate);
    } else if (IsJSSet(*receiver, isolate) || IsJSSetIterator(*receiver) ||
               IsJSSetIteratorPrototype(*receiver) ||
               IsJSSetPrototype(*receiver)) {
      if (Protectors::IsSetIteratorLookupChainIntact(isolate)) {
        Protectors::InvalidateSetIteratorLookupChain(isolate);
      }
    } else if (IsJSMapIterator(*receiver) ||
               IsJSMapIteratorPrototype(*receiver)) {
      if (Protectors::IsMapIteratorLookupChainIntact(isolate)) {
        Protectors::InvalidateMapIteratorLookupChain(isolate);
      }
    } else if (IsJSIteratorPrototype(*receiver)) {
      if (Protectors::IsMapIteratorLookupChainIntact(isolate)) {
        Protectors::InvalidateMapIteratorLookupChain(isolate);
      }
      if (Protectors::IsSetIteratorLookupChainIntact(isolate)) {
        Protectors::InvalidateSetIteratorLookupChain(isolate);
      }
    } else if (isolate->IsInCreationContext(
                   *receiver, Context::INITIAL_STRING_PROTOTYPE_INDEX)) {
      // Setting the Symbol.iterator property of String.prototype invalidates
      // the string iterator protector. Symbol.iterator can also be set on a
      // String wrapper, but not on a primitive string. We only support
      // protector for primitive strings.
      if (!Protectors::IsStringIteratorLookupChainIntact(isolate)) return;
      Protectors::InvalidateStringIteratorLookupChain(isolate);
    }
  } else if (*name == roots.resolve_string()) {
    if (!Protectors::IsPromiseResolveLookupChainIntact(isolate)) return;
    // Setting the "resolve" property on any %Promise% intrinsic object
    // invalidates the Promise.resolve protector.
    if (IsJSPromiseConstructor(*receiver)) {
      Protectors::InvalidatePromiseResolveLookupChain(isolate);
    }
  } else if (*name == roots.then_string()) {
    if (!Protectors::IsPromiseThenLookupChainIntact(isolate)) return;
    // Setting the "then" property on any JSPromise instance or on the
    // initial %PromisePrototype% invalidates the Promise#then protector.
    // Also setting the "then" property on the initial %ObjectPrototype%
    // invalidates the Promise#then protector, since we use this protector
    // to guard the fast-path in AsyncGeneratorResolve, where we can skip
    // the ResolvePromise step and go directly to FulfillPromise if we
    // know that the Object.prototype doesn't contain a "then" method.
    if (IsJSPromise(*receiver, isolate) || IsJSObjectPrototype(*receiver) ||
        IsJSPromisePrototype(*receiver)) {
      Protectors::InvalidatePromiseThenLookupChain(isolate);
    }
  } else if (*name == roots.match_all_symbol() ||
             *name == roots.replace_symbol() || *name == roots.split_symbol()) {
    if (!Protectors::IsNumberStringNotRegexpLikeIntact(isolate)) return;
    // We need to protect the prototype chains of `Number.prototype` and
    // `String.prototype`: that `Symbol.{matchAll|replace|split}` is not added
    // as a property on any object on these prototype chains. We detect
    // `Number.prototype` and `String.prototype` by checking for a prototype
    // that is a JSPrimitiveWrapper. This is a safe approximation. Using
    // JSPrimitiveWrapper as prototype should be sufficiently rare.
    if (receiver->map()->is_prototype_map() &&
        (IsJSPrimitiveWrapper(*receiver) || IsJSObjectPrototype(*receiver))) {
      Protectors::InvalidateNumberStringNotRegexpLike(isolate);
    }
  } else if (*name == roots.to_primitive_symbol()) {
    if (!Protectors::IsStringWrapperToPrimitiveIntact(isolate)) return;
    if (isolate->IsInCreationContext(*receiver,
                                     Context::INITIAL_STRING_PROTOTYPE_INDEX) ||
        isolate->IsInCreationContext(*receiver,
                                     Context::INITIAL_OBJECT_PROTOTYPE_INDEX) ||
        IsStringWrapper(*receiver)) {
      Protectors::InvalidateStringWrapperToPrimitive(isolate);
    }
  } else if (*name == roots.valueOf_string()) {
    if (!Protectors::IsStringWrapperToPrimitiveIntact(isolate)) return;
    if (isolate->IsInCreationContext(*receiver,
                                     Context::INITIAL_STRING_PROTOTYPE_INDEX) ||
        IsStringWrapper(*receiver)) {
      Protectors::InvalidateStringWrapperToPrimitive(isolate);
    }
  }
}

void LookupIterator::PrepareForDataProperty(DirectHandle<Object> value) {
  DCHECK(state_ == DATA || state_ == ACCESSOR);
  DCHECK(HolderIsReceiverOrHiddenPrototype());
  DCHECK(!IsWasmObject(*receiver_, isolate_));

  Handle<JSReceiver> holder = GetHolder<JSReceiver>();
  // We are not interested in tracking constness of a JSProxy's direct
  // properties.
  DCHECK_IMPLIES(IsJSProxy(*holder, isolate_), name()->IsPrivate());
  if (IsJSProxy(*holder, isolate_)) return;

  if (IsElement(*holder)) {
    Handle<JSObject> holder_obj = Cast<JSObject>(holder);
    ElementsKind kind = holder_obj->GetElementsKind(isolate_);
    ElementsKind to = Object::OptimalElementsKind(*value, isolate_);
    if (IsHoleyElementsKind(kind)) to = GetHoleyElementsKind(to);
    to = GetMoreGeneralElementsKind(kind, to);

    if (kind != to) {
      JSObject::TransitionElementsKind(holder_obj, to);
    }

    // Copy the backing store if it is copy-on-write.
    if (IsSmiOrObjectElementsKind(to) || IsSealedElementsKind(to) ||
        IsNonextensibleElementsKind(to)) {
      JSObject::EnsureWritableFastElements(holder_obj);
    }
    return;
  }

  if (IsJSGlobalObject(*holder, isolate_)) {
    DirectHandle<GlobalDictionary> dictionary(
        Cast<JSGlobalObject>(*holder)->global_dictionary(isolate_,
                                                         kAcquireLoad),
        isolate());
    DirectHandle<PropertyCell> cell(
        dictionary->CellAt(isolate_, dictionary_entry()), isolate());
    property_details_ = cell->property_details();
    PropertyCell::PrepareForAndSetValue(
        isolate(), dictionary, dictionary_entry(), value, property_details_);
    return;
  }

  PropertyConstness new_constness = PropertyConstness::kConst;
  if (constness() == PropertyConstness::kConst) {
    DCHECK_EQ(PropertyKind::kData, property_details_.kind());
    // Check that current value matches new value otherwise we should make
    // the property mutable.
    if (holder->HasFastProperties(isolate_)) {
      if (!CanStayConst(*value)) new_constness = PropertyConstness::kMutable;
    } else if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) {
      if (!DictCanStayConst(*value)) {
        property_details_ =
            property_details_.CopyWithConstness(PropertyConstness::kMutable);

        // We won't reach the map updating code after Map::Update below, because
        // that's only for the case that the existing map is a fast mode map.
        // Therefore, we need to perform the necessary updates to the property
        // details and the prototype validity cell directly.
        if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
          Tagged<SwissNameDictionary> dict =
              holder->property_dictionary_swiss();
          dict->DetailsAtPut(dictionary_entry(), property_details_);
        } else {
          Tagged<NameDictionary> dict = holder->property_dictionary();
          dict->DetailsAtPut(dictionary_entry(), property_details_);
        }

        Tagged<Map> old_map = holder->map(isolate_);
        if (old_map->is_prototype_map()) {
          JSObject::InvalidatePrototypeChains(old_map);
        }
      }
      return;
    }
  }

  if (!holder->HasFastProperties(isolate_)) return;

  auto holder_obj = Cast<JSObject>(holder);
  Handle<Map> old_map(holder->map(isolate_), isolate_);

  Handle<Map> new_map = Map::Update(isolate_, old_map);
  if (!new_map->is_dictionary_map()) {  // fast -> fast
    new_map = Map::PrepareForDataProperty(
        isolate(), new_map, descriptor_number(), new_constness, value);

    if (old_map.is_identical_to(new_map)) {
      // Update the property details if the representation was None.
      if (constness() != new_constness || representation().IsNone()) {
        property_details_ = new_map->instance_descriptors(isolate_)->GetDetails(
            descriptor_number());
      }
      return;
    }
  }
  // We should only get here if the new_map is different from the old map,
  // otherwise we would have falled through to the is_identical_to check above.
  DCHECK_NE(*old_map, *new_map);

  JSObject::MigrateToMap(isolate_, holder_obj, new_map);
  ReloadPropertyInformation<false>();

  // If we transitioned from fast to slow and the property changed from kConst
  // to kMutable, then this change in the constness is indicated by neither the
  // old or the new map. We need to update the constness ourselves.
  DCHECK(!old_map->is_dictionary_map());
  if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && new_map->is_dictionary_map() &&
      new_constness == PropertyConstness::kMutable) {  // fast -> slow
    property_details_ =
        property_details_.CopyWithConstness(PropertyConstness::kMutable);

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict =
          holder_obj->property_dictionary_swiss();
      dict->DetailsAtPut(dictionary_entry(), property_details_);
    } else {
      Tagged<NameDictionary> dict = holder_obj->property_dictionary();
      dict->DetailsAtPut(dictionary_entry(), property_details_);
    }

    DCHECK_IMPLIES(new_map->is_prototype_map(),
                   !new_map->IsPrototypeValidityCellValid());
  }
}

void LookupIterator::ReconfigureDataProperty(Handle<Object> value,
                                             PropertyAttributes attributes) {
  DCHECK(state_ == DATA || state_ == ACCESSOR);
  DCHECK(HolderIsReceiverOrHiddenPrototype());

  Handle<JSReceiver> holder = GetHolder<JSReceiver>();
  if (V8_UNLIKELY(IsWasmObject(*holder))) UNREACHABLE();

  // Property details can never change for private properties.
  if (IsJSProxy(*holder, isolate_)) {
    DCHECK(name()->IsPrivate());
    return;
  }

  Handle<JSObject> holder_obj = Cast<JSObject>(holder);
  if (IsElement(*holder)) {
    DCHECK(!holder_obj->HasTypedArrayOrRabGsabTypedArrayElements(isolate_));
    DCHECK(attributes != NONE || !holder_obj->HasFastElements(isolate_));
    Handle<FixedArrayBase> elements(holder_obj->elements(isolate_), isolate());
    holder_obj->GetElementsAccessor(isolate_)->Reconfigure(
        holder_obj, elements, number_, value, attributes);
    ReloadPropertyInformation<true>();
  } else if (holder_obj->HasFastProperties(isolate_)) {
    Handle<Map> old_map(holder_obj->map(isolate_), isolate_);
    // Force mutable to avoid changing constant value by reconfiguring
    // kData -> kAccessor -> kData.
    Handle<Map> new_map = MapUpdater::ReconfigureExistingProperty(
        isolate_, old_map, descriptor_number(), i::PropertyKind::kData,
        attributes, PropertyConstness::kMutable);
    if (!new_map->is_dictionary_map()) {
      // Make sure that the data property has a compatible representation.
      // TODO(leszeks): Do this as part of ReconfigureExistingProperty.
      new_map =
          Map::PrepareForDataProperty(isolate(), new_map, descriptor_number(),
                                      PropertyConstness::kMutable, value);
    }
    JSObject::MigrateToMap(isolate_, holder_obj, new_map);
    ReloadPropertyInformation<false>();
  }

  if (!IsElement(*holder) && !holder_obj->HasFastProperties(isolate_)) {
    if (holder_obj->map(isolate_)->is_prototype_map() &&
        (((property_details_.attributes() & READ_ONLY) == 0 &&
          (attributes & READ_ONLY) != 0) ||
         (property_details_.attributes() & DONT_ENUM) !=
             (attributes & DONT_ENUM))) {
      // Invalidate prototype validity cell when a property is reconfigured
      // from writable to read-only as this may invalidate transitioning store
      // IC handlers.
      // Invalidate prototype validity cell when a property changes
      // enumerability to clear the prototype chain enum cache.
      JSObject::InvalidatePrototypeChains(holder->map(isolate_));
    }
    if (IsJSGlobalObject(*holder_obj, isolate_)) {
      PropertyDetails details(PropertyKind::kData, attributes,
                              PropertyCellType::kMutable);
      DirectHandle<GlobalDictionary> dictionary(
          Cast<JSGlobalObject>(*holder_obj)
              ->global_dictionary(isolate_, kAcquireLoad),
          isolate());

      DirectHandle<PropertyCell> cell = PropertyCell::PrepareForAndSetValue(
          isolate(), dictionary, dictionary_entry(), value, details);
      property_details_ = cell->property_details();
      DCHECK_EQ(cell->value(), *value);
    } else {
      PropertyDetails details(PropertyKind::kData, attributes,
                              PropertyConstness::kMutable);
      if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        DirectHandle<SwissNameDictionary> dictionary(
            holder_obj->property_dictionary_swiss(isolate_), isolate());
        dictionary->ValueAtPut(dictionary_entry(), *value);
        dictionary->DetailsAtPut(dictionary_entry(), details);
        DCHECK_EQ(details.AsSmi(),
                  dictionary->DetailsAt(dictionary_entry()).AsSmi());
        property_details_ = details;
      } else {
        DirectHandle<NameDictionary> dictionary(
            holder_obj->property_dictionary(isolate_), isolate());
        PropertyDetails original_details =
            dictionary->DetailsAt(dictionary_entry());
        int enumeration_index = original_details.dictionary_index();
        DCHECK_GT(enumeration_index, 0);
        details = details.set_index(enumeration_index);
        dictionary->SetEntry(dictionary_entry(), *name(), *value, details);
        property_details_ = details;
      }
    }
    state_ = DATA;
  }

  WriteDataValue(value, true);

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    holder->HeapObjectVerify(isolate());
  }
#endif
}

// Can only be called when the receiver is a JSObject, or when the name is a
// private field, otherwise JSProxy has to be handled via a trap.
// Adding properties to primitive values is not observable.
void LookupIterator::PrepareTransitionToDataProperty(
    Handle<JSReceiver> receiver, DirectHandle<Object> value,
    PropertyAttributes attributes, StoreOrigin store_origin) {
  DCHECK_IMPLIES(IsJSProxy(*receiver, isolate_), name()->IsPrivate());
  DCHECK_IMPLIES(!receiver.is_identical_to(GetStoreTarget<JSReceiver>()),
                 name()->IsPrivateName());
  DCHECK(!IsAlwaysSharedSpaceJSObject(*receiver));
  if (state_ == TRANSITION) return;

  if (!IsElement() && name()->IsPrivate()) {
    attributes = static_cast<PropertyAttributes>(attributes | DONT_ENUM);
  }

  DCHECK(state_ != LookupIterator::ACCESSOR ||
         IsAccessorInfo(*GetAccessors(), isolate_));
  DCHECK_NE(TYPED_ARRAY_INDEX_NOT_FOUND, state_);
  DCHECK(state_ == NOT_FOUND || !HolderIsReceiverOrHiddenPrototype());

  Handle<Map> map(receiver->map(isolate_), isolate_);

  // Dictionary maps can always have additional data properties.
  if (map->is_dictionary_map()) {
    state_ = TRANSITION;
    if (IsJSGlobalObjectMap(*map)) {
      DCHECK(!IsTheHole(*value, isolate_));
      // Don't set enumeration index (it will be set during value store).
      property_details_ =
          PropertyDetails(PropertyKind::kData, attributes,
                          PropertyCell::InitialType(isolate_, *value));
      transition_ = isolate_->factory()->NewPropertyCell(
          name(), property_details_, value);
      has_property_ = true;
    } else {
      // Don't set enumeration index (it will be set during value store).
      property_details_ =
          PropertyDetails(PropertyKind::kData, attributes,
                          PropertyDetails::kConstIfDictConstnessTracking);
      transition_ = map;
    }
    return;
  }

  Handle<Map> transition =
      Map::TransitionToDataProperty(isolate_, map, name_, value, attributes,
                                    PropertyConstness::kConst, store_origin);
  state_ = TRANSITION;
  transition_ = transition;

  if (transition->is_dictionary_map()) {
    DCHECK(!IsJSGlobalObjectMap(*transition));
    // Don't set enumeration index (it will be set during value store).
    property_details_ =
        PropertyDetails(PropertyKind::kData, attributes,
                        PropertyDetails::kConstIfDictConstnessTracking);
  } else {
    property_details_ = transition->GetLastDescriptorDetails(isolate_);
    has_property_ = true;
  }
}

void LookupIterator::ApplyTransitionToDataProperty(
    Handle<JSReceiver> receiver) {
  DCHECK_EQ(TRANSITION, state_);

  DCHECK_IMPLIES(!receiver.is_identical_to(GetStoreTarget<JSReceiver>()),
                 name()->IsPrivateName());
  holder_ = receiver;
  if (IsJSGlobalObject(*receiver, isolate_)) {
    JSObject::InvalidatePrototypeChains(receiver->map(isolate_));

    // Install a property cell.
    auto global = Cast<JSGlobalObject>(receiver);
    DCHECK(!global->HasFastProperties());
    Handle<GlobalDictionary> dictionary(
        global->global_dictionary(isolate_, kAcquireLoad), isolate_);

    dictionary =
        GlobalDictionary::Add(isolate_, dictionary, name(), transition_cell(),
                              property_details_, &number_);
    global->set_global_dictionary(*dictionary, kReleaseStore);

    // Reload details containing proper enumeration index value.
    property_details_ = transition_cell()->property_details();
    has_property_ = true;
    state_ = DATA;
    return;
  }
  DirectHandle<Map> transition = transition_map();
  bool simple_transition =
      transition->GetBackPointer(isolate_) == receiver->map(isolate_);

  if (configuration_ == DEFAULT && !transition->is_dictionary_map() &&
      !transition->IsPrototypeValidityCellValid()) {
    // Only LookupIterator instances with DEFAULT (full prototype chain)
    // configuration can produce valid transition handler maps.
    DirectHandle<UnionOf<Smi, Cell>> validity_cell =
        Map::GetOrCreatePrototypeChainValidityCell(transition, isolate());
    transition->set_prototype_validity_cell(*validity_cell, kRelaxedStore);
  }

  if (!IsJSProxy(*receiver, isolate_)) {
    JSObject::MigrateToMap(isolate_, Cast<JSObject>(receiver), transition);
  }

  if (simple_transition) {
    number_ = transition->LastAdded();
    property_details_ = transition->GetLastDescriptorDetails(isolate_);
    state_ = DATA;
  } else if (receiver->map(isolate_)->is_dictionary_map()) {
    if (receiver->map(isolate_)->is_prototype_map() &&
        IsJSObject(*receiver, isolate_)) {
      JSObject::InvalidatePrototypeChains(receiver->map(isolate_));
    }
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          receiver->property_dictionary_swiss(isolate_), isolate_);

      dictionary =
          SwissNameDictionary::Add(isolate(), dictionary, name(),
                                   isolate_->factory()->uninitialized_value(),
                                   property_details_, &number_);
      receiver->SetProperties(*dictionary);
    } else {
      Handle<NameDictionary> dictionary(receiver->property_dictionary(isolate_),
                                        isolate_);

      dictionary =
          NameDictionary::Add(isolate(), dictionary, name(),
                              isolate_->factory()->uninitialized_value(),
                              property_details_, &number_);
      receiver->SetProperties(*dictionary);
      // TODO(pthier): Add flags to swiss dictionaries.
      if (name()->IsInteresting(isolate())) {
        dictionary->set_may_have_interesting_properties(true);
      }
      // Reload details containing proper enumeration index value.
      property_details_ = dictionary->DetailsAt(number_);
    }
    has_property_ = true;
    state_ = DATA;

  } else {
    ReloadPropertyInformation<false>();
  }
}

void LookupIterator::Delete() {
  Handle<JSReceiver> holder = Cast<JSReceiver>(holder_);
  if (IsElement(*holder)) {
    Handle<JSObject> object = Cast<JSObject>(holder);
    ElementsAccessor* accessor = object->GetElementsAccessor(isolate_);
    accessor->Delete(object, nu
"""


```