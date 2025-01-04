Response: The user wants me to summarize the functionality of the C++ code provided in `v8/src/objects/lookup.cc`. This is the first part of a two-part file. Since this is part 1, I should focus on the functions defined within this snippet. The code seems to deal with property lookup in JavaScript objects within the V8 engine. It involves iterating through the prototype chain and handling different property types (data, accessor, etc.) and storage mechanisms (fast properties, dictionaries, elements arrays).

Here's a breakdown of the key classes and methods observed:

- **`PropertyKey`**:  Represents a property key, which can be either a string or an integer index.
- **`LookupIterator`**: The core class for property lookup. It maintains state as it iterates through the object's properties and its prototype chain.
    - `Start()`: Initializes the lookup process.
    - `Next()`: Moves to the next property in the lookup.
    - `NextInternal()`: Internal implementation for moving to the next holder in the prototype chain.
    - `RestartInternal()`: Restarts the lookup process.
    - `RecheckTypedArrayBounds()`:  Specifically handles bounds checking for TypedArrays.
    - `GetRootForNonJSReceiver()`: Handles property lookup on non-JSReceiver objects like strings.
    - `GetReceiverMap()`: Retrieves the map of the receiver object.
    - `HasAccess()`: Checks access permissions.
    - `ReloadPropertyInformation()`: Refreshes property information.
    - `InternalUpdateProtector()`: Manages the invalidation of V8's protector mechanisms based on property modifications.
    - `PrepareForDataProperty()`: Prepares an object to store a data property.
    - `ReconfigureDataProperty()`:  Changes the attributes of an existing data property.
    - `PrepareTransitionToDataProperty()`: Prepares for the addition of a new data property.
    - `ApplyTransitionToDataProperty()`:  Completes the addition of a new data property.
    - `Delete()`: Deletes a property.
    - `TransitionToAccessorProperty()`: Converts a property to an accessor.
    - `TransitionToAccessorPair()`:  Specifically handles setting an accessor pair.
    - `HolderIsReceiver()`: Checks if the current holder is the original receiver.
    - `HolderIsReceiverOrHiddenPrototype()`: Checks if the current holder is the receiver or its hidden prototype.
    - `FetchValue()`: Retrieves the value of a property.
    - `CanStayConst()`: Checks if a constant property can retain its constant nature after a value change.
    - `DictCanStayConst()`:  Similar to `CanStayConst` but for dictionary properties.
    - `GetFieldDescriptorIndex()`, `GetAccessorIndex()`, `GetFieldIndex()`, `GetPropertyCell()`, `GetAccessors()`, `GetDataValue()`: Accessors for property information.
    - `WriteDataValue()`: Sets the value of a data property.
    - `SwapDataValue()`, `CompareAndSwapDataValue()`: Atomic operations for shared memory.
    - `SkipInterceptor()`:  Determines if an interceptor should be skipped.
    - `NextHolder()`:  Gets the next object in the prototype chain.
    - `NotFound()`:  Determines the appropriate "not found" state.
    - `LookupInSpecialHolder()`: Handles property lookup in special object types.
    - `LookupInRegularHolder()`:  Handles property lookup in regular objects.
    - `HasInternalMarkerProperty()`: Checks for internal marker properties.
    - `GetInterceptorForFailedAccessCheck()`: Retrieves the interceptor for failed access checks.
    - `TryLookupCachedProperty()`: Attempts to use cached property information.
- **`ConcurrentLookupIterator`**: A specialized iterator for concurrent property access.

Based on this analysis, I can formulate a functional summary. For the JavaScript example, I'll demonstrate how property access triggers the underlying lookup mechanism.
这个C++源代码文件（`v8/src/objects/lookup.cc`）是V8 JavaScript引擎的一部分，主要负责**实现JavaScript对象的属性查找机制**。它提供了在JavaScript对象及其原型链上查找属性的功能，并管理查找过程中的各种状态和细节。

更具体地说，这个文件的功能可以归纳为：

1. **定义了用于表示属性键的 `PropertyKey` 类**:  该类可以表示字符串类型的属性名或整数索引类型的属性名。
2. **定义了核心的 `LookupIterator` 类**: 这个类是实现属性查找的关键，它提供了一系列方法来：
    - **启动属性查找 (`Start`)**:  根据起始对象和属性键开始查找过程。
    - **在原型链上移动 (`Next`, `NextInternal`)**: 迭代对象的原型链，逐个检查对象是否拥有目标属性。
    - **处理不同类型的对象和属性**:  包括普通对象、数组、字符串对象等，以及数据属性、访问器属性、索引属性等。
    - **处理访问控制 (`HasAccess`)**: 检查是否允许访问某个属性。
    - **处理拦截器 (`SkipInterceptor`)**:  在查找过程中考虑对象上可能存在的拦截器。
    - **获取属性的各种信息**:  例如属性的值 (`FetchValue`, `GetDataValue`)，属性的描述符信息（`property_details_`）。
    - **修改属性**:  例如准备存储数据属性 (`PrepareForDataProperty`)，重新配置数据属性 (`ReconfigureDataProperty`)，添加新的数据属性 (`PrepareTransitionToDataProperty`, `ApplyTransitionToDataProperty`)，删除属性 (`Delete`)，以及将属性转换为访问器 (`TransitionToAccessorProperty`, `TransitionToAccessorPair`)。
    - **处理属性的常量性 (`CanStayConst`, `DictCanStayConst`)**:  确定一个常量属性是否可以保持其常量性。
    - **管理查找状态**:  例如属性是否找到 (`IsFound`)，当前查找所处的状态 (`state_`)。
    - **处理TypedArray**:  包含针对TypedArray的特殊处理，例如边界检查 (`RecheckTypedArrayBounds`)。
    - **处理原型链保护机制 (`InternalUpdateProtector`)**:  当某些关键属性被修改时，会触发V8的保护机制失效，以保证优化的正确性。
3. **定义了用于并发查找的 `ConcurrentLookupIterator` 类**: 提供了在并发场景下安全地查找属性的能力。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`LookupIterator` 类在 V8 引擎内部被广泛使用，当 JavaScript 代码尝试访问对象的属性时，V8 会使用类似 `LookupIterator` 的机制来找到该属性。

以下是一些 JavaScript 示例，说明了 `LookupIterator` 在幕后是如何工作的：

**示例 1: 访问对象自身的属性**

```javascript
const obj = { a: 1 };
console.log(obj.a); // JavaScript 引擎会使用 LookupIterator 在 obj 对象自身查找属性 'a'
```

在这个例子中，当 JavaScript 引擎执行 `obj.a` 时，`LookupIterator` 会在 `obj` 对象自身的属性中查找名为 `a` 的属性，并返回其值 `1`。

**示例 2: 访问原型链上的属性**

```javascript
function Parent() {
  this.b = 2;
}
Parent.prototype.c = 3;

const child = new Parent();
console.log(child.c); // JavaScript 引擎会使用 LookupIterator 先在 child 对象自身查找，未找到，然后在 Parent.prototype 上查找
```

在这个例子中，当执行 `child.c` 时，`LookupIterator` 首先会在 `child` 对象自身查找属性 `c`，由于 `child` 对象没有 `c` 属性，`LookupIterator` 会沿着原型链向上查找，最终在 `Parent.prototype` 上找到 `c` 属性，并返回其值 `3`。

**示例 3: 设置对象的属性**

```javascript
const obj = {};
obj.d = 4; // JavaScript 引擎可能会使用 LookupIterator (或者相关机制) 来确定如何存储属性 'd'
```

当执行 `obj.d = 4` 时，V8 引擎可能使用类似于 `LookupIterator` 中的 `PrepareTransitionToDataProperty` 和 `ApplyTransitionToDataProperty` 等方法，来决定如何在 `obj` 对象上存储新的数据属性 `d`。这可能涉及到对象形状的改变 (Map 的更新) 等内部操作。

**示例 4: 使用访问器属性**

```javascript
const obj = {
  _e: 5,
  get e() {
    return this._e;
  },
  set e(value) {
    this._e = value;
  }
};
console.log(obj.e); // JavaScript 引擎使用 LookupIterator 找到 'e' 的访问器，并调用 getter
obj.e = 6;         // JavaScript 引擎使用 LookupIterator 找到 'e' 的访问器，并调用 setter
```

当访问 `obj.e` 或设置 `obj.e` 时，`LookupIterator` 会找到 `e` 属性对应的访问器（getter 和 setter），并根据操作类型调用相应的函数。

总而言之，`v8/src/objects/lookup.cc` 中的 `LookupIterator` 类是 V8 引擎实现 JavaScript 属性访问和操作的核心组件，它在幕后默默地工作，确保 JavaScript 代码能够正确地访问和修改对象的属性。

Prompt: 
```
这是目录为v8/src/objects/lookup.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
    accessor->Delete(object, number_);
  } else {
    DCHECK(!name()->IsPrivateName());
    bool is_prototype_map = holder->map(isolate_)->is_prototype_map();
    RCS_SCOPE(isolate_,
              is_prototype_map
                  ? RuntimeCallCounterId::kPrototypeObject_DeleteProperty
                  : RuntimeCallCounterId::kObject_DeleteProperty);

    PropertyNormalizationMode mode =
        is_prototype_map ? KEEP_INOBJECT_PROPERTIES : CLEAR_INOBJECT_PROPERTIES;

    if (holder->HasFastProperties(isolate_)) {
      JSObject::NormalizeProperties(isolate_, Cast<JSObject>(holder), mode, 0,
                                    "DeletingProperty");
      ReloadPropertyInformation<false>();
    }
    JSReceiver::DeleteNormalizedProperty(holder, dictionary_entry());
    if (IsJSObject(*holder, isolate_)) {
      JSObject::ReoptimizeIfPrototype(Cast<JSObject>(holder));
    }
  }
  state_ = NOT_FOUND;
}

void LookupIterator::TransitionToAccessorProperty(
    DirectHandle<Object> getter, DirectHandle<Object> setter,
    PropertyAttributes attributes) {
  DCHECK(!IsNull(*getter, isolate_) || !IsNull(*setter, isolate_));
  // Can only be called when the receiver is a JSObject. JSProxy has to be
  // handled via a trap. Adding properties to primitive values is not
  // observable.
  Handle<JSObject> receiver = GetStoreTarget<JSObject>();
  if (!IsElement() && name()->IsPrivate()) {
    attributes = static_cast<PropertyAttributes>(attributes | DONT_ENUM);
  }

  if (!IsElement(*receiver) && !receiver->map(isolate_)->is_dictionary_map()) {
    Handle<Map> old_map(receiver->map(isolate_), isolate_);

    if (!holder_.is_identical_to(receiver)) {
      holder_ = receiver;
      state_ = NOT_FOUND;
    } else if (state_ == INTERCEPTOR) {
      LookupInRegularHolder<false>(*old_map, *holder_);
    }
    // The case of IsFound() && number_.is_not_found() can occur for
    // interceptors.
    DCHECK_IMPLIES(!IsFound(), number_.is_not_found());

    DirectHandle<Map> new_map = Map::TransitionToAccessorProperty(
        isolate_, old_map, name_, number_, getter, setter, attributes);
    bool simple_transition =
        new_map->GetBackPointer(isolate_) == receiver->map(isolate_);
    JSObject::MigrateToMap(isolate_, receiver, new_map);

    if (simple_transition) {
      number_ = new_map->LastAdded();
      property_details_ = new_map->GetLastDescriptorDetails(isolate_);
      state_ = ACCESSOR;
      return;
    }

    ReloadPropertyInformation<false>();
    if (!new_map->is_dictionary_map()) return;
  }

  Handle<AccessorPair> pair;
  if (state() == ACCESSOR && IsAccessorPair(*GetAccessors(), isolate_)) {
    pair = Cast<AccessorPair>(GetAccessors());
    // If the component and attributes are identical, nothing has to be done.
    if (pair->Equals(*getter, *setter)) {
      if (property_details().attributes() == attributes) {
        if (!IsElement(*receiver)) JSObject::ReoptimizeIfPrototype(receiver);
        return;
      }
    } else {
      pair = AccessorPair::Copy(isolate(), pair);
      pair->SetComponents(*getter, *setter);
    }
  } else {
    pair = factory()->NewAccessorPair();
    pair->SetComponents(*getter, *setter);
  }

  TransitionToAccessorPair(pair, attributes);

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->JSObjectVerify(isolate());
  }
#endif
}

void LookupIterator::TransitionToAccessorPair(Handle<Object> pair,
                                              PropertyAttributes attributes) {
  Handle<JSObject> receiver = GetStoreTarget<JSObject>();
  holder_ = receiver;

  PropertyDetails details(PropertyKind::kAccessor, attributes,
                          PropertyCellType::kMutable);

  if (IsElement(*receiver)) {
    // TODO(verwaest): Move code into the element accessor.
    isolate_->CountUsage(v8::Isolate::kIndexAccessor);
    Handle<NumberDictionary> dictionary = JSObject::NormalizeElements(receiver);

    dictionary = NumberDictionary::Set(isolate_, dictionary, array_index(),
                                       pair, receiver, details);
    receiver->RequireSlowElements(*dictionary);

    if (receiver->HasSlowArgumentsElements(isolate_)) {
      Tagged<SloppyArgumentsElements> parameter_map =
          Cast<SloppyArgumentsElements>(receiver->elements(isolate_));
      uint32_t length = parameter_map->length();
      if (number_.is_found() && number_.as_uint32() < length) {
        parameter_map->set_mapped_entries(
            number_.as_int(), ReadOnlyRoots(isolate_).the_hole_value());
      }
      parameter_map->set_arguments(*dictionary);
    } else {
      receiver->set_elements(*dictionary);
    }

    ReloadPropertyInformation<true>();
  } else {
    PropertyNormalizationMode mode = CLEAR_INOBJECT_PROPERTIES;
    if (receiver->map(isolate_)->is_prototype_map()) {
      JSObject::InvalidatePrototypeChains(receiver->map(isolate_));
      mode = KEEP_INOBJECT_PROPERTIES;
    }

    // Normalize object to make this operation simple.
    JSObject::NormalizeProperties(isolate_, receiver, mode, 0,
                                  "TransitionToAccessorPair");

    JSObject::SetNormalizedProperty(receiver, name_, pair, details);
    JSObject::ReoptimizeIfPrototype(receiver);

    ReloadPropertyInformation<false>();
  }
}

bool LookupIterator::HolderIsReceiver() const {
  DCHECK(has_property_ || state_ == INTERCEPTOR || state_ == JSPROXY);
  // Optimization that only works if configuration_ is not mutable.
  if (!check_prototype_chain()) return true;
  return *receiver_ == *holder_;
}

bool LookupIterator::HolderIsReceiverOrHiddenPrototype() const {
  DCHECK(has_property_ || state_ == INTERCEPTOR || state_ == JSPROXY);
  // Optimization that only works if configuration_ is not mutable.
  if (!check_prototype_chain()) return true;
  if (*receiver_ == *holder_) return true;
  if (!IsJSGlobalProxy(*receiver_, isolate_)) return false;
  return Cast<JSGlobalProxy>(receiver_)->map(isolate_)->prototype(isolate_) ==
         *holder_;
}

Handle<Object> LookupIterator::FetchValue(
    AllocationPolicy allocation_policy) const {
  Tagged<Object> result;
  DCHECK(!IsWasmObject(*holder_));
  if (IsElement(*holder_)) {
    Handle<JSObject> holder = GetHolder<JSObject>();
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->Get(isolate_, holder, number_);
  } else if (IsJSGlobalObject(*holder_, isolate_)) {
    DirectHandle<JSGlobalObject> holder = GetHolder<JSGlobalObject>();
    result = holder->global_dictionary(isolate_, kAcquireLoad)
                 ->ValueAt(isolate_, dictionary_entry());
  } else if (!holder_->HasFastProperties(isolate_)) {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      result = holder_->property_dictionary_swiss(isolate_)->ValueAt(
          dictionary_entry());
    } else {
      result = holder_->property_dictionary(isolate_)->ValueAt(
          isolate_, dictionary_entry());
    }
  } else if (property_details_.location() == PropertyLocation::kField) {
    DCHECK_EQ(PropertyKind::kData, property_details_.kind());
    DirectHandle<JSObject> holder = GetHolder<JSObject>();
    FieldIndex field_index =
        FieldIndex::ForDetails(holder->map(isolate_), property_details_);
    if (allocation_policy == AllocationPolicy::kAllocationDisallowed &&
        field_index.is_inobject() && field_index.is_double()) {
      return isolate_->factory()->undefined_value();
    }
    return JSObject::FastPropertyAt(
        isolate_, holder, property_details_.representation(), field_index);
  } else {
    result =
        holder_->map(isolate_)->instance_descriptors(isolate_)->GetStrongValue(
            isolate_, descriptor_number());
  }
  return handle(result, isolate_);
}

bool LookupIterator::CanStayConst(Tagged<Object> value) const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());
  if (IsUninitialized(value, isolate())) {
    // Storing uninitialized value means that we are preparing for a computed
    // property value in an object literal. The initializing store will follow
    // and it will properly update constness based on the actual value.
    return true;
  }
  DirectHandle<JSObject> holder = GetHolder<JSObject>();
  FieldIndex field_index =
      FieldIndex::ForDetails(holder->map(isolate_), property_details_);
  if (property_details_.representation().IsDouble()) {
    if (!IsNumber(value, isolate_)) return false;
    uint64_t bits;
    Tagged<Object> current_value =
        holder->RawFastPropertyAt(isolate_, field_index);
    DCHECK(IsHeapNumber(current_value, isolate_));
    bits = Cast<HeapNumber>(current_value)->value_as_bits();
    // Use bit representation of double to check for hole double, since
    // manipulating the signaling NaN used for the hole in C++, e.g. with
    // base::bit_cast or value(), will change its value on ia32 (the x87
    // stack is used to return values and stores to the stack silently clear the
    // signalling bit).
    // Only allow initializing stores to double to stay constant.
    return bits == kHoleNanInt64;
  }

  Tagged<Object> current_value =
      holder->RawFastPropertyAt(isolate_, field_index);
  return IsUninitialized(current_value, isolate());
}

bool LookupIterator::DictCanStayConst(Tagged<Object> value) const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DCHECK(!holder_->HasFastProperties(isolate_));
  DCHECK(!IsJSGlobalObject(*holder_));
  DCHECK(!IsJSProxy(*holder_));
  DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());

  DisallowHeapAllocation no_gc;

  if (IsUninitialized(value, isolate())) {
    // Storing uninitialized value means that we are preparing for a computed
    // property value in an object literal. The initializing store will follow
    // and it will properly update constness based on the actual value.
    return true;
  }
  DirectHandle<JSReceiver> holder = GetHolder<JSReceiver>();
  Tagged<Object> current_value;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = holder->property_dictionary_swiss();
    current_value = dict->ValueAt(dictionary_entry());
  } else {
    Tagged<NameDictionary> dict = holder->property_dictionary();
    current_value = dict->ValueAt(dictionary_entry());
  }

  return IsUninitialized(current_value, isolate());
}

int LookupIterator::GetFieldDescriptorIndex() const {
  DCHECK(has_property_);
  DCHECK(holder_->HasFastProperties());
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  // TODO(jkummerow): Propagate InternalIndex further.
  return descriptor_number().as_int();
}

int LookupIterator::GetAccessorIndex() const {
  DCHECK(has_property_);
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kDescriptor, property_details_.location());
  DCHECK_EQ(PropertyKind::kAccessor, property_details_.kind());
  return descriptor_number().as_int();
}

FieldIndex LookupIterator::GetFieldIndex() const {
  DCHECK(has_property_);
  DCHECK(!holder_.is_null());
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK(!IsElement(*holder_));
  return FieldIndex::ForDetails(holder_->map(isolate_), property_details_);
}

Handle<PropertyCell> LookupIterator::GetPropertyCell() const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DirectHandle<JSGlobalObject> holder = GetHolder<JSGlobalObject>();
  return handle(holder->global_dictionary(isolate_, kAcquireLoad)
                    ->CellAt(isolate_, dictionary_entry()),
                isolate_);
}

Handle<Object> LookupIterator::GetAccessors() const {
  DCHECK_EQ(ACCESSOR, state_);
  return FetchValue();
}

Handle<Object> LookupIterator::GetDataValue(
    AllocationPolicy allocation_policy) const {
  DCHECK_EQ(DATA, state_);
  Handle<Object> value = FetchValue(allocation_policy);
  return value;
}

Handle<Object> LookupIterator::GetDataValue(SeqCstAccessTag tag) const {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->GetAtomic(isolate_, holder, number_, kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  FieldIndex field_index =
      FieldIndex::ForDetails(holder->map(isolate_), property_details_);
  return JSObject::FastPropertyAt(
      isolate_, holder, property_details_.representation(), field_index, tag);
}

void LookupIterator::WriteDataValue(DirectHandle<Object> value,
                                    bool initializing_store) {
  DCHECK_EQ(DATA, state_);
  // WriteDataValueToWasmObject() must be used instead for writing to
  // WasmObjects.
  DCHECK(!IsWasmObject(*holder_, isolate_));
  DCHECK_IMPLIES(IsJSSharedStruct(*holder_), IsShared(*value));

  Handle<JSReceiver> holder = GetHolder<JSReceiver>();
  if (IsElement(*holder)) {
    Handle<JSObject> object = Cast<JSObject>(holder);
    ElementsAccessor* accessor = object->GetElementsAccessor(isolate_);
    accessor->Set(object, number_, *value);
  } else if (holder->HasFastProperties(isolate_)) {
    DCHECK(IsJSObject(*holder, isolate_));
    if (property_details_.location() == PropertyLocation::kField) {
      // Check that in case of VariableMode::kConst field the existing value is
      // equal to |value|.
      DCHECK_IMPLIES(!initializing_store && property_details_.constness() ==
                                                PropertyConstness::kConst,
                     CanStayConst(*value));
      Cast<JSObject>(*holder)->WriteToField(descriptor_number(),
                                            property_details_, *value);
    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, property_details_.location());
      DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());
    }
  } else if (IsJSGlobalObject(*holder, isolate_)) {
    // PropertyCell::PrepareForAndSetValue already wrote the value into the
    // cell.
#ifdef DEBUG
    Tagged<GlobalDictionary> dictionary =
        Cast<JSGlobalObject>(*holder)->global_dictionary(isolate_,
                                                         kAcquireLoad);
    Tagged<PropertyCell> cell =
        dictionary->CellAt(isolate_, dictionary_entry());
    DCHECK(cell->value() == *value ||
           (IsString(cell->value()) && IsString(*value) &&
            Cast<String>(cell->value())->Equals(Cast<String>(*value))));
#endif  // DEBUG
  } else {
    DCHECK_IMPLIES(IsJSProxy(*holder, isolate_), name()->IsPrivate());
    // Check similar to fast mode case above.
    DCHECK_IMPLIES(
        V8_DICT_PROPERTY_CONST_TRACKING_BOOL && !initializing_store &&
            property_details_.constness() == PropertyConstness::kConst,
        IsJSProxy(*holder, isolate_) || DictCanStayConst(*value));

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dictionary =
          holder->property_dictionary_swiss(isolate_);
      dictionary->ValueAtPut(dictionary_entry(), *value);
    } else {
      Tagged<NameDictionary> dictionary = holder->property_dictionary(isolate_);
      dictionary->ValueAtPut(dictionary_entry(), *value);
    }
  }
}

void LookupIterator::WriteDataValue(DirectHandle<Object> value,
                                    SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    accessor->SetAtomic(holder, number_, *value, kSeqCstAccess);
    return;
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  DisallowGarbageCollection no_gc;
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  holder->FastPropertyAtPut(field_index, *value, tag);
}

Handle<Object> LookupIterator::SwapDataValue(DirectHandle<Object> value,
                                             SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->SwapAtomic(isolate_, holder, number_, *value,
                                kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  DisallowGarbageCollection no_gc;
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  return handle(holder->RawFastPropertyAtSwap(field_index, *value, tag),
                isolate_);
}

Handle<Object> LookupIterator::CompareAndSwapDataValue(
    DirectHandle<Object> expected, DirectHandle<Object> value,
    SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  DisallowGarbageCollection no_gc;
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->CompareAndSwapAtomic(isolate_, holder, number_, *expected,
                                          *value, kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  return handle(holder->RawFastPropertyAtCompareAndSwap(field_index, *expected,
                                                        *value, tag),
                isolate_);
}

template <bool is_element>
bool LookupIterator::SkipInterceptor(Tagged<JSObject> holder) {
  Tagged<InterceptorInfo> info = GetInterceptor<is_element>(holder);
  if (!is_element && IsSymbol(*name_, isolate_) &&
      !info->can_intercept_symbols()) {
    return true;
  }
  if (info->non_masking()) {
    switch (interceptor_state_) {
      case InterceptorState::kUninitialized:
        interceptor_state_ = InterceptorState::kSkipNonMasking;
        [[fallthrough]];
      case InterceptorState::kSkipNonMasking:
        return true;
      case InterceptorState::kProcessNonMasking:
        return false;
    }
  }
  return interceptor_state_ == InterceptorState::kProcessNonMasking;
}

Tagged<JSReceiver> LookupIterator::NextHolder(Tagged<Map> map) {
  DisallowGarbageCollection no_gc;
  if (map->prototype(isolate_) == ReadOnlyRoots(isolate_).null_value()) {
    return JSReceiver();
  }
  if (!check_prototype_chain() && !IsJSGlobalProxyMap(map)) {
    return JSReceiver();
  }
  return Cast<JSReceiver>(map->prototype(isolate_));
}

LookupIterator::State LookupIterator::NotFound(
    Tagged<JSReceiver> const holder) const {
  if (!IsJSTypedArray(holder, isolate_)) return NOT_FOUND;
  if (IsElement()) return TYPED_ARRAY_INDEX_NOT_FOUND;
  if (!IsString(*name_, isolate_)) return NOT_FOUND;
  return IsSpecialIndex(Cast<String>(*name_)) ? TYPED_ARRAY_INDEX_NOT_FOUND
                                              : NOT_FOUND;
}

namespace {

template <bool is_element>
bool HasInterceptor(Tagged<Map> map, size_t index) {
  if (is_element) {
    if (index > JSObject::kMaxElementIndex) {
      // There is currently no way to install interceptors on an object with
      // typed array elements.
      DCHECK(!map->has_typed_array_or_rab_gsab_typed_array_elements());
      return map->has_named_interceptor();
    }
    return map->has_indexed_interceptor();
  } else {
    return map->has_named_interceptor();
  }
}

}  // namespace

template <bool is_element>
LookupIterator::State LookupIterator::LookupInSpecialHolder(
    Tagged<Map> const map, Tagged<JSReceiver> const holder) {
  static_assert(INTERCEPTOR == BEFORE_PROPERTY);
  switch (state_) {
    case NOT_FOUND:
      if (IsJSProxyMap(map)) {
        if (is_element || !name_->IsPrivate()) return JSPROXY;
      }
#if V8_ENABLE_WEBASSEMBLY
      if (IsWasmObjectMap(map)) return WASM_OBJECT;
#endif  // V8_ENABLE_WEBASSEMBLY
      if (map->is_access_check_needed()) {
        if (is_element || !name_->IsPrivate() || name_->IsPrivateName())
          return ACCESS_CHECK;
      }
      [[fallthrough]];
    case ACCESS_CHECK:
      if (check_interceptor() && HasInterceptor<is_element>(map, index_) &&
          !SkipInterceptor<is_element>(Cast<JSObject>(holder))) {
        if (is_element || !name_->IsPrivate()) return INTERCEPTOR;
      }
      [[fallthrough]];
    case INTERCEPTOR:
      if (IsJSGlobalObjectMap(map) && !is_js_array_element(is_element)) {
        Tagged<GlobalDictionary> dict =
            Cast<JSGlobalObject>(holder)->global_dictionary(isolate_,
                                                            kAcquireLoad);
        number_ = dict->FindEntry(isolate(), name_);
        if (number_.is_not_found()) return NOT_FOUND;
        Tagged<PropertyCell> cell = dict->CellAt(isolate_, number_);
        if (IsPropertyCellHole(cell->value(isolate_), isolate_)) {
          return NOT_FOUND;
        }
        property_details_ = cell->property_details();
        has_property_ = true;
        switch (property_details_.kind()) {
          case v8::internal::PropertyKind::kData:
            return DATA;
          case v8::internal::PropertyKind::kAccessor:
            return ACCESSOR;
        }
      }
      return LookupInRegularHolder<is_element>(map, holder);
    case ACCESSOR:
    case DATA:
      return NOT_FOUND;
    case TYPED_ARRAY_INDEX_NOT_FOUND:
    case JSPROXY:
    case WASM_OBJECT:
    case TRANSITION:
      UNREACHABLE();
  }
  UNREACHABLE();
}

template <bool is_element>
LookupIterator::State LookupIterator::LookupInRegularHolder(
    Tagged<Map> const map, Tagged<JSReceiver> const holder) {
  DisallowGarbageCollection no_gc;
  if (interceptor_state_ == InterceptorState::kProcessNonMasking) {
    return NOT_FOUND;
  }
  DCHECK(!IsWasmObject(holder, isolate_));
  if (is_element && IsElement(holder)) {
    Tagged<JSObject> js_object = Cast<JSObject>(holder);
    ElementsAccessor* accessor = js_object->GetElementsAccessor(isolate_);
    Tagged<FixedArrayBase> backing_store = js_object->elements(isolate_);
    number_ =
        accessor->GetEntryForIndex(isolate_, js_object, backing_store, index_);
    if (number_.is_not_found()) {
      return IsJSTypedArray(holder, isolate_) ? TYPED_ARRAY_INDEX_NOT_FOUND
                                              : NOT_FOUND;
    }
    property_details_ = accessor->GetDetails(js_object, number_);
    if (map->has_frozen_elements()) {
      property_details_ = property_details_.CopyAddAttributes(FROZEN);
    } else if (map->has_sealed_elements()) {
      property_details_ = property_details_.CopyAddAttributes(SEALED);
    }
  } else if (!map->is_dictionary_map()) {
    Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate_);
    number_ = descriptors->SearchWithCache(isolate_, *name_, map);
    if (number_.is_not_found()) return NotFound(holder);
    property_details_ = descriptors->GetDetails(number_);
  } else {
    DCHECK_IMPLIES(IsJSProxy(holder, isolate_), name()->IsPrivate());
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict =
          holder->property_dictionary_swiss(isolate_);
      number_ = dict->FindEntry(isolate(), *name_);
      if (number_.is_not_found()) return NotFound(holder);
      property_details_ = dict->DetailsAt(number_);
    } else {
      Tagged<NameDictionary> dict = holder->property_dictionary(isolate_);
      number_ = dict->FindEntry(isolate(), name_);
      if (number_.is_not_found()) return NotFound(holder);
      property_details_ = dict->DetailsAt(number_);
    }
  }
  has_property_ = true;
  switch (property_details_.kind()) {
    case v8::internal::PropertyKind::kData:
      return DATA;
    case v8::internal::PropertyKind::kAccessor:
      return ACCESSOR;
  }

  UNREACHABLE();
}

// This is a specialization of function LookupInRegularHolder above
// which is tailored to test whether an object has an internal marker
// property.
// static
bool LookupIterator::HasInternalMarkerProperty(Isolate* isolate,
                                               Tagged<JSReceiver> const holder,
                                               Handle<Symbol> const marker) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> map = holder->map(isolate);
  if (map->is_dictionary_map()) {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict =
          holder->property_dictionary_swiss(isolate);
      InternalIndex entry = dict->FindEntry(isolate, marker);
      return entry.is_found();
    } else {
      Tagged<NameDictionary> dict = holder->property_dictionary(isolate);
      InternalIndex entry = dict->FindEntry(isolate, marker);
      return entry.is_found();
    }
  } else {
    Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
    InternalIndex entry = descriptors->SearchWithCache(isolate, *marker, map);
    return entry.is_found();
  }
}

Handle<InterceptorInfo> LookupIterator::GetInterceptorForFailedAccessCheck()
    const {
  DCHECK_EQ(ACCESS_CHECK, state_);
  // Skip the interceptors for private
  if (IsPrivateName()) {
    return Handle<InterceptorInfo>();
  }

  DisallowGarbageCollection no_gc;
  Tagged<AccessCheckInfo> access_check_info =
      AccessCheckInfo::Get(isolate_, Cast<JSObject>(holder_));
  if (!access_check_info.is_null()) {
    // There is currently no way to create objects with typed array elements
    // and access checks.
    DCHECK(!holder_->map()->has_typed_array_or_rab_gsab_typed_array_elements());
    Tagged<Object> interceptor = is_js_array_element(IsElement())
                                     ? access_check_info->indexed_interceptor()
                                     : access_check_info->named_interceptor();
    if (interceptor != Tagged<Object>()) {
      return handle(Cast<InterceptorInfo>(interceptor), isolate_);
    }
  }
  return Handle<InterceptorInfo>();
}

bool LookupIterator::TryLookupCachedProperty(
    DirectHandle<AccessorPair> accessor) {
  DCHECK_EQ(state(), LookupIterator::ACCESSOR);
  return LookupCachedProperty(accessor);
}

bool LookupIterator::TryLookupCachedProperty() {
  if (state() != LookupIterator::ACCESSOR) return false;

  Handle<Object> accessor_pair = GetAccessors();
  return IsAccessorPair(*accessor_pair, isolate_) &&
         LookupCachedProperty(Cast<AccessorPair>(accessor_pair));
}

bool LookupIterator::LookupCachedProperty(
    DirectHandle<AccessorPair> accessor_pair) {
  if (!HolderIsReceiverOrHiddenPrototype()) return false;
  if (!lookup_start_object_.is_identical_to(receiver_) &&
      !lookup_start_object_.is_identical_to(holder_)) {
    return false;
  }

  DCHECK_EQ(state(), LookupIterator::ACCESSOR);
  DCHECK(IsAccessorPair(*GetAccessors(), isolate_));

  Tagged<Object> getter = accessor_pair->getter(isolate_);
  std::optional<Tagged<Name>> maybe_name =
      FunctionTemplateInfo::TryGetCachedPropertyName(isolate(), getter);
  if (!maybe_name.has_value()) return false;

  if (IsJSFunction(getter)) {
    // If the getter was a JSFunction there's no guarantee that the holder
    // actually has a property with the cached name. In that case look it up to
    // make sure.
    LookupIterator it(isolate_, holder_, handle(maybe_name.value(), isolate_));
    if (it.state() != DATA) return false;
    name_ = it.name();
  } else {
    name_ = handle(maybe_name.value(), isolate_);
  }

  // We have found a cached property! Modify the iterator accordingly.
  Restart();
  CHECK_EQ(state(), LookupIterator::DATA);
  return true;
}

// static
std::optional<Tagged<Object>> ConcurrentLookupIterator::TryGetOwnCowElement(
    Isolate* isolate, Tagged<FixedArray> array_elements,
    ElementsKind elements_kind, int array_length, size_t index) {
  DisallowGarbageCollection no_gc;

  CHECK_EQ(array_elements->map(), ReadOnlyRoots(isolate).fixed_cow_array_map());
  DCHECK(IsFastElementsKind(elements_kind) &&
         IsSmiOrObjectElementsKind(elements_kind));
  USE(elements_kind);
  DCHECK_GE(array_length, 0);

  //  ________________________________________
  // ( Check against both JSArray::length and )
  // ( FixedArray::length.                    )
  //  ----------------------------------------
  //         o   ^__^
  //          o  (oo)\_______
  //             (__)\       )\/\
  //                 ||----w |
  //                 ||     ||
  // The former is the source of truth, but due to concurrent reads it may not
  // match the given `array_elements`.
  if (index >= static_cast<size_t>(array_length)) return {};
  if (index >= static_cast<size_t>(array_elements->length())) return {};

  Tagged<Object> result = array_elements->get(static_cast<int>(index));

  //  ______________________________________
  // ( Filter out holes irrespective of the )
  // ( elements kind.                       )
  //  --------------------------------------
  //         o   ^__^
  //          o  (..)\_______
  //             (__)\       )\/\
  //                 ||----w |
  //                 ||     ||
  // The elements kind may not be consistent with the given elements backing
  // store.
  if (result == ReadOnlyRoots(isolate).the_hole_value()) return {};

  return result;
}

// static
ConcurrentLookupIterator::Result
ConcurrentLookupIterator::TryGetOwnConstantElement(
    Tagged<Object>* result_out, Isolate* isolate, LocalIsolate* local_isolate,
    Tagged<JSObject> holder, Tagged<FixedArrayBase> elements,
    ElementsKind elements_kind, size_t index) {
  DisallowGarbageCollection no_gc;

  DCHECK_LE(index, JSObject::kMaxElementIndex);

  // Own 'constant' elements (PropertyAttributes READ_ONLY|DONT_DELETE) occur in
  // three main cases:
  //
  // 1. Frozen elements: guaranteed constant.
  // 2. Dictionary elements: may be constant.
  // 3. String wrapper elements: guaranteed constant.

  // Interesting field reads below:
  //
  // - elements.length (immutable on FixedArrays).
  // - elements[i] (immutable if constant; be careful around dictionaries).
  // - holder.AsJSPrimitiveWrapper.value.AsString.length (immutable).
  // - holder.AsJSPrimitiveWrapper.value.AsString[i] (immutable).
  // - single_character_string_table()->get().

  if (IsFrozenElementsKind(elements_kind)) {
    if (!IsFixedArray(elements)) return kGaveUp;
    Tagged<FixedArray> elements_fixed_array = Cast<FixedArray>(elements);
    if (index >= static_cast<uint32_t>(elements_fixed_array->length())) {
      return kGaveUp;
    }
    Tagged<Object> result = elements_fixed_array->get(static_cast<int>(index));
    if (IsHoleyElementsKindForRead(elements_kind) &&
        result == ReadOnlyRoots(isolate).the_hole_value()) {
      return kNotPresent;
    }
    *result_out = result;
    return kPresent;
  } else if (IsDictionaryElementsKind(elements_kind)) {
    if (!IsNumberDictionary(elements)) return kGaveUp;
    // TODO(jgruber, v8:7790): Add support. Dictionary elements require racy
    // NumberDictionary lookups. This should be okay in general (slot iteration
    // depends only on the dict's capacity), but 1. we'd need to update
    // NumberDictionary methods to do atomic reads, and 2. the dictionary
    // elements case isn't very important for callers of this function.
    return kGaveUp;
  } else if (IsStringWrapperElementsKind(elements_kind)) {
    // In this case we don't care about the actual `elements`. All in-bounds
    // reads are redirected to the wrapped String.

    Tagged<JSPrimitiveWrapper> js_value = Cast<JSPrimitiveWrapper>(holder);
    Tagged<String> wrapped_string = Cast<String>(js_value->value());
    return ConcurrentLookupIterator::TryGetOwn
"""


```