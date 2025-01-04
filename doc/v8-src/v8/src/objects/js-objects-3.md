Response: The user wants to understand the functionality of the C++ code snippet from `v8/src/objects/js-objects.cc`. This is the fourth part of a larger file. I need to:

1. **Summarize the purpose of the code:** Analyze the provided functions and their interactions.
2. **Relate to JavaScript:** If applicable, explain how the C++ code relates to JavaScript features.
3. **Provide JavaScript examples:** Illustrate the connection with concrete JavaScript code.

Based on the code, here's a breakdown of the functionalities:

- **Prototype manipulation:** Functions like `ReoptimizeIfPrototype`, `LazyRegisterPrototypeUser`, `UnregisterPrototypeUser`, `InvalidatePrototypeChains`, and `SetPrototype` deal with the prototype chain mechanism in JavaScript.
- **Property handling:** Code related to constant property tracking and invalidation during prototype changes (`V8_DICT_PROPERTY_CONST_TRACKING_BOOL`).
- **Elements kind transitions:** Functions like `AddDataElement`, `TransitionElementsKind`, and related helper functions manage the internal representation of array elements (e.g., going from integer arrays to double arrays).
- **Property access with interceptors:** The function `GetPropertyWithInterceptor` handles property lookups involving interceptors.
- **Global object property invalidation:** `JSGlobalObject::InvalidatePropertyCell` is used when properties on the global object are modified.
- **`JSDate` object:** Functions for creating, getting, and setting date values. This includes handling timezones and caching.
- **`JSMessageObject`:** Functions for accessing information about error messages, such as line numbers and source code.

Now, let's map these to JavaScript and provide examples.
这个C++代码片段主要负责以下功能，并与JavaScript的原型继承、属性管理和数组元素存储方式等密切相关：

**1. 原型链优化与管理:**

*   **`ReoptimizeIfPrototype(DirectHandle<JSObject> object)`:**  当一个对象的 Map 被标记为可以优化为快速原型 Map 时，会触发优化。这与 JavaScript 中对象的原型链查找性能息息相关。V8 尝试将常用的原型对象优化成更快的表示形式。
*   **`LazyRegisterPrototypeUser(DirectHandle<Map> user, Isolate* isolate)`:**  当一个 Map 作为另一个对象的原型时，这个函数会延迟注册这个“用户”。这是原型链追踪的一部分，用于在原型对象发生变化时通知依赖它的对象。
*   **`UnregisterPrototypeUser(DirectHandle<Map> user, Isolate* isolate)`:**  当一个 Map 不再作为原型时，会取消注册，清理相关的依赖关系。
*   **`InvalidatePrototypeChains(Tagged<Map> map)`:**  当一个原型对象发生结构性变化（例如添加或删除属性）时，这个函数会使依赖于这个原型链的对象的优化失效，确保下次访问时能获取到最新的状态。
*   **`SetPrototype(Isolate* isolate, Handle<JSObject> object, Handle<Object> value_obj, bool from_javascript, ShouldThrow should_throw)`:**  实现了 JavaScript 中 `Object.setPrototypeOf()` 和 `__proto__` 设置原型的功能。它会检查各种约束条件，例如是否会形成原型链环，对象是否可扩展等，然后更新对象的原型。

**JavaScript 示例：原型链**

```javascript
const parent = {
  getValue() {
    return this.value;
  },
};

const child = {
  value: 10,
};

Object.setPrototypeOf(child, parent); // 对应 C++ 的 SetPrototype

console.log(child.getValue()); // JavaScript 引擎会沿着原型链向上查找 getValue 方法
```

**2. 属性常量跟踪:**

*   代码中出现的 `V8_DICT_PROPERTY_CONST_TRACKING_BOOL` 相关的逻辑表明 V8 能够跟踪字典模式对象中的常量属性。当一个对象的属性字典被确定后，它可以将这些属性标记为常量，从而在后续访问时进行优化。

**JavaScript 示例：常量属性（在 V8 内部优化）**

虽然 JavaScript 本身没有直接声明常量属性的方式（除了 `const` 声明的变量），但 V8 内部会对某些对象的属性进行常量优化。例如，内置对象的属性往往会被当作常量处理。

```javascript
const obj = {};
obj.x = 5; // 如果 obj 进入字典模式，且不再添加或修改 x，V8 可能将其优化为常量。

console.log(obj.x);
```

**3. 数组元素类型转换与优化:**

*   **`AddDataElement(Handle<JSObject> object, uint32_t index, DirectHandle<Object> value, PropertyAttributes attributes)`:**  负责向对象（特别是数组）添加元素。它会根据添加的元素的类型和对象的当前元素类型，决定是否需要进行元素类型的转换（例如从 SMI 数组转换为 DOUBLE 数组或 OBJECT 数组）。
*   **`TransitionElementsKind(Handle<JSObject> object, ElementsKind to_kind)`:**  显式地将对象的元素存储方式从一种类型转换为另一种类型。例如，当一个只包含整数的数组添加了一个浮点数时，V8 会将其内部表示从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_DOUBLE_ELEMENTS`。
*   代码中还涉及到 `EnsureCanContainElements`， `WouldConvertToSlowElements`， `ShouldConvertToFastElements` 和 `BestFittingFastElementsKind` 等函数，用于判断和优化数组的内部存储结构。

**JavaScript 示例：数组元素类型转换**

```javascript
const arr = [1, 2, 3]; // 初始可能是 PACKED_SMI_ELEMENTS

arr.push(3.14); // 触发元素类型转换，可能变为 PACKED_DOUBLE_ELEMENTS

arr.push({}); // 再次触发转换，可能变为 PACKED_ELEMENTS (存储对象的元素)
```

**4. 属性拦截器处理:**

*   **`GetPropertyWithInterceptor(LookupIterator* it, bool* done)`:**  当访问一个带有属性拦截器的对象的属性时，这个函数会被调用，负责执行拦截器的逻辑。

**JavaScript 示例：属性拦截器**

```javascript
const obj = {};
Object.defineProperty(obj, 'x', {
  get: function() {
    console.log('Getting x');
    return this._x;
  },
  set: function(value) {
    console.log('Setting x to', value);
    this._x = value;
  },
});

obj.x = 10; // 触发 set 拦截器
console.log(obj.x); // 触发 get 拦截器
```

**5. 全局对象属性失效:**

*   **`JSGlobalObject::InvalidatePropertyCell(DirectHandle<JSGlobalObject> global, Handle<Name> name)`:**  当全局对象的属性发生变化时，需要使相关的缓存失效，确保下次访问时能获取到最新的值。

**JavaScript 示例：全局对象**

```javascript
globalThis.myGlobalVar = 10;

console.log(myGlobalVar);

delete globalThis.myGlobalVar; // 这会触发全局对象属性的失效
```

**6. `JSDate` 对象操作:**

*   代码中包含了 `JSDate` 对象的创建、获取和设置时间值的方法，包括处理时区和缓存机制。

**JavaScript 示例：Date 对象**

```javascript
const now = new Date(); // 对应 C++ 的 JSDate::New
console.log(now.getFullYear()); // 对应 C++ 的 JSDate::GetField
now.setFullYear(2024); // 对应 C++ 中设置 Date 字段的操作
```

**7. `JSMessageObject` 对象操作:**

*   代码包含了获取错误信息，例如错误发生的行号、列号和源代码片段等功能。

**JavaScript 示例：错误信息**

```javascript
try {
  throw new Error('Something went wrong');
} catch (e) {
  console.log(e.lineNumber); // 对应 C++ 的 JSMessageObject::GetLineNumber
  console.log(e.columnNumber); // 对应 C++ 的 JSMessageObject::GetColumnNumber
  console.log(e.stack);
}
```

总而言之，这个代码片段是 V8 引擎中负责管理 JavaScript 对象的核心部分，它实现了原型继承、属性访问、数组优化以及错误处理等关键功能，保证了 JavaScript 代码的正确执行和性能。

Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
 } else {
          new_map->SetConstructor(object_function);
        }
      }
    }
    JSObject::MigrateToMap(isolate, object, new_map);

    if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && !object->HasFastProperties()) {
      ReadOnlyRoots roots(isolate);
      DisallowHeapAllocation no_gc;

      auto make_constant = [&](auto dict) {
        for (InternalIndex index : dict->IterateEntries()) {
          Tagged<Object> k;
          if (!dict->ToKey(roots, index, &k)) continue;

          PropertyDetails details = dict->DetailsAt(index);
          details = details.CopyWithConstness(PropertyConstness::kConst);
          dict->DetailsAtPut(index, details);
        }
      };
      if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        make_constant(object->property_dictionary_swiss());
      } else {
        make_constant(object->property_dictionary());
      }
    }
  }
#ifdef DEBUG
  bool should_be_dictionary = V8_DICT_PROPERTY_CONST_TRACKING_BOOL &&
                              enable_setup_mode && !IsJSGlobalProxy(*object) &&
                              !isolate->bootstrapper()->IsActive();
  DCHECK_IMPLIES(should_be_dictionary,
                 object->map(isolate)->is_dictionary_map());
#endif
}

// static
void JSObject::ReoptimizeIfPrototype(DirectHandle<JSObject> object) {
  {
    Tagged<Map> map = object->map();
    if (!map->is_prototype_map()) return;
    if (!map->should_be_fast_prototype_map()) return;
  }
  OptimizeAsPrototype(object);
}

// static
void JSObject::LazyRegisterPrototypeUser(DirectHandle<Map> user,
                                         Isolate* isolate) {
  // Contract: In line with InvalidatePrototypeChains()'s requirements,
  // leaf maps don't need to register as users, only prototypes do.
  DCHECK(user->is_prototype_map());

  DirectHandle<Map> current_user = user;
  DirectHandle<PrototypeInfo> current_user_info =
      Map::GetOrCreatePrototypeInfo(user, isolate);
  for (PrototypeIterator iter(isolate, user); !iter.IsAtEnd(); iter.Advance()) {
    // Walk up the prototype chain as far as links haven't been registered yet.
    if (current_user_info->registry_slot() != MemoryChunk::UNREGISTERED) {
      break;
    }
    Handle<Object> maybe_proto = PrototypeIterator::GetCurrent(iter);
    // This checks for both proxies and shared objects.
    //
    // Proxies on the prototype chain are not supported. They make it
    // impossible to make any assumptions about the prototype chain anyway.
    //
    // Objects in the shared heap have fixed layouts and their maps never
    // change, so they don't need to be tracked as prototypes
    // anyway. Additionally, registering users of shared objects is not
    // threadsafe.
    if (!IsJSObjectThatCanBeTrackedAsPrototype(*maybe_proto)) continue;
    auto proto = Cast<JSObject>(maybe_proto);
    DirectHandle<PrototypeInfo> proto_info =
        Map::GetOrCreatePrototypeInfo(proto, isolate);
    Handle<Object> maybe_registry(proto_info->prototype_users(), isolate);
    Handle<WeakArrayList> registry =
        IsSmi(*maybe_registry)
            ? handle(ReadOnlyRoots(isolate->heap()).empty_weak_array_list(),
                     isolate)
            : Cast<WeakArrayList>(maybe_registry);
    int slot = 0;
    Handle<WeakArrayList> new_array =
        PrototypeUsers::Add(isolate, registry, current_user, &slot);
    current_user_info->set_registry_slot(slot);
    if (!maybe_registry.is_identical_to(new_array)) {
      proto_info->set_prototype_users(*new_array);
    }
    if (v8_flags.trace_prototype_users) {
      PrintF("Registering %p as a user of prototype %p (map=%p).\n",
             reinterpret_cast<void*>(current_user->ptr()),
             reinterpret_cast<void*>(proto->ptr()),
             reinterpret_cast<void*>(proto->map().ptr()));
    }

    current_user = handle(proto->map(), isolate);
    current_user_info = proto_info;
  }
}

// Can be called regardless of whether |user| was actually registered with
// |prototype|. Returns true when there was a registration.
// static
bool JSObject::UnregisterPrototypeUser(DirectHandle<Map> user,
                                       Isolate* isolate) {
  DCHECK(user->is_prototype_map());
  // If it doesn't have a PrototypeInfo, it was never registered.
  if (!user->has_prototype_info()) return false;
  DCHECK(IsPrototypeInfo(user->prototype_info()));
  // If it had no prototype before, see if it had users that might expect
  // registration.
  if (!IsJSObject(user->prototype())) {
    Tagged<Object> users =
        Cast<PrototypeInfo>(user->prototype_info())->prototype_users();
    return IsWeakArrayList(users);
  }
  DirectHandle<JSObject> prototype(Cast<JSObject>(user->prototype()), isolate);
  DirectHandle<PrototypeInfo> user_info =
      Map::GetOrCreatePrototypeInfo(user, isolate);
  int slot = user_info->registry_slot();
  if (slot == MemoryChunk::UNREGISTERED) return false;
  DCHECK(prototype->map()->is_prototype_map());
  Tagged<Object> maybe_proto_info = prototype->map()->prototype_info();
  // User knows its registry slot, prototype info and user registry must exist.
  DCHECK(IsPrototypeInfo(maybe_proto_info));
  DirectHandle<PrototypeInfo> proto_info(Cast<PrototypeInfo>(maybe_proto_info),
                                         isolate);
  DirectHandle<WeakArrayList> prototype_users(
      Cast<WeakArrayList>(proto_info->prototype_users()), isolate);
  DCHECK_EQ(prototype_users->Get(slot), MakeWeak(*user));
  PrototypeUsers::MarkSlotEmpty(*prototype_users, slot);
  if (v8_flags.trace_prototype_users) {
    PrintF("Unregistering %p as a user of prototype %p.\n",
           reinterpret_cast<void*>(user->ptr()),
           reinterpret_cast<void*>(prototype->ptr()));
  }
  return true;
}

namespace {

// This function must be kept in sync with
// AccessorAssembler::InvalidateValidityCellIfPrototype() which does pre-checks
// before jumping here.
void InvalidateOnePrototypeValidityCellInternal(Tagged<Map> map) {
  DCHECK(map->is_prototype_map());
  if (v8_flags.trace_prototype_users) {
    PrintF("Invalidating prototype map %p 's cell\n",
           reinterpret_cast<void*>(map.ptr()));
  }
  Tagged<Object> maybe_cell = map->prototype_validity_cell(kRelaxedLoad);
  if (IsCell(maybe_cell)) {
    // Just set the value; the cell will be replaced lazily.
    Tagged<Cell> cell = Cast<Cell>(maybe_cell);
    Tagged<Smi> invalid_value = Smi::FromInt(Map::kPrototypeChainInvalid);
    if (cell->value() != invalid_value) {
      cell->set_value(invalid_value);
    }
  }
  Tagged<PrototypeInfo> prototype_info;
  if (map->TryGetPrototypeInfo(&prototype_info)) {
    prototype_info->set_prototype_chain_enum_cache(Smi::zero());
  }

  // We may inline accesses to constants stored in dictionary mode prototypes in
  // optimized code. When doing so, we install dependencies of group
  // |kPrototypeCheckGroup| on each prototype between the receiver's immediate
  // prototype and the holder of the constant property. This dependency is used
  // both to detect changes to the constant value itself, and other changes to
  // the prototype chain that invalidate the access to the given property from
  // the given receiver (like adding the property to another prototype between
  // the receiver and the (previous) holder). This works by de-opting this group
  // whenever the validity cell would be invalidated. However, the actual value
  // of the validity cell is not used. Therefore, we always trigger the de-opt
  // here, even if the cell was already invalid.
  if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && map->is_dictionary_map()) {
    // TODO(11527): pass Isolate as an argument.
    Isolate* isolate = GetIsolateFromWritableObject(map);
    DependentCode::DeoptimizeDependencyGroups(
        isolate, map, DependentCode::kPrototypeCheckGroup);
  }
}

void InvalidatePrototypeChainsInternal(Tagged<Map> map) {
  // We handle linear prototype chains by looping, and multiple children
  // by recursion, in order to reduce the likelihood of running into stack
  // overflows. So, conceptually, the outer loop iterates the depth of the
  // prototype tree, and the inner loop iterates the breadth of a node.
  Tagged<Map> next_map;
  for (; !map.is_null(); map = next_map, next_map = Map()) {
    InvalidateOnePrototypeValidityCellInternal(map);

    Tagged<PrototypeInfo> proto_info;
    if (!map->TryGetPrototypeInfo(&proto_info)) return;
    if (!IsWeakArrayList(proto_info->prototype_users())) {
      return;
    }
    Tagged<WeakArrayList> prototype_users =
        Cast<WeakArrayList>(proto_info->prototype_users());
    // For now, only maps register themselves as users.
    for (int i = PrototypeUsers::kFirstIndex; i < prototype_users->length();
         ++i) {
      Tagged<HeapObject> heap_object;
      if (prototype_users->Get(i).GetHeapObjectIfWeak(&heap_object) &&
          IsMap(heap_object)) {
        // Walk the prototype chain (backwards, towards leaf objects) if
        // necessary.
        if (next_map.is_null()) {
          next_map = Cast<Map>(heap_object);
        } else {
          InvalidatePrototypeChainsInternal(Cast<Map>(heap_object));
        }
      }
    }
  }
}

}  // namespace

// static
Tagged<Map> JSObject::InvalidatePrototypeChains(Tagged<Map> map) {
  DisallowGarbageCollection no_gc;
  InvalidatePrototypeChainsInternal(map);
  return map;
}

// We also invalidate global objects validity cell when a new lexical
// environment variable is added. This is necessary to ensure that
// Load/StoreGlobalIC handlers that load/store from global object's prototype
// get properly invalidated.
// Note, that the normal Load/StoreICs that load/store through the global object
// in the prototype chain are not affected by appearance of a new lexical
// variable and therefore we don't propagate invalidation down.
// static
void JSObject::InvalidatePrototypeValidityCell(Tagged<JSGlobalObject> global) {
  DisallowGarbageCollection no_gc;
  InvalidateOnePrototypeValidityCellInternal(global->map());
}

Maybe<bool> JSObject::SetPrototype(Isolate* isolate, Handle<JSObject> object,
                                   Handle<Object> value_obj,
                                   bool from_javascript,
                                   ShouldThrow should_throw) {
#ifdef DEBUG
  int size = object->Size();
#endif

  if (from_javascript) {
    if (IsAccessCheckNeeded(*object) &&
        !isolate->MayAccess(isolate->native_context(), object)) {
      RETURN_ON_EXCEPTION_VALUE(
          isolate, isolate->ReportFailedAccessCheck(object), Nothing<bool>());
      UNREACHABLE();
    }
  } else {
    DCHECK(!IsAccessCheckNeeded(*object));
  }

  // Silently ignore the change if value is not a JSReceiver or null.
  // SpiderMonkey behaves this way.
  Handle<JSPrototype> value;
  if (!TryCast(value_obj, &value)) return Just(true);

  bool all_extensible = object->map()->is_extensible();
  Handle<JSObject> real_receiver = object;
  if (from_javascript) {
    // Find the first object in the chain whose prototype object is not
    // hidden.
    PrototypeIterator iter(isolate, real_receiver, kStartAtPrototype,
                           PrototypeIterator::END_AT_NON_HIDDEN);
    while (!iter.IsAtEnd()) {
      // Casting to JSObject is fine because hidden prototypes are never
      // JSProxies.
      real_receiver = PrototypeIterator::GetCurrent<JSObject>(iter);
      iter.Advance();
      all_extensible = all_extensible && real_receiver->map()->is_extensible();
    }
  }
  Handle<Map> map(real_receiver->map(), isolate);

  // Nothing to do if prototype is already set.
  if (map->prototype() == *value) return Just(true);

  bool immutable_proto = map->is_immutable_proto();
  if (immutable_proto) {
    Handle<Object> msg;
    if (IsJSObjectPrototype(*object)) {  // is [[Object.prototype]]
      msg = isolate->factory()->Object_prototype_string();
    } else {
      msg = object;
    }
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kImmutablePrototypeSet, msg));
  }

  // From 6.1.7.3 Invariants of the Essential Internal Methods
  //
  // [[SetPrototypeOf]] ( V )
  // * ...
  // * If target is non-extensible, [[SetPrototypeOf]] must return false,
  //   unless V is the SameValue as the target's observed [[GetPrototypeOf]]
  //   value.
  if (!all_extensible) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kNonExtensibleProto, object));
  }

  // Before we can set the prototype we need to be sure prototype cycles are
  // prevented.  It is sufficient to validate that the receiver is not in the
  // new prototype chain.
  if (Tagged<JSReceiver> receiver; TryCast<JSReceiver>(*value, &receiver)) {
    for (PrototypeIterator iter(isolate, receiver, kStartAtReceiver);
         !iter.IsAtEnd(); iter.Advance()) {
      if (iter.GetCurrent<JSReceiver>() == *object) {
        // Cycle detected.
        RETURN_FAILURE(isolate, should_throw,
                       NewTypeError(MessageTemplate::kCyclicProto));
      }
    }
  }

  // Set the new prototype of the object.

  isolate->UpdateProtectorsOnSetPrototype(real_receiver, value);

  DirectHandle<Map> new_map =
      v8_flags.move_prototype_transitions_first
          ? MapUpdater(isolate, map).ApplyPrototypeTransition(value)
          : Map::TransitionToUpdatePrototype(isolate, map, value);

  DCHECK(new_map->prototype() == *value);
  JSObject::MigrateToMap(isolate, real_receiver, new_map);

  DCHECK_IMPLIES(!new_map->is_dictionary_map() && !map->is_deprecated() &&
                     !IsUndefined(new_map->GetBackPointer()),
                 size == object->Size());
  return Just(true);
}

// static
void JSObject::SetImmutableProto(Isolate* isolate,
                                 DirectHandle<JSObject> object) {
  Handle<Map> map(object->map(), isolate);

  // Nothing to do if prototype is already set.
  if (map->is_immutable_proto()) return;

  DirectHandle<Map> new_map = Map::TransitionToImmutableProto(isolate, map);
  object->set_map(isolate, *new_map, kReleaseStore);
}

void JSObject::EnsureCanContainElements(Handle<JSObject> object,
                                        JavaScriptArguments* args,
                                        uint32_t arg_count,
                                        EnsureElementsMode mode) {
  return EnsureCanContainElements(
      object, FullObjectSlot(args->address_of_arg_at(0)), arg_count, mode);
}

void JSObject::ValidateElements(Tagged<JSObject> object) {
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    object->GetElementsAccessor()->Validate(object);
  }
#endif
}

bool JSObject::WouldConvertToSlowElements(uint32_t index) {
  if (!HasFastElements()) return false;
  uint32_t capacity = static_cast<uint32_t>(elements()->length());
  uint32_t new_capacity;
  return ShouldConvertToSlowElements(*this, capacity, index, &new_capacity);
}

static bool ShouldConvertToFastElements(Tagged<JSObject> object,
                                        Tagged<NumberDictionary> dictionary,
                                        uint32_t index,
                                        uint32_t* new_capacity) {
  // If properties with non-standard attributes or accessors were added, we
  // cannot go back to fast elements.
  if (dictionary->requires_slow_elements()) return false;

  // Adding a property with this index will require slow elements.
  if (index >= static_cast<uint32_t>(Smi::kMaxValue)) return false;

  if (IsJSArray(object)) {
    Tagged<Object> length = Cast<JSArray>(object)->length();
    if (!IsSmi(length)) return false;
    *new_capacity = static_cast<uint32_t>(Smi::ToInt(length));
  } else if (IsJSArgumentsObject(object)) {
    return false;
  } else {
    *new_capacity = dictionary->max_number_key() + 1;
  }
  *new_capacity = std::max(index + 1, *new_capacity);

  uint32_t dictionary_size = static_cast<uint32_t>(dictionary->Capacity()) *
                             NumberDictionary::kEntrySize;

  // Turn fast if the dictionary only saves 50% space.
  return 2 * dictionary_size >= *new_capacity;
}

static ElementsKind BestFittingFastElementsKind(Tagged<JSObject> object) {
  if (!object->map()->CanHaveFastTransitionableElementsKind()) {
    return HOLEY_ELEMENTS;
  }
  if (object->HasSloppyArgumentsElements()) {
    return FAST_SLOPPY_ARGUMENTS_ELEMENTS;
  }
  if (object->HasStringWrapperElements()) {
    return FAST_STRING_WRAPPER_ELEMENTS;
  }
  DCHECK(object->HasDictionaryElements());
  Tagged<NumberDictionary> dictionary = object->element_dictionary();
  ElementsKind kind = HOLEY_SMI_ELEMENTS;
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> key = dictionary->KeyAt(i);
    if (IsNumber(key)) {
      Tagged<Object> value = dictionary->ValueAt(i);
      if (!IsNumber(value)) return HOLEY_ELEMENTS;
      if (!IsSmi(value)) {
        if (!v8_flags.unbox_double_arrays) return HOLEY_ELEMENTS;
        kind = HOLEY_DOUBLE_ELEMENTS;
      }
    }
  }
  return kind;
}

// static
Maybe<bool> JSObject::AddDataElement(Handle<JSObject> object, uint32_t index,
                                     DirectHandle<Object> value,
                                     PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  DCHECK(object->map(isolate)->is_extensible());

  uint32_t old_length = 0;
  uint32_t new_capacity = 0;

  if (IsJSArray(*object, isolate)) {
    CHECK(Object::ToArrayLength(Cast<JSArray>(*object)->length(), &old_length));
  }

  ElementsKind kind = object->GetElementsKind(isolate);
  Tagged<FixedArrayBase> elements = object->elements(isolate);
  ElementsKind dictionary_kind = DICTIONARY_ELEMENTS;
  if (IsSloppyArgumentsElementsKind(kind)) {
    elements = Cast<SloppyArgumentsElements>(elements)->arguments();
    dictionary_kind = SLOW_SLOPPY_ARGUMENTS_ELEMENTS;
  } else if (IsStringWrapperElementsKind(kind)) {
    dictionary_kind = SLOW_STRING_WRAPPER_ELEMENTS;
  }

  if (attributes != NONE) {
    kind = dictionary_kind;
  } else if (IsNumberDictionary(elements, isolate)) {
    kind = ShouldConvertToFastElements(
               *object, Cast<NumberDictionary>(elements), index, &new_capacity)
               ? BestFittingFastElementsKind(*object)
               : dictionary_kind;
  } else if (ShouldConvertToSlowElements(
                 *object, static_cast<uint32_t>(elements->length()), index,
                 &new_capacity)) {
    kind = dictionary_kind;
  }

  ElementsKind to = Object::OptimalElementsKind(*value, isolate);
  if (IsHoleyElementsKind(kind) || !IsJSArray(*object, isolate) ||
      index > old_length) {
    to = GetHoleyElementsKind(to);
    kind = GetHoleyElementsKind(kind);
  }
  to = GetMoreGeneralElementsKind(kind, to);
  ElementsAccessor* accessor = ElementsAccessor::ForKind(to);
  MAYBE_RETURN(accessor->Add(object, index, value, attributes, new_capacity),
               Nothing<bool>());

  if (IsJSArray(*object, isolate) && index >= old_length) {
    DirectHandle<Number> new_length =
        isolate->factory()->NewNumberFromUint(index + 1);
    Cast<JSArray>(*object)->set_length(*new_length);
  }
  return Just(true);
}

template <AllocationSiteUpdateMode update_or_check>
bool JSObject::UpdateAllocationSite(DirectHandle<JSObject> object,
                                    ElementsKind to_kind) {
  if (!IsJSArray(*object)) return false;

  if (!HeapLayout::InYoungGeneration(*object)) return false;

  if (Heap::IsLargeObject(*object)) return false;

  Handle<AllocationSite> site;
  {
    DisallowGarbageCollection no_gc;

    Heap* heap = object->GetHeap();
    Tagged<AllocationMemento> memento =
        PretenuringHandler::FindAllocationMemento<
            PretenuringHandler::kForRuntime>(heap, object->map(), *object);
    if (memento.is_null()) return false;

    // Walk through to the Allocation Site
    site = handle(memento->GetAllocationSite(), heap->isolate());
  }
  return AllocationSite::DigestTransitionFeedback<update_or_check>(site,
                                                                   to_kind);
}

template bool
JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kCheckOnly>(
    DirectHandle<JSObject> object, ElementsKind to_kind);

template bool JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kUpdate>(
    DirectHandle<JSObject> object, ElementsKind to_kind);

void JSObject::TransitionElementsKind(Handle<JSObject> object,
                                      ElementsKind to_kind) {
  ElementsKind from_kind = object->GetElementsKind();

  if (IsHoleyElementsKind(from_kind)) {
    to_kind = GetHoleyElementsKind(to_kind);
  }

  if (from_kind == to_kind) return;

  // This method should never be called for any other case.
  DCHECK(IsFastElementsKind(from_kind) ||
         IsNonextensibleElementsKind(from_kind));
  DCHECK(IsFastElementsKind(to_kind) || IsNonextensibleElementsKind(to_kind));
  DCHECK_NE(TERMINAL_FAST_ELEMENTS_KIND, from_kind);

  UpdateAllocationSite(object, to_kind);
  Isolate* isolate = object->GetIsolate();
  if (object->elements() == ReadOnlyRoots(isolate).empty_fixed_array() ||
      IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind)) {
    // No change is needed to the elements() buffer, the transition
    // only requires a map change.
    DirectHandle<Map> new_map = GetElementsTransitionMap(object, to_kind);
    JSObject::MigrateToMap(isolate, object, new_map);
    if (v8_flags.trace_elements_transitions) {
      DirectHandle<FixedArrayBase> elms(object->elements(), isolate);
      PrintElementsTransition(stdout, object, from_kind, elms, to_kind, elms);
    }
  } else {
    DCHECK((IsSmiElementsKind(from_kind) && IsDoubleElementsKind(to_kind)) ||
           (IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind)));
    uint32_t c = static_cast<uint32_t>(object->elements()->length());
    if (ElementsAccessor::ForKind(to_kind)
            ->GrowCapacityAndConvert(object, c)
            .IsNothing()) {
      // TODO(victorgomes): Temporarily forcing a fatal error here in case of
      // overflow, until all users of TransitionElementsKind can handle
      // exceptions.
      FATAL(
          "Fatal JavaScript invalid size error when transitioning elements "
          "kind");
      UNREACHABLE();
    }
  }
}

template <typename BackingStore>
static int HoleyElementsUsage(Tagged<JSObject> object,
                              Tagged<BackingStore> store) {
  Isolate* isolate = object->GetIsolate();
  int limit = IsJSArray(object) ? Smi::ToInt(Cast<JSArray>(object)->length())
                                : store->length();
  int used = 0;
  for (int i = 0; i < limit; ++i) {
    if (!store->is_the_hole(isolate, i)) ++used;
  }
  return used;
}

int JSObject::GetFastElementsUsage() {
  Tagged<FixedArrayBase> store = elements();
  switch (GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS:
      return IsJSArray(*this) ? Smi::ToInt(Cast<JSArray>(*this)->length())
                              : store->length();
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
      store = Cast<SloppyArgumentsElements>(store)->arguments();
      [[fallthrough]];
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
      return HoleyElementsUsage(*this, Cast<FixedArray>(store));
    case HOLEY_DOUBLE_ELEMENTS:
      if (elements()->length() == 0) return 0;
      return HoleyElementsUsage(*this, Cast<FixedDoubleArray>(store));

    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case DICTIONARY_ELEMENTS:
    case WASM_ARRAY_ELEMENTS:
    case NO_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      UNREACHABLE();
  }
  return 0;
}

MaybeHandle<JSAny> JSObject::GetPropertyWithInterceptor(LookupIterator* it,
                                                        bool* done) {
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  return GetPropertyWithInterceptorInternal(it, it->GetInterceptor(), done);
}

Maybe<bool> JSObject::HasRealNamedProperty(Isolate* isolate,
                                           Handle<JSObject> object,
                                           Handle<Name> name) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  return HasProperty(&it);
}

Maybe<bool> JSObject::HasRealElementProperty(Isolate* isolate,
                                             Handle<JSObject> object,
                                             uint32_t index) {
  LookupIterator it(isolate, object, index, object,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  return HasProperty(&it);
}

Maybe<bool> JSObject::HasRealNamedCallbackProperty(Isolate* isolate,
                                                   Handle<JSObject> object,
                                                   Handle<Name> name) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  Maybe<PropertyAttributes> maybe_result = GetPropertyAttributes(&it);
  return maybe_result.IsJust() ? Just(it.state() == LookupIterator::ACCESSOR)
                               : Nothing<bool>();
}

Tagged<Object> JSObject::RawFastPropertyAtCompareAndSwap(
    FieldIndex index, Tagged<Object> expected, Tagged<Object> value,
    SeqCstAccessTag tag) {
  return HeapObject::SeqCst_CompareAndSwapField(
      expected, value,
      [=, this](Tagged<Object> expected_value, Tagged<Object> new_value) {
        return RawFastPropertyAtCompareAndSwapInternal(index, expected_value,
                                                       new_value, tag);
      });
}

bool JSGlobalProxy::IsDetached() { return !GetCreationContext().has_value(); }

void JSGlobalObject::InvalidatePropertyCell(DirectHandle<JSGlobalObject> global,
                                            Handle<Name> name) {
  Isolate* isolate = global->GetIsolate();
  // Regardless of whether the property is there or not invalidate
  // Load/StoreGlobalICs that load/store through global object's prototype.
  JSObject::InvalidatePrototypeValidityCell(*global);
  DCHECK(!global->HasFastProperties());
  auto dictionary = handle(global->global_dictionary(kAcquireLoad), isolate);
  InternalIndex entry = dictionary->FindEntry(isolate, name);
  if (entry.is_not_found()) return;

  DirectHandle<PropertyCell> cell(dictionary->CellAt(entry), isolate);
  DirectHandle<Object> value(cell->value(), isolate);
  PropertyDetails details = cell->property_details();
  details = details.set_cell_type(PropertyCellType::kMutable);
  PropertyCell::InvalidateAndReplaceEntry(isolate, dictionary, entry, details,
                                          value);
}

// static
MaybeHandle<JSDate> JSDate::New(Handle<JSFunction> constructor,
                                Handle<JSReceiver> new_target, double tv) {
  Handle<JSDate> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      constructor->GetIsolate(), result,
      Cast<JSDate>(JSObject::New(constructor, new_target,
                                 Handle<AllocationSite>::null())));
  if (DateCache::TryTimeClip(&tv)) {
    result->SetValue(tv);
  } else {
    result->SetNanValue();
  }
  return result;
}

// static
int64_t JSDate::CurrentTimeValue(Isolate* isolate) {
  if (v8_flags.log_timer_events) LOG(isolate, CurrentTimeEvent());
  if (v8_flags.correctness_fuzzer_suppressions) return 4;

  // According to ECMA-262, section 15.9.1, page 117, the precision of
  // the number in a Date object representing a particular instant in
  // time is milliseconds. Therefore, we floor the result of getting
  // the OS time.
  return V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds();
}

// static
Address JSDate::GetField(Isolate* isolate, Address raw_object,
                         Address smi_index) {
  // Called through CallCFunction.
  DisallowGarbageCollection no_gc;
  DisallowHandleAllocation no_handles;
  DisallowJavascriptExecution no_js(isolate);

  Tagged<Object> object(raw_object);
  Tagged<Smi> index(smi_index);
  return Cast<JSDate>(object)
      ->DoGetField(isolate, static_cast<FieldIndex>(index.value()))
      .ptr();
}

Tagged<Object> JSDate::DoGetField(Isolate* isolate, FieldIndex index) {
  DateCache* date_cache = isolate->date_cache();

  if (index < kFirstUncachedField) {
    Tagged<Object> stamp = cache_stamp();
    if (stamp != date_cache->stamp() && IsSmi(stamp)) {
      // Since the stamp is not NaN, the value is also not NaN.
      int64_t local_time_ms =
          date_cache->ToLocal(static_cast<int64_t>(value()));
      SetCachedFields(local_time_ms, date_cache);
    }
    switch (index) {
      case kYear:
        return year();
      case kMonth:
        return month();
      case kDay:
        return day();
      case kWeekday:
        return weekday();
      case kHour:
        return hour();
      case kMinute:
        return min();
      case kSecond:
        return sec();
      default:
        UNREACHABLE();
    }
  }

  if (index >= kFirstUTCField) {
    return GetUTCField(index, value(), date_cache);
  }

  double time = value();
  if (std::isnan(time)) return GetReadOnlyRoots().nan_value();

  int64_t local_time_ms = date_cache->ToLocal(static_cast<int64_t>(time));
  int days = DateCache::DaysFromTime(local_time_ms);

  if (index == kDays) return Smi::FromInt(days);

  int time_in_day_ms = DateCache::TimeInDay(local_time_ms, days);
  if (index == kMillisecond) return Smi::FromInt(time_in_day_ms % 1000);
  DCHECK_EQ(index, kTimeInDay);
  return Smi::FromInt(time_in_day_ms);
}

Tagged<Object> JSDate::GetUTCField(FieldIndex index, double value,
                                   DateCache* date_cache) {
  DCHECK_GE(index, kFirstUTCField);

  if (std::isnan(value)) return GetReadOnlyRoots().nan_value();

  int64_t time_ms = static_cast<int64_t>(value);

  if (index == kTimezoneOffset) {
    return Smi::FromInt(date_cache->TimezoneOffset(time_ms));
  }

  int days = DateCache::DaysFromTime(time_ms);

  if (index == kWeekdayUTC) return Smi::FromInt(date_cache->Weekday(days));

  if (index <= kDayUTC) {
    int year, month, day;
    date_cache->YearMonthDayFromDays(days, &year, &month, &day);
    if (index == kYearUTC) return Smi::FromInt(year);
    if (index == kMonthUTC) return Smi::FromInt(month);
    DCHECK_EQ(index, kDayUTC);
    return Smi::FromInt(day);
  }

  int time_in_day_ms = DateCache::TimeInDay(time_ms, days);
  switch (index) {
    case kHourUTC:
      return Smi::FromInt(time_in_day_ms / (60 * 60 * 1000));
    case kMinuteUTC:
      return Smi::FromInt((time_in_day_ms / (60 * 1000)) % 60);
    case kSecondUTC:
      return Smi::FromInt((time_in_day_ms / 1000) % 60);
    case kMillisecondUTC:
      return Smi::FromInt(time_in_day_ms % 1000);
    case kDaysUTC:
      return Smi::FromInt(days);
    case kTimeInDayUTC:
      return Smi::FromInt(time_in_day_ms);
    default:
      UNREACHABLE();
  }

  UNREACHABLE();
}

// static
void JSDate::SetValue(double value) {
#ifdef DEBUG
  DCHECK(!std::isnan(value));
  double clipped_value = value;
  DCHECK(DateCache::TryTimeClip(&clipped_value));
  DCHECK_EQ(value, clipped_value);
#endif
  set_value(value);
  set_cache_stamp(Smi::FromInt(DateCache::kInvalidStamp), SKIP_WRITE_BARRIER);
}
void JSDate::SetNanValue() {
  set_value(std::numeric_limits<double>::quiet_NaN());

  Tagged<HeapNumber> nan = GetReadOnlyRoots().nan_value();
  set_cache_stamp(nan, SKIP_WRITE_BARRIER);
  set_year(nan, SKIP_WRITE_BARRIER);
  set_month(nan, SKIP_WRITE_BARRIER);
  set_day(nan, SKIP_WRITE_BARRIER);
  set_hour(nan, SKIP_WRITE_BARRIER);
  set_min(nan, SKIP_WRITE_BARRIER);
  set_sec(nan, SKIP_WRITE_BARRIER);
  set_weekday(nan, SKIP_WRITE_BARRIER);
}

void JSDate::SetCachedFields(int64_t local_time_ms, DateCache* date_cache) {
  int days = DateCache::DaysFromTime(local_time_ms);
  int time_in_day_ms = DateCache::TimeInDay(local_time_ms, days);
  int year, month, day;
  date_cache->YearMonthDayFromDays(days, &year, &month, &day);
  int weekday = date_cache->Weekday(days);
  int hour = time_in_day_ms / (60 * 60 * 1000);
  int min = (time_in_day_ms / (60 * 1000)) % 60;
  int sec = (time_in_day_ms / 1000) % 60;
  set_cache_stamp(date_cache->stamp());
  set_year(Smi::FromInt(year), SKIP_WRITE_BARRIER);
  set_month(Smi::FromInt(month), SKIP_WRITE_BARRIER);
  set_day(Smi::FromInt(day), SKIP_WRITE_BARRIER);
  set_weekday(Smi::FromInt(weekday), SKIP_WRITE_BARRIER);
  set_hour(Smi::FromInt(hour), SKIP_WRITE_BARRIER);
  set_min(Smi::FromInt(min), SKIP_WRITE_BARRIER);
  set_sec(Smi::FromInt(sec), SKIP_WRITE_BARRIER);
}

// static
void JSMessageObject::InitializeSourcePositions(
    Isolate* isolate, DirectHandle<JSMessageObject> message) {
  DCHECK(!message->DidEnsureSourcePositionsAvailable());
  Script::InitLineEnds(isolate, handle(message->script(), isolate));
  if (message->shared_info() == Smi::FromInt(-1)) {
    message->set_shared_info(Smi::zero());
    return;
  }
  DCHECK(IsSharedFunctionInfo(message->shared_info()));
  DCHECK_GE(message->bytecode_offset().value(), kFunctionEntryBytecodeOffset);
  Handle<SharedFunctionInfo> shared_info(
      Cast<SharedFunctionInfo>(message->shared_info()), isolate);
  IsCompiledScope is_compiled_scope;
  SharedFunctionInfo::EnsureBytecodeArrayAvailable(
      isolate, shared_info, &is_compiled_scope, CreateSourcePositions::kYes);
  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared_info);
  DCHECK(shared_info->HasBytecodeArray());
  int position = shared_info->abstract_code(isolate)->SourcePosition(
      isolate, message->bytecode_offset().value());
  DCHECK_GE(position, 0);
  message->set_start_position(position);
  message->set_end_position(position + 1);
  message->set_shared_info(Smi::zero());
}

int JSMessageObject::GetLineNumber() const {
  DisallowGarbageCollection no_gc;
  DCHECK(DidEnsureSourcePositionsAvailable());
  if (start_position() == -1) return Message::kNoLineNumberInfo;

  DCHECK(script()->has_line_ends());
  DirectHandle<Script> the_script(script(), GetIsolate());
  Script::PositionInfo info;
  if (!script()->GetPositionInfo(start_position(), &info)) {
    return Message::kNoLineNumberInfo;
  }
  return info.line + 1;
}

int JSMessageObject::GetColumnNumber() const {
  DisallowGarbageCollection no_gc;
  DCHECK(DidEnsureSourcePositionsAvailable());
  if (start_position() == -1) return -1;

  DCHECK(script()->has_line_ends());
  DirectHandle<Script> the_script(script(), GetIsolate());
  Script::PositionInfo info;
  if (!script()->GetPositionInfo(start_position(), &info)) {
    return -1;
  }
  return info.column;  // Note: No '+1' in contrast to GetLineNumber.
}

Tagged<String> JSMessageObject::GetSource() const {
  DisallowGarbageCollection no_gc;
  Tagged<Script> script_object = script();
  if (script_object->HasValidSource()) {
    Tagged<Object> source = script_object->source();
    if (IsString(source)) return Cast<String>(source);
  }
  return ReadOnlyRoots(GetIsolate()).empty_string();
}

Handle<String> JSMessageObject::GetSourceLine() const {
  Isolate* isolate = GetIsolate();

#if V8_ENABLE_WEBASSEMBLY
  if (script()->type() == Script::Type::kWasm) {
    return isolate->factory()->empty_string();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  Script::PositionInfo info;
  {
    DisallowGarbageCollection no_gc;
    DCHECK(DidEnsureSourcePositionsAvailable());
    DCHECK(script()->has_line_ends());
    if (!script()->GetPositionInfo(start_position(), &info)) {
      return isolate->factory()->empty_string();
    }
  }

  Handle<String> src = handle(Cast<String>(script()->source()), isolate);
  return isolate->factory()->NewSubString(src, info.line_start, info.line_end);
}

}  // namespace v8::internal

"""


```