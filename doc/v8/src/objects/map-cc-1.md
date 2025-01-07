Response:
The user wants me to analyze a C++ source code snippet from V8's `map.cc` file. I need to perform the following steps based on the provided instructions:

1. **Summarize the functionality:** Explain what the code does.
2. **Check for Torque:** Determine if the file is a Torque file based on its extension.
3. **Relate to JavaScript:** If the code relates to JavaScript, provide a JavaScript example.
4. **Provide logic examples:**  Give examples with hypothetical inputs and outputs for code logic.
5. **Highlight common errors:** Mention potential programming errors related to this code.
6. **Indicate part number:**  Note that this is part 2 of 4.

Let's break down the code snippet to understand its functionality. It appears to deal with map transitions, elements kind transitions, and map creation/modification within the V8 engine.

- `AddDerivedMap`: Likely involved in creating maps for derived objects or constructors.
- `TransitionRootMapToPrototypeForNewObject`: Handles map transitions when a new object is created with a prototype.
- `ContainsMap`: Checks if a given map exists within a span of maps.
- `HasElementsKind`: Checks if any map in a span has a specific elements kind.
- `FindElementsKindTransitionedMap`:  Finds a map within candidates that has transitioned to a specific elements kind.
- `FindClosestElementsTransition`:  Finds the closest map in an elements kind transition chain.
- `LookupElementsTransitionMap`: Looks up a map with a specific elements kind in the transition chain.
- `IsMapInArrayPrototypeChain`: Checks if a map is part of the Array prototype chain.
- `TransitionElementsTo`:  Handles the transition of a map's elements kind.
- `AddMissingElementsTransitions`: Adds intermediate transitions when changing elements kind.
- `TryAsElementsKind`: Attempts to retrieve a map with a specific elements kind.
- `AsElementsKind`:  Retrieves a map with a specific elements kind, adding transitions if necessary.
- `NumberOfEnumerableProperties`: Counts the number of enumerable properties in a map.
- `NextFreePropertyIndex`:  Finds the next available index for a property.
- `OnlyHasSimpleProperties`: Checks if a map only has simple properties.
- `ShouldCheckForReadOnlyElementsInPrototypeChain`: Determines if the prototype chain needs to be checked for read-only elements.
- `RawCopy`: Creates a raw copy of a map.
- `Normalize`: Normalizes a map, potentially caching the result.
- `CopyNormalized`: Creates a normalized copy of a map.
- `TransitionToImmutableProto`: Creates a map for an immutable prototype.
- `EnsureInitialMap`: Ensures certain properties of an initial map.
- `CopyInitialMapNormalized`: Creates a normalized copy of an initial map.
- `CopyInitialMap`: Creates a copy of an initial map.
- `CopyDropDescriptors`: Creates a copy of a map without its descriptors.
- `ShareDescriptor`: Shares a descriptor between maps.
- `ConnectTransition`: Connects two maps with a transition.
- `CopyReplaceDescriptors`: Creates a copy of a map replacing its descriptors.
- `AddMissingTransitions`: Adds missing transitions in a map's history.
- `InstallDescriptors`: Installs descriptors on a map.
- `CopyAsElementsKind`: Creates a copy of a map with a specific elements kind.
- `AsLanguageMode`:  Retrieves the appropriate map based on the language mode.

The code heavily revolves around the concept of **map transitions** in V8. When an object's properties or elements change in a way that affects its internal structure, its hidden class (represented by the `Map` object) might transition to a new `Map` that reflects these changes. This is done for optimization purposes. The code also deals with different kinds of element storage (e.g., `FAST_ELEMENTS`, `DICTIONARY_ELEMENTS`).

Now, let's structure the answer based on the user's requirements.
```
功能归纳：

这段C++代码是V8引擎中处理对象映射（Map）的核心部分，主要负责以下功能：

1. **Map的创建和转换:**
   - 创建新的Map对象，包括派生Map和用于新对象的原型Map。
   - 在对象属性或元素发生变化时，进行Map的转换（transition），以优化属性访问和内存布局。
   - 特别关注元素类型的转换 (`ElementsKind`)，例如从快速数组到字典数组的转换。
   - 提供方法查找特定元素类型的转换Map。

2. **Map的比较和查找:**
   - 检查给定的Map是否在一个Map集合中存在。
   - 检查Map集合中是否存在具有特定元素类型的Map。
   - 查找元素类型转换链中最近的Map。

3. **Map与原型链的关系:**
   - 判断一个Map是否在数组的原型链上。
   - 处理与原型相关的Map转换。

4. **Map的属性和元数据管理:**
   - 计算可枚举属性的数量。
   - 获取下一个可用的属性索引。
   - 判断Map是否只包含简单属性。
   - 检查原型链中是否存在只读元素。

5. **Map的复制和规范化:**
   - 创建Map的副本，包括原始副本和规范化副本（用于字典模式）。
   - 规范化Map会将对象转变为更通用的表示，例如将内联属性移出。
   - 支持带缓存的规范化，以提高性能。

6. **Map的描述符管理:**
   - 管理Map的属性描述符 (`DescriptorArray`)。
   - 共享、添加、替换和删除描述符。
   - 连接Map之间的转换，形成转换树。

7. **Map的元素类型处理:**
   - 显式地转换Map的元素类型。
   - 添加缺失的元素类型转换。

8. **其他辅助功能:**
   - 处理不可变原型的Map。
   - 处理函数对象的Map和语言模式。

由于这是一个C++文件，扩展名为 `.cc`，所以它不是V8 Torque源代码。

这段代码与JavaScript的功能密切相关，因为它直接影响了JavaScript对象的内部表示和行为。

**JavaScript 示例:**

```javascript
// 假设我们有一个普通对象
const obj = {};

// 当我们添加第一个属性时，V8会为它创建一个初始的Map
obj.a = 1;

// 当我们添加更多属性时，V8可能会进行Map的转换，
// 如果属性数量超过了内联属性的限制，或者属性的类型发生了变化。
obj.b = "hello";
obj.c = true;

// 当我们访问属性时，V8会使用对象的Map来快速查找属性在内存中的位置。
console.log(obj.a);

// 当我们删除属性时，V8也可能进行Map的转换。
delete obj.b;

// 数组也有类似的Map转换机制，例如从全是数字的数组
const arr1 = [1, 2, 3];
// 转换为包含空洞或不同类型的数组
arr1[5] = 6; // 创建空洞
arr1.push("string"); // 添加字符串
```

**代码逻辑推理（假设输入与输出）:**

**假设输入:**

- `map`: 一个表示普通对象的初始Map的Handle。
- 我们要向这个对象添加一个新的属性 "d"，值为 `42`。

**输出:**

- 函数 `Map::ShareDescriptor` 或 `Map::CopyReplaceDescriptors` 会被调用。
- 会创建一个新的Map对象，作为转换后的Map。
- 新的Map对象会包含属性 "d" 的描述符。
- 原始的Map对象会通过一个转换指向新的Map对象，属性名为 "d"。

**用户常见的编程错误:**

1. **过度依赖对象属性的顺序:**  尽管V8会尽力保持属性添加的顺序，但在某些情况下（例如，删除后重新添加），属性的内部顺序可能会发生变化，这可能会影响某些依赖特定顺序的代码（虽然通常不推荐这样做）。Map转换是为了优化，内部顺序不是稳定的保证。

2. **动态修改对象结构导致性能下降:**  频繁地添加或删除属性，尤其是改变属性类型，会导致V8不断进行Map的转换和对象的重新布局，这会带来性能开销。在性能敏感的场景中，应该尽量避免这种动态修改。例如：

   ```javascript
   const obj = {};
   for (let i = 0; i < 1000; i++) {
       obj[`prop${i}`] = i; // 频繁添加属性可能导致多次Map转换
   }
   ```

3. **误解原型链的Map共享:**  虽然具有相同结构的对象可能共享相同的Map，但这并不意味着对一个对象的Map的修改会影响到原型链上的其他对象。Map的转换是基于对象自身的结构变化的。

**功能归纳 (第2部分):**

这段代码主要负责 **Map的创建、转换以及与元素类型和描述符相关的管理**。它提供了在对象属性结构或元素类型发生变化时，高效地更新对象内部表示的关键机制。这些机制对于V8引擎优化JavaScript代码的性能至关重要。代码中包含了查找、比较、复制和修改Map的功能，以及维护Map之间转换关系的能力。
```
Prompt: 
```
这是目录为v8/src/objects/map.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/map.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
o::AddDerivedMap(info, map, isolate);
    }
    return map;
  }

  // The TransitionToPrototype map will not have new_target_is_base reset. But
  // we don't need it to for proxies.
  return Map::TransitionRootMapToPrototypeForNewObject(isolate, from,
                                                       prototype);
}

static bool ContainsMap(MapHandlesSpan maps, Tagged<Map> map) {
  DCHECK(!map.is_null());
  for (Handle<Map> current : maps) {
    if (!current.is_null() && *current == map) return true;
  }
  return false;
}

static bool HasElementsKind(MapHandlesSpan maps, ElementsKind elements_kind) {
  for (Handle<Map> current : maps) {
    if (!current.is_null() && current->elements_kind() == elements_kind)
      return true;
  }
  return false;
}

Tagged<Map> Map::FindElementsKindTransitionedMap(Isolate* isolate,
                                                 MapHandlesSpan candidates,
                                                 ConcurrencyMode cmode) {
  DisallowGarbageCollection no_gc;

  if (IsDetached(isolate)) return Map();

  ElementsKind kind = elements_kind();
  bool is_packed = IsFastPackedElementsKind(kind);

  Tagged<Map> transition;
  if (IsTransitionableFastElementsKind(kind)) {
    // Check the state of the root map.
    Tagged<Map> root_map = FindRootMap(isolate);
    if (!EquivalentToForElementsKindTransition(root_map, cmode)) return Map();
    root_map = root_map->LookupElementsTransitionMap(isolate, kind, cmode);
    DCHECK(!root_map.is_null());
    // Starting from the next existing elements kind transition try to
    // replay the property transitions that does not involve instance rewriting
    // (ElementsTransitionAndStoreStub does not support that).
    for (root_map = root_map->ElementsTransitionMap(isolate, cmode);
         !root_map.is_null() && root_map->has_fast_elements();
         root_map = root_map->ElementsTransitionMap(isolate, cmode)) {
      // If root_map's elements kind doesn't match any of the elements kind in
      // the candidates there is no need to do any additional work.
      if (!HasElementsKind(candidates, root_map->elements_kind())) continue;
      Tagged<Map> current =
          root_map->TryReplayPropertyTransitions(isolate, *this, cmode);
      if (current.is_null()) continue;
      if (InstancesNeedRewriting(current, cmode)) continue;

      const bool current_is_packed =
          IsFastPackedElementsKind(current->elements_kind());
      if (ContainsMap(candidates, current) &&
          (is_packed || !current_is_packed)) {
        transition = current;
        is_packed = is_packed && current_is_packed;
      }
    }
  }
  return transition;
}

static Tagged<Map> FindClosestElementsTransition(Isolate* isolate,
                                                 Tagged<Map> map,
                                                 ElementsKind to_kind,
                                                 ConcurrencyMode cmode) {
  DisallowGarbageCollection no_gc;
  // Ensure we are requested to search elements kind transition "near the root".
  DCHECK_EQ(map->FindRootMap(isolate)->NumberOfOwnDescriptors(),
            map->NumberOfOwnDescriptors());
  Tagged<Map> current_map = map;

  ElementsKind kind = map->elements_kind();
  while (kind != to_kind) {
    Tagged<Map> next_map = current_map->ElementsTransitionMap(isolate, cmode);
    if (next_map.is_null()) return current_map;
    kind = next_map->elements_kind();
    current_map = next_map;
  }

  DCHECK_EQ(to_kind, current_map->elements_kind());
  return current_map;
}

Tagged<Map> Map::LookupElementsTransitionMap(Isolate* isolate,
                                             ElementsKind to_kind,
                                             ConcurrencyMode cmode) {
  Tagged<Map> to_map =
      FindClosestElementsTransition(isolate, *this, to_kind, cmode);
  if (to_map->elements_kind() == to_kind) return to_map;
  return Map();
}

bool Map::IsMapInArrayPrototypeChain(Isolate* isolate) const {
  if (isolate->initial_array_prototype()->map() == *this) {
    return true;
  }

  if (isolate->initial_object_prototype()->map() == *this) {
    return true;
  }

  return false;
}

Handle<Map> Map::TransitionElementsTo(Isolate* isolate, Handle<Map> map,
                                      ElementsKind to_kind) {
  ElementsKind from_kind = map->elements_kind();
  if (from_kind == to_kind) return map;

  Tagged<Context> native_context = isolate->context()->native_context();
  if (from_kind == FAST_SLOPPY_ARGUMENTS_ELEMENTS) {
    if (*map == native_context->fast_aliased_arguments_map()) {
      DCHECK_EQ(SLOW_SLOPPY_ARGUMENTS_ELEMENTS, to_kind);
      return handle(native_context->slow_aliased_arguments_map(), isolate);
    }
  } else if (from_kind == SLOW_SLOPPY_ARGUMENTS_ELEMENTS) {
    if (*map == native_context->slow_aliased_arguments_map()) {
      DCHECK_EQ(FAST_SLOPPY_ARGUMENTS_ELEMENTS, to_kind);
      return handle(native_context->fast_aliased_arguments_map(), isolate);
    }
  } else if (IsFastElementsKind(from_kind) && IsFastElementsKind(to_kind)) {
    // Reuse map transitions for JSArrays.
    DisallowGarbageCollection no_gc;
    if (native_context->GetInitialJSArrayMap(from_kind) == *map) {
      Tagged<Object> maybe_transitioned_map =
          native_context->get(Context::ArrayMapIndex(to_kind));
      if (IsMap(maybe_transitioned_map)) {
        return handle(Cast<Map>(maybe_transitioned_map), isolate);
      }
    }
  }

  DCHECK(!IsUndefined(*map, isolate));
  // Check if we can go back in the elements kind transition chain.
  if (IsHoleyElementsKind(from_kind) &&
      to_kind == GetPackedElementsKind(from_kind) &&
      IsMap(map->GetBackPointer()) &&
      Cast<Map>(map->GetBackPointer())->elements_kind() == to_kind) {
    return handle(Cast<Map>(map->GetBackPointer()), isolate);
  }

  bool allow_store_transition = IsTransitionElementsKind(from_kind);
  // Only store fast element maps in ascending generality.
  if (IsFastElementsKind(to_kind)) {
    allow_store_transition =
        allow_store_transition && IsTransitionableFastElementsKind(from_kind) &&
        IsMoreGeneralElementsKindTransition(from_kind, to_kind);
  }

  if (!allow_store_transition) {
    return Map::CopyAsElementsKind(isolate, map, to_kind, OMIT_TRANSITION);
  }

  return MapUpdater{isolate, map}.ReconfigureElementsKind(to_kind);
}

static Handle<Map> AddMissingElementsTransitions(Isolate* isolate,
                                                 Handle<Map> map,
                                                 ElementsKind to_kind) {
  DCHECK(IsTransitionElementsKind(map->elements_kind()));

  Handle<Map> current_map = map;

  ElementsKind kind = map->elements_kind();
  TransitionFlag flag;
  if (map->IsDetached(isolate)) {
    flag = OMIT_TRANSITION;
  } else {
    flag = INSERT_TRANSITION;
    if (IsFastElementsKind(kind)) {
      while (kind != to_kind && !IsTerminalElementsKind(kind)) {
        kind = GetNextTransitionElementsKind(kind);
        current_map = Map::CopyAsElementsKind(isolate, current_map, kind, flag);
      }
    }
  }

  // In case we are exiting the fast elements kind system, just add the map in
  // the end.
  if (kind != to_kind) {
    current_map = Map::CopyAsElementsKind(isolate, current_map, to_kind, flag);
  }

  DCHECK(current_map->elements_kind() == to_kind);
  return current_map;
}

// static
std::optional<Tagged<Map>> Map::TryAsElementsKind(Isolate* isolate,
                                                  DirectHandle<Map> map,
                                                  ElementsKind kind,
                                                  ConcurrencyMode cmode) {
  Tagged<Map> closest_map =
      FindClosestElementsTransition(isolate, *map, kind, cmode);
  if (closest_map->elements_kind() != kind) return {};
  return closest_map;
}

// static
Handle<Map> Map::AsElementsKind(Isolate* isolate, DirectHandle<Map> map,
                                ElementsKind kind) {
  Handle<Map> closest_map(
      FindClosestElementsTransition(isolate, *map, kind,
                                    ConcurrencyMode::kSynchronous),
      isolate);

  if (closest_map->elements_kind() == kind) {
    return closest_map;
  }

  return AddMissingElementsTransitions(isolate, closest_map, kind);
}

int Map::NumberOfEnumerableProperties() const {
  int result = 0;
  Tagged<DescriptorArray> descs = instance_descriptors(kRelaxedLoad);
  for (InternalIndex i : IterateOwnDescriptors()) {
    if ((int{descs->GetDetails(i).attributes()} & ONLY_ENUMERABLE) == 0 &&
        !Object::FilterKey(descs->GetKey(i), ENUMERABLE_STRINGS)) {
      result++;
    }
  }
  return result;
}

int Map::NextFreePropertyIndex() const {
  int number_of_own_descriptors = NumberOfOwnDescriptors();
  Tagged<DescriptorArray> descs = instance_descriptors(kRelaxedLoad);
  // Search properties backwards to find the last field.
  for (int i = number_of_own_descriptors - 1; i >= 0; --i) {
    PropertyDetails details = descs->GetDetails(InternalIndex(i));
    if (details.location() == PropertyLocation::kField) {
      return details.field_index() + details.field_width_in_words();
    }
  }
  return 0;
}

bool Map::OnlyHasSimpleProperties() const {
  // Wrapped string elements aren't explicitly stored in the elements backing
  // store, but are loaded indirectly from the underlying string.
  return !IsStringWrapperElementsKind(elements_kind()) &&
         !IsSpecialReceiverMap(*this) && !is_dictionary_map();
}

bool Map::ShouldCheckForReadOnlyElementsInPrototypeChain(Isolate* isolate) {
  // If this map has TypedArray elements kind, we won't look at the prototype
  // chain, so we can return early.
  if (IsTypedArrayElementsKind(elements_kind())) return false;

  for (PrototypeIterator iter(isolate, *this); !iter.IsAtEnd();
       iter.Advance()) {
    // Be conservative, don't look into any JSReceivers that may have custom
    // elements. For example, into JSProxies, String wrappers (which have have
    // non-configurable, non-writable elements), API objects, etc.
    if (IsCustomElementsReceiverMap(iter.GetCurrent()->map())) return true;

    Tagged<JSObject> current = iter.GetCurrent<JSObject>();
    ElementsKind elements_kind = current->GetElementsKind(isolate);
    // If this prototype has TypedArray elements kind, we won't look any further
    // in the prototype chain, so we can return early.
    if (IsTypedArrayElementsKind(elements_kind)) return false;
    if (IsFrozenElementsKind(elements_kind)) return true;

    if (IsDictionaryElementsKind(elements_kind) &&
        current->element_dictionary(isolate)->requires_slow_elements()) {
      return true;
    }

    if (IsSlowArgumentsElementsKind(elements_kind)) {
      Tagged<SloppyArgumentsElements> elements =
          Cast<SloppyArgumentsElements>(current->elements(isolate));
      Tagged<Object> arguments = elements->arguments();
      if (Cast<NumberDictionary>(arguments)->requires_slow_elements()) {
        return true;
      }
    }
  }

  return false;
}

Handle<Map> Map::RawCopy(Isolate* isolate, Handle<Map> src_handle,
                         int instance_size, int inobject_properties) {
  Handle<Map> result = isolate->factory()->NewMap(
      src_handle, src_handle->instance_type(), instance_size,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);

  // We have to set the bitfields before any potential GCs could happen because
  // heap verification might fail otherwise.
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> src = *src_handle;
    Tagged<Map> raw = *result;
    raw->set_constructor_or_back_pointer(src->GetConstructorRaw());
    raw->set_bit_field(src->bit_field());
    raw->set_bit_field2(src->bit_field2());
    int new_bit_field3 = src->bit_field3();
    new_bit_field3 = Bits3::OwnsDescriptorsBit::update(new_bit_field3, true);
    new_bit_field3 =
        Bits3::NumberOfOwnDescriptorsBits::update(new_bit_field3, 0);
    new_bit_field3 = Bits3::EnumLengthBits::update(new_bit_field3,
                                                   kInvalidEnumCacheSentinel);
    new_bit_field3 = Bits3::IsDeprecatedBit::update(new_bit_field3, false);
    new_bit_field3 =
        Bits3::IsInRetainedMapListBit::update(new_bit_field3, false);
    if (!src->is_dictionary_map()) {
      new_bit_field3 = Bits3::IsUnstableBit::update(new_bit_field3, false);
    }
    // Same as bit_field comment above.
    raw->set_bit_field3(new_bit_field3);
    raw->clear_padding();
  }
  Handle<JSPrototype> prototype(src_handle->prototype(), isolate);
  Map::SetPrototype(isolate, result, prototype);
  return result;
}

Handle<Map> Map::Normalize(Isolate* isolate, Handle<Map> fast_map,
                           ElementsKind new_elements_kind,
                           Handle<JSPrototype> new_prototype,
                           PropertyNormalizationMode mode, bool use_cache,
                           const char* reason) {
  DCHECK(!fast_map->is_dictionary_map());

  Tagged<Map> meta_map = fast_map->map();
  if (fast_map->is_prototype_map()) {
    use_cache = false;
  }
  DirectHandle<NormalizedMapCache> cache;
  if (use_cache) {
    Tagged<Object> normalized_map_cache =
        meta_map->native_context()->normalized_map_cache();
    use_cache = !IsUndefined(normalized_map_cache, isolate);
    if (use_cache) {
      cache = Cast<NormalizedMapCache>(handle(normalized_map_cache, isolate));
    }
  }

  Handle<Map> new_map;
  if (use_cache && cache
                       ->Get(isolate, fast_map, new_elements_kind,
                             new_prototype.is_null() ? fast_map->prototype()
                                                     : *new_prototype,
                             mode)
                       .ToHandle(&new_map)) {
#ifdef VERIFY_HEAP
    if (v8_flags.verify_heap) new_map->DictionaryMapVerify(isolate);
#endif
#ifdef ENABLE_SLOW_DCHECKS
    if (v8_flags.enable_slow_asserts) {
      // The cached map should match newly created normalized map bit-by-bit,
      // except for the code cache, which can contain some ICs which can be
      // applied to the shared map, dependent code and weak cell cache.
      DirectHandle<Map> fresh = Map::CopyNormalized(isolate, fast_map, mode);
      fresh->set_elements_kind(new_elements_kind);
      if (!new_prototype.is_null()) {
        Map::SetPrototype(isolate, fresh, new_prototype);
      }

      static_assert(Map::kPrototypeValidityCellOffset ==
                    Map::kDependentCodeOffset + kTaggedSize);
      DCHECK_EQ(0, memcmp(reinterpret_cast<void*>(fresh->address()),
                          reinterpret_cast<void*>(new_map->address()),
                          Map::kBitField3Offset));
      // The IsInRetainedMapListBit might be different if the {new_map}
      // that we got from the {cache} was already embedded into optimized
      // code somewhere.
      // The IsMigrationTargetBit might be different if the {new_map} from
      // {cache} has already been marked as a migration target.
      constexpr int ignored_bit_field3_bits =
          Bits3::IsInRetainedMapListBit::kMask |
          Bits3::IsMigrationTargetBit::kMask;
      DCHECK_EQ(fresh->bit_field3() & ~ignored_bit_field3_bits,
                new_map->bit_field3() & ~ignored_bit_field3_bits);
      int offset = Map::kBitField3Offset + kInt32Size;
      DCHECK_EQ(0, memcmp(reinterpret_cast<void*>(fresh->address() + offset),
                          reinterpret_cast<void*>(new_map->address() + offset),
                          Map::kDependentCodeOffset - offset));
      offset = Map::kPrototypeValidityCellOffset + kTaggedSize;
      if (new_map->is_prototype_map()) {
        // For prototype maps, the PrototypeInfo is not copied.
        static_assert(Map::kTransitionsOrPrototypeInfoOffset ==
                      Map::kPrototypeValidityCellOffset + kTaggedSize);
        offset = kTransitionsOrPrototypeInfoOffset + kTaggedSize;
        DCHECK_EQ(fresh->raw_transitions(), Smi::zero());
      }
      DCHECK_EQ(0, memcmp(reinterpret_cast<void*>(fresh->address() + offset),
                          reinterpret_cast<void*>(new_map->address() + offset),
                          Map::kSize - offset));
    }
#endif
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("NormalizeCached", fast_map, new_map, reason));
    }
  } else {
    new_map = Map::CopyNormalized(isolate, fast_map, mode);
    new_map->set_elements_kind(new_elements_kind);
    if (!new_prototype.is_null()) {
      Map::SetPrototype(isolate, new_map, new_prototype);
      DCHECK(new_map->is_dictionary_map() && !new_map->is_deprecated());
    }
    if (use_cache) {
      cache->Set(isolate, fast_map, new_map);
    }
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("Normalize", fast_map, new_map, reason));
    }
  }
  fast_map->NotifyLeafMapLayoutChange(isolate);
  return new_map;
}

Handle<Map> Map::CopyNormalized(Isolate* isolate, Handle<Map> map,
                                PropertyNormalizationMode mode) {
  int new_instance_size = map->instance_size();
  if (mode == CLEAR_INOBJECT_PROPERTIES) {
    new_instance_size -= map->GetInObjectProperties() * kTaggedSize;
  }

  Handle<Map> result = RawCopy(
      isolate, map, new_instance_size,
      mode == CLEAR_INOBJECT_PROPERTIES ? 0 : map->GetInObjectProperties());
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw = *result;
    // Clear the unused_property_fields explicitly as this field should not
    // be accessed for normalized maps.
    raw->SetInObjectUnusedPropertyFields(0);
    raw->set_is_dictionary_map(true);
    raw->set_is_migration_target(false);
    raw->set_may_have_interesting_properties(true);
    raw->set_construction_counter(kNoSlackTracking);
  }

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) result->DictionaryMapVerify(isolate);
#endif

  return result;
}

// Return an immutable prototype exotic object version of the input map.
// Never even try to cache it in the transition tree, as it is intended
// for the global object and its prototype chain, and excluding it saves
// memory on the map transition tree.

// static
Handle<Map> Map::TransitionToImmutableProto(Isolate* isolate, Handle<Map> map) {
  Handle<Map> new_map = Map::Copy(isolate, map, "ImmutablePrototype");
  new_map->set_is_immutable_proto(true);
  return new_map;
}

namespace {
void EnsureInitialMap(Isolate* isolate, DirectHandle<Map> map) {
#ifdef DEBUG
  Tagged<Object> maybe_constructor = map->GetConstructor();
  DCHECK((IsJSFunction(maybe_constructor) &&
          *map == Cast<JSFunction>(maybe_constructor)->initial_map()) ||
         // Below are the exceptions to the check above.
         // |Function|'s initial map is a |sloppy_function_map| but
         // other function map variants such as sloppy with name or readonly
         // prototype or various strict function maps variants, etc. also
         // have Function as a constructor.
         *map == *isolate->strict_function_map() ||
         *map == *isolate->strict_function_with_name_map() ||
         // Same applies to |GeneratorFunction|'s initial map and generator
         // function map variants.
         *map == *isolate->generator_function_with_name_map() ||
         // Same applies to |AsyncFunction|'s initial map and other async
         // function map variants.
         *map == *isolate->async_function_with_name_map());
#endif
  // Initial maps must not contain descriptors in the descriptors array
  // that do not belong to the map.
  DCHECK_EQ(map->NumberOfOwnDescriptors(),
            map->instance_descriptors(isolate)->number_of_descriptors());
}
}  // namespace

// static
Handle<Map> Map::CopyInitialMapNormalized(Isolate* isolate, Handle<Map> map,
                                          PropertyNormalizationMode mode) {
  EnsureInitialMap(isolate, map);
  return CopyNormalized(isolate, map, mode);
}

// static
Handle<Map> Map::CopyInitialMap(Isolate* isolate, Handle<Map> map,
                                int instance_size, int inobject_properties,
                                int unused_property_fields) {
  EnsureInitialMap(isolate, map);

  Handle<Map> result =
      RawCopy(isolate, map, instance_size, inobject_properties);

  // Please note instance_type and instance_size are set when allocated.
  result->SetInObjectUnusedPropertyFields(unused_property_fields);

  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  if (number_of_own_descriptors > 0) {
    // The copy will use the same descriptors array without ownership.
    Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
    result->set_owns_descriptors(false);
    result->UpdateDescriptors(isolate, descriptors, number_of_own_descriptors);

    DCHECK_EQ(result->NumberOfFields(ConcurrencyMode::kSynchronous),
              result->GetInObjectProperties() - result->UnusedPropertyFields());
  }

  return result;
}

Handle<Map> Map::CopyDropDescriptors(Isolate* isolate, Handle<Map> map) {
  Handle<Map> result =
      RawCopy(isolate, map, map->instance_size(),
              IsJSObjectMap(*map) ? map->GetInObjectProperties() : 0);

  // Please note instance_type and instance_size are set when allocated.
  if (IsJSObjectMap(*map)) {
    result->CopyUnusedPropertyFields(*map);
  }
  map->NotifyLeafMapLayoutChange(isolate);
  return result;
}

Handle<Map> Map::ShareDescriptor(Isolate* isolate, Handle<Map> map,
                                 DirectHandle<DescriptorArray> descriptors,
                                 Descriptor* descriptor) {
  // Sanity check. This path is only to be taken if the map owns its descriptor
  // array, implying that its NumberOfOwnDescriptors equals the number of
  // descriptors in the descriptor array.
  DCHECK_EQ(map->NumberOfOwnDescriptors(),
            map->instance_descriptors(isolate)->number_of_descriptors());

  Handle<Map> result = CopyDropDescriptors(isolate, map);
  Handle<Name> name = descriptor->GetKey();

  // Properly mark the {result} if the {name} is an "interesting symbol".
  if (name->IsInteresting(isolate)) {
    result->set_may_have_interesting_properties(true);
  }

  // Ensure there's space for the new descriptor in the shared descriptor array.
  if (descriptors->number_of_slack_descriptors() == 0) {
    int old_size = descriptors->number_of_descriptors();
    if (old_size == 0) {
      descriptors = DescriptorArray::Allocate(isolate, 0, 1);
    } else {
      int slack = SlackForArraySize(old_size, kMaxNumberOfDescriptors);
      EnsureDescriptorSlack(isolate, map, slack);
      descriptors = handle(map->instance_descriptors(isolate), isolate);
    }
  }

  {
    DisallowGarbageCollection no_gc;
    descriptors->Append(descriptor);
    result->InitializeDescriptors(isolate, *descriptors);
  }

  DCHECK(result->NumberOfOwnDescriptors() == map->NumberOfOwnDescriptors() + 1);
  ConnectTransition(isolate, map, result, name, SIMPLE_PROPERTY_TRANSITION);

  return result;
}

void Map::ConnectTransition(Isolate* isolate, Handle<Map> parent,
                            Handle<Map> child, Handle<Name> name,
                            TransitionKindFlag transition_kind,
                            bool force_connect) {
  DCHECK_EQ(parent->map(), child->map());
  DCHECK_IMPLIES(name->IsInteresting(isolate),
                 child->may_have_interesting_properties());
  DCHECK_IMPLIES(parent->may_have_interesting_properties(),
                 child->may_have_interesting_properties());
  if (!IsUndefined(parent->GetBackPointer(), isolate)) {
    parent->set_owns_descriptors(false);
  } else if (!parent->IsDetached(isolate)) {
    // |parent| is initial map and it must not contain descriptors in the
    // descriptors array that do not belong to the map.
    DCHECK_EQ(parent->NumberOfOwnDescriptors(),
              parent->instance_descriptors(isolate)->number_of_descriptors());
  }
  if (parent->IsDetached(isolate) && !force_connect) {
    DCHECK(child->IsDetached(isolate));
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("Transition", parent, child, "prototype", name));
    }
  } else {
    TransitionsAccessor::Insert(isolate, parent, name, child, transition_kind);
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("Transition", parent, child, "", name));
    }
  }
}

Handle<Map> Map::CopyReplaceDescriptors(
    Isolate* isolate, Handle<Map> map,
    DirectHandle<DescriptorArray> descriptors, TransitionFlag flag,
    MaybeHandle<Name> maybe_name, const char* reason,
    TransitionKindFlag transition_kind) {
  DCHECK(descriptors->IsSortedNoDuplicates());

  Handle<Map> result = CopyDropDescriptors(isolate, map);
  bool is_connected = false;

  // Properly mark the {result} if the {name} is an "interesting symbol".
  Handle<Name> name;
  if (maybe_name.ToHandle(&name) && name->IsInteresting(isolate)) {
    result->set_may_have_interesting_properties(true);
  }

  if (map->is_prototype_map()) {
    result->InitializeDescriptors(isolate, *descriptors);
  } else {
    if (flag == INSERT_TRANSITION &&
        TransitionsAccessor::CanHaveMoreTransitions(isolate, map)) {
      result->InitializeDescriptors(isolate, *descriptors);

      DCHECK(!maybe_name.is_null());
      ConnectTransition(isolate, map, result, name, transition_kind);
      is_connected = true;
    } else if ((transition_kind == PROTOTYPE_TRANSITION &&
                v8_flags.move_prototype_transitions_first) ||
               isolate->bootstrapper()->IsActive()) {
      // Prototype transitions are always between root maps. UpdatePrototype
      // uses the MapUpdater and instance migration. Thus, field generalization
      // is allowed to happen lazily.
      DCHECK_IMPLIES(transition_kind == PROTOTYPE_TRANSITION,
                     IsUndefined(map->GetBackPointer()));
      result->InitializeDescriptors(isolate, *descriptors);
    } else {
      DCHECK_IMPLIES(transition_kind == PROTOTYPE_TRANSITION,
                     !v8_flags.move_prototype_transitions_first);
      descriptors->GeneralizeAllFields(transition_kind == PROTOTYPE_TRANSITION);
      result->InitializeDescriptors(isolate, *descriptors);
    }
  }
  if (v8_flags.log_maps && !is_connected) {
    LOG(isolate, MapEvent("ReplaceDescriptors", map, result, reason,
                          maybe_name.is_null() ? Handle<HeapObject>() : name));
  }
  return result;
}

// Creates transition tree starting from |split_map| and adding all descriptors
// starting from descriptor with index |split_map|.NumberOfOwnDescriptors().
// The way how it is done is tricky because of GC and special descriptors
// marking logic.
Handle<Map> Map::AddMissingTransitions(
    Isolate* isolate, Handle<Map> split_map,
    DirectHandle<DescriptorArray> descriptors) {
  DCHECK(descriptors->IsSortedNoDuplicates());
  int split_nof = split_map->NumberOfOwnDescriptors();
  int nof_descriptors = descriptors->number_of_descriptors();
  CHECK_LT(split_nof, nof_descriptors);

  // Start with creating last map which will own full descriptors array.
  // This is necessary to guarantee that GC will mark the whole descriptor
  // array if any of the allocations happening below fail.
  // Number of unused properties is temporarily incorrect and the layout
  // descriptor could unnecessarily be in slow mode but we will fix after
  // all the other intermediate maps are created.
  // Also the last map might have interesting symbols, we temporarily set
  // the flag and clear it right before the descriptors are installed. This
  // makes heap verification happy and ensures the flag ends up accurate.
  Handle<Map> last_map = CopyDropDescriptors(isolate, split_map);
  last_map->InitializeDescriptors(isolate, *descriptors);
  last_map->SetInObjectUnusedPropertyFields(0);
  last_map->set_may_have_interesting_properties(true);

  // During creation of intermediate maps we violate descriptors sharing
  // invariant since the last map is not yet connected to the transition tree
  // we create here. But it is safe because GC never trims map's descriptors
  // if there are no dead transitions from that map and this is exactly the
  // case for all the intermediate maps we create here.
  Handle<Map> map = split_map;
  for (InternalIndex i : InternalIndex::Range(split_nof, nof_descriptors - 1)) {
    Handle<Map> new_map = CopyDropDescriptors(isolate, map);
    // Force connection of these maps to prevent split_map being a root map to
    // be treated as detached.
    InstallDescriptors(isolate, map, new_map, i, descriptors,
                       /* force_connect */ true);
    DCHECK_EQ(*new_map->GetBackPointer(), *map);
    map = new_map;
  }
  map->NotifyLeafMapLayoutChange(isolate);
  last_map->set_may_have_interesting_properties(false);
  InstallDescriptors(isolate, map, last_map, InternalIndex(nof_descriptors - 1),
                     descriptors);
  return last_map;
}

// Since this method is used to rewrite an existing transition tree, it can
// always insert transitions without checking.
void Map::InstallDescriptors(Isolate* isolate, Handle<Map> parent,
                             Handle<Map> child, InternalIndex new_descriptor,
                             DirectHandle<DescriptorArray> descriptors,
                             bool force_connect) {
  DCHECK(descriptors->IsSortedNoDuplicates());

  child->SetInstanceDescriptors(isolate, *descriptors,
                                new_descriptor.as_int() + 1);
  child->CopyUnusedPropertyFields(*parent);
  PropertyDetails details = descriptors->GetDetails(new_descriptor);
  if (details.location() == PropertyLocation::kField) {
    child->AccountAddedPropertyField();
  }

  Handle<Name> name = handle(descriptors->GetKey(new_descriptor), isolate);
  if (parent->may_have_interesting_properties() ||
      name->IsInteresting(isolate)) {
    child->set_may_have_interesting_properties(true);
  }
  ConnectTransition(isolate, parent, child, name, SIMPLE_PROPERTY_TRANSITION,
                    force_connect);
}

Handle<Map> Map::CopyAsElementsKind(Isolate* isolate, Handle<Map> map,
                                    ElementsKind kind, TransitionFlag flag) {
  // Only certain objects are allowed to have non-terminal fast transitional
  // elements kinds.
  DCHECK(IsJSObjectMap(*map));
  DCHECK_IMPLIES(
      !map->CanHaveFastTransitionableElementsKind(),
      IsDictionaryElementsKind(kind) || IsTerminalElementsKind(kind));

  Tagged<Map> maybe_elements_transition_map;
  if (flag == INSERT_TRANSITION) {
    // Ensure we are requested to add elements kind transition "near the root".
    DCHECK_EQ(map->FindRootMap(isolate)->NumberOfOwnDescriptors(),
              map->NumberOfOwnDescriptors());

    maybe_elements_transition_map =
        map->ElementsTransitionMap(isolate, ConcurrencyMode::kSynchronous);
    DCHECK(maybe_elements_transition_map.is_null() ||
           (maybe_elements_transition_map->elements_kind() ==
                DICTIONARY_ELEMENTS &&
            kind == DICTIONARY_ELEMENTS));
    DCHECK(!IsFastElementsKind(kind) ||
           IsMoreGeneralElementsKindTransition(map->elements_kind(), kind));
    DCHECK(kind != map->elements_kind());
  }

  bool insert_transition =
      flag == INSERT_TRANSITION &&
      TransitionsAccessor::CanHaveMoreTransitions(isolate, map) &&
      maybe_elements_transition_map.is_null();

  if (insert_transition) {
    Handle<Map> new_map = CopyForElementsTransition(isolate, map);
    new_map->set_elements_kind(kind);

    Handle<Name> name = isolate->factory()->elements_transition_symbol();
    ConnectTransition(isolate, map, new_map, name, SPECIAL_TRANSITION);
    return new_map;
  }

  // Create a new free-floating map only if we are not allowed to store it.
  Handle<Map> new_map = Copy(isolate, map, "CopyAsElementsKind");
  new_map->set_elements_kind(kind);
  return new_map;
}

Handle<Map> Map::AsLanguageMode(Isolate* isolate, Handle<Map> initial_map,
                                DirectHandle<SharedFunctionInfo> shared_info) {
  DCHECK(InstanceTypeChecker::IsJSFunction(initial_map->instance_type()));
  // Initial map for sloppy mode function is stored in the function
  // constructor. Initial maps for strict mode are cached as special transitions
  // using |strict_function_transition_symbol| as a key.
  if (is_sloppy(shared_info->language_mode())) return initial_map;

  Handle<Map> function_map(Cast<Map>(isolate->native_context()->get(
                               shared_info->function_map_index())),
                           isolate);

  static_assert(LanguageModeSize == 2);
  DCHECK_EQ(LanguageMode::kStrict, shared_info->language_mode());
  Handle<Symbol> transition_symbol =
      isolate->factory()->strict_function_transition_symbol();
  MaybeHandle<Map> maybe_transition = TransitionsAccessor::SearchSpecial(
      isolate, initial_map, *tran
"""


```