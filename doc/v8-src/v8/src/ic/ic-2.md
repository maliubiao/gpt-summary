Response: The user wants a summary of the C++ source code file `v8/src/ic/ic.cc`. This is the third part of a three-part summary request. I need to focus on the functionality contained within this specific snippet of code.

Based on the code, the primary functionalities seem to revolve around:

1. **Fast object cloning:**  The code heavily discusses `FastCloneObjectMode`, `CanFastCloneObjectToObjectLiteral`, `CloneObjectSlowPath`, and related functions. This suggests the code is responsible for optimizing the process of creating copies of JavaScript objects.

2. **Inline caching (IC) related operations:**  The presence of `Runtime_CloneObjectIC_Slow`, `Runtime_CloneObjectIC_Miss`, `Runtime_KeyedHasIC_Miss` strongly indicates that this part of the code handles "misses" in the inline cache for object cloning and keyed property checks. It also manages updating the feedback vector based on these misses.

3. **Interceptor handling:** Functions like `Runtime_LoadPropertyWithInterceptor`, `Runtime_StorePropertyWithInterceptor`, and `Runtime_HasElementWithInterceptor` deal with property access and modification when interceptors are involved. Interceptors are a mechanism to hook into property access in JavaScript.

4. **Object.assign optimization:** The `Runtime_ObjectAssignTryFastcase` function attempts to optimize the `Object.assign()` operation by potentially using a faster cloning mechanism.

I will structure the summary by grouping these related functionalities and providing a high-level explanation. For the JavaScript examples, I'll choose simple scenarios that directly illustrate the concepts discussed in the C++ code.
这是 `v8/src/ic/ic.cc` 文件的第三部分，主要负责实现 V8 引擎中与对象克隆、属性访问（特别是涉及拦截器的情况）以及 `Object.assign` 优化相关的运行时功能。

**功能归纳:**

1. **快速对象克隆 (`FastCloneObject`):** 这部分代码的核心是优化 JavaScript 对象的克隆操作。它定义了不同的克隆模式 (`FastCloneObjectMode`)，并提供了检查对象是否可以进行快速克隆的函数 (`CanFastCloneObjectToObjectLiteral`, `GetCloneModeForMap`)。快速克隆旨在避免完整复制对象的所有属性，特别是当克隆的对象与源对象具有相似的结构时。

2. **对象克隆的内联缓存（IC）未命中处理:**  `Runtime_CloneObjectIC_Slow` 和 `Runtime_CloneObjectIC_Miss` 这两个运行时函数处理对象克隆操作在内联缓存中未命中的情况。`Runtime_CloneObjectIC_Miss` 尝试分析未命中的原因，并可能更新反馈向量，以便后续的克隆操作可以更快。如果无法进行快速克隆，则会调用 `Runtime_CloneObjectIC_Slow` 执行更慢但更通用的克隆方式。

3. **`Object.assign` 的优化:** `Runtime_ObjectAssignTryFastcase` 函数尝试优化 `Object.assign` 操作。它会检查源对象和目标对象是否满足特定的条件，如果满足，则可以采用更快的属性复制方式，甚至可以尝试直接克隆源对象的 Map。

4. **属性访问的拦截器处理:** 这部分代码包含了处理 JavaScript 对象属性访问中涉及拦截器（interceptors）的运行时函数。拦截器允许用户自定义属性的读取、写入和查询行为。
    - `Runtime_LoadPropertyWithInterceptor`: 处理带有拦截器的属性读取操作。
    - `Runtime_StorePropertyWithInterceptor`: 处理带有拦截器的属性写入操作。
    - `Runtime_LoadElementWithInterceptor`: 处理带有拦截器的数组元素读取操作。
    - `Runtime_HasElementWithInterceptor`: 处理带有拦截器的数组元素是否存在检查。

5. **键值 `HasProperty` 的内联缓存未命中处理:** `Runtime_KeyedHasIC_Miss` 函数处理在使用键值（例如数组索引或字符串键）检查对象是否具有某个属性时，内联缓存未命中的情况。它会更新反馈向量以优化后续的检查。

**与 JavaScript 功能的关系及示例:**

1. **快速对象克隆:**
   ```javascript
   const obj1 = { a: 1, b: 'hello' };
   const obj2 = { ...obj1 }; // 使用展开运算符进行浅拷贝

   // 或者使用 Object.assign
   const obj3 = Object.assign({}, obj1);
   ```
   V8 引擎在执行这些代码时，会尝试使用 `FastCloneObject` 优化 `obj2` 和 `obj3` 的创建。`GetCloneModeForMap` 等函数会分析 `obj1` 的结构，判断是否可以进行快速克隆。

2. **对象克隆的内联缓存（IC）未命中处理:**
   ```javascript
   function cloneObject(obj) {
     return { ...obj };
   }

   const initialObj = { x: 1 };
   cloneObject(initialObj); // 第一次调用可能导致 IC 未命中
   cloneObject(initialObj); // 第二次调用可能会命中 IC，如果引擎进行了优化
   ```
   `Runtime_CloneObjectIC_Miss` 在第一次调用 `cloneObject` 时可能会被调用，如果引擎无法快速判断如何克隆 `initialObj`。

3. **`Object.assign` 的优化:**
   ```javascript
   const target = {};
   const source = { c: 3, d: 4 };
   Object.assign(target, source);
   ```
   `Runtime_ObjectAssignTryFastcase` 会尝试快速地将 `source` 的属性复制到 `target`。

4. **属性访问的拦截器处理:**
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'prop', {
     get() {
       console.log('Getting prop!');
       return this._prop;
     },
     set(value) {
       console.log('Setting prop to', value);
       this._prop = value;
     }
   });

   obj.prop; // 调用 get 拦截器
   obj.prop = 5; // 调用 set 拦截器
   ```
   当访问或设置 `obj.prop` 时，由于定义了 getter 和 setter，V8 会调用 `Runtime_LoadPropertyWithInterceptor` 和 `Runtime_StorePropertyWithInterceptor` 来处理这些拦截器。

   对于使用 `Proxy` 的情况：
   ```javascript
   const obj = {};
   const proxy = new Proxy(obj, {
     get(target, prop) {
       console.log('Getting', prop);
       return target[prop];
     },
     set(target, prop, value) {
       console.log('Setting', prop, 'to', value);
       target[prop] = value;
       return true;
     }
   });

   proxy.name; // 触发 Proxy 的 get handler
   proxy.age = 30; // 触发 Proxy 的 set handler
   ```
   `Proxy` 的 handlers 也会导致类似的拦截器运行时函数的调用。

5. **键值 `HasProperty` 的内联缓存未命中处理:**
   ```javascript
   const arr = [1, 2, 3];
   'length' in arr; // 检查 'length' 属性是否存在
   2 in arr;       // 检查索引 2 是否存在

   const obj = { a: 1 };
   'a' in obj;       // 检查属性 'a' 是否存在
   'b' in obj;       // 检查属性 'b' 是否存在
   ```
   在执行 `in` 运算符时，如果 V8 引擎无法快速确定属性是否存在，`Runtime_KeyedHasIC_Miss` 可能会被调用。

总而言之，这部分 `ic.cc` 代码是 V8 引擎中负责优化对象操作（特别是克隆和属性访问）的关键组成部分，它通过内联缓存和对拦截器的处理来提升 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
ap> map,
                                       bool null_proto_literal,
                                       Isolate* isolate) {
  FastCloneObjectMode pre_check =
      GetCloneModeForMapPreCheck(map, null_proto_literal, isolate);
  if (pre_check != FastCloneObjectMode::kMaybeSupported) {
    return pre_check;
  }

  // The clone must always start from an object literal map, it must be an
  // instance of the object function, have the default prototype and not be a
  // prototype itself. Only if the source map fits that criterion we can
  // directly use it as the target map.
  FastCloneObjectMode mode =
      map->instance_type() == JS_OBJECT_TYPE &&
              !IsAnyNonextensibleElementsKind(map->elements_kind()) &&
              map->GetConstructor() == *isolate->object_function() &&
              map->prototype() == *isolate->object_function_prototype() &&
              !map->is_prototype_map()
          ? FastCloneObjectMode::kIdenticalMap
          : FastCloneObjectMode::kDifferentMap;

  if (null_proto_literal || IsNull(map->prototype())) {
    mode = FastCloneObjectMode::kDifferentMap;
  }

  Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    Tagged<Name> key = descriptors->GetKey(i);
    if (details.kind() != PropertyKind::kData || !details.IsEnumerable() ||
        key->IsPrivateName()) {
      return FastCloneObjectMode::kNotSupported;
    }
    if (!details.IsConfigurable() || details.IsReadOnly()) {
      mode = FastCloneObjectMode::kDifferentMap;
    }
  }

  DCHECK_IMPLIES(mode == FastCloneObjectMode::kIdenticalMap,
                 !map->is_prototype_map());

  return mode;
}

bool CanCacheCloneTargetMapTransition(
    DirectHandle<Map> source_map, std::optional<DirectHandle<Map>> target_map,
    bool null_proto_literal, Isolate* isolate) {
  if (!v8_flags.clone_object_sidestep_transitions || null_proto_literal) {
    return false;
  }
  // As of now any R/O source object should end up in the kEmptyObject case, but
  // there is not really a way of ensuring it. Thus, we also check it below.
  // This is a performance dcheck. If it fails, the clone IC does not handle a
  // case it probably could.
  // TODO(olivf): Either remove that dcheck or move it to GetCloneModeForMap.
  DCHECK(!HeapLayout::InReadOnlySpace(*source_map));
  if (HeapLayout::InReadOnlySpace(*source_map) || source_map->is_deprecated() ||
      source_map->is_prototype_map()) {
    return false;
  }
  if (!target_map) {
    return true;
  }
  CHECK(!HeapLayout::InReadOnlySpace(**target_map));
  return !(*target_map)->is_deprecated();
}

// Check if an object with `source_map` can be cloned by `FastCloneJSObject`
// when the result shall have `target_map`. Optionally `override_map` is the map
// of an already existing object that will be written into. If no `override_map`
// is given, we assume that a fresh target object can be allocated with
// already the correct `target_map`.
bool CanFastCloneObjectToObjectLiteral(DirectHandle<Map> source_map,
                                       DirectHandle<Map> target_map,
                                       DirectHandle<Map> override_map,
                                       bool null_proto_literal,
                                       Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  DCHECK(!target_map->is_deprecated());
  DCHECK(source_map->OnlyHasSimpleProperties());
  DCHECK(!source_map->IsInobjectSlackTrackingInProgress());
  DCHECK(!target_map->IsInobjectSlackTrackingInProgress());
  DCHECK_EQ(*target_map->map(), *source_map->map());
  DCHECK_EQ(target_map->GetConstructor(), *isolate->object_function());
  DCHECK_IMPLIES(
      !null_proto_literal,
      *target_map->prototype() == *isolate->object_function_prototype());

  // Ensure source and target have identical binary represenation of properties
  // and elements as the IC relies on copying the raw bytes. This also excludes
  // cases with non-enumerable properties or accessors on the source object.
  if (source_map->instance_type() != JS_OBJECT_TYPE ||
      target_map->instance_type() != JS_OBJECT_TYPE ||
      !target_map->OnlyHasSimpleProperties() ||
      !target_map->has_fast_elements()) {
    return false;
  }
  if (!override_map.is_null()) {
    // No cross-context object reuse.
    if (target_map->map() != override_map->map()) {
      return false;
    }
    // In case we want to clone into an existing target object, we must ensure
    // that this existing object has a compatible size. In particular we cannot
    // shrink or grow the already given object. We also exclude a different
    // start offset, since this doesn't allow us to change the object in-place
    // in a GC safe way.
    DCHECK_EQ(*override_map, isolate->object_function()->initial_map());
    DCHECK(override_map->instance_type() == JS_OBJECT_TYPE);
    DCHECK_EQ(override_map->NumberOfOwnDescriptors(), 0);
    DCHECK(!override_map->IsInobjectSlackTrackingInProgress());
    if (override_map->instance_size() != target_map->instance_size() ||
        override_map->GetInObjectPropertiesStartInWords() !=
            target_map->GetInObjectPropertiesStartInWords()) {
      return false;
    }
  }
#ifdef DEBUG
  ElementsKind source_elements_kind = source_map->elements_kind();
  ElementsKind target_elements_kind = target_map->elements_kind();
  DCHECK(IsSmiOrObjectElementsKind(source_elements_kind) ||
         IsAnyNonextensibleElementsKind(source_elements_kind));
  DCHECK(IsSmiOrObjectElementsKind(target_elements_kind));
  DCHECK_IMPLIES(IsHoleyElementsKindForRead(source_elements_kind),
                 IsHoleyElementsKind(target_elements_kind));
#endif  // DEBUG
  // There are no transitions between prototype maps.
  if (source_map->is_prototype_map() || target_map->is_prototype_map()) {
    return false;
  }
  // Exclude edge-cases like not copying a __proto__ property.
  if (source_map->NumberOfOwnDescriptors() !=
      target_map->NumberOfOwnDescriptors()) {
    return false;
  }
  // Check that the source inobject properties fit into the target.
  int source_used_inobj_properties = source_map->GetInObjectProperties() -
                                     source_map->UnusedInObjectProperties();
  int target_used_inobj_properties = target_map->GetInObjectProperties() -
                                     target_map->UnusedInObjectProperties();
  if (source_used_inobj_properties != target_used_inobj_properties) {
    return false;
  }
  // The properties backing store must be of the same size as the clone ic again
  // blindly copies it.
  if (source_map->HasOutOfObjectProperties() !=
          target_map->HasOutOfObjectProperties() ||
      (target_map->HasOutOfObjectProperties() &&
       source_map->UnusedPropertyFields() !=
           target_map->UnusedPropertyFields())) {
    return false;
  }
  Tagged<DescriptorArray> descriptors = source_map->instance_descriptors();
  Tagged<DescriptorArray> target_descriptors =
      target_map->instance_descriptors();
  for (InternalIndex i : target_map->IterateOwnDescriptors()) {
    if (descriptors->GetKey(i) != target_descriptors->GetKey(i)) {
      return false;
    }
    PropertyDetails details = descriptors->GetDetails(i);
    PropertyDetails target_details = target_descriptors->GetDetails(i);
    DCHECK_EQ(details.kind(), PropertyKind::kData);
    DCHECK_EQ(target_details.kind(), PropertyKind::kData);
    Tagged<FieldType> type = descriptors->GetFieldType(i);
    Tagged<FieldType> target_type = target_descriptors->GetFieldType(i);
    // This DCHECK rests on the fact that we only clear field types when there
    // are no instances of the host map left. Thus, to enter the clone IC at
    // least one object of the source map needs to be created, which in turn
    // will re-initialize the source maps field type. This is guaranteed to also
    // update the target map through the sidestep transition, unless the target
    // map is deprecated.
    DCHECK(!IsNone(type));
    DCHECK(!IsNone(target_type));
    // With move_prototype_transitions_first enabled field updates don't
    // generalize across prototype transitions, because the transitions happen
    // on root maps (i.e., before any field is added). In other words we cannot
    // rely on changes in the source map propagating to the target map when
    // there is a SetPrototype involved. NB, technically without
    // move_prototype_transitions_first we also don't update field types across
    // prototype transitions, however we preemptively generalize all fields of
    // prototype transition target maps.
    bool prototype_transition_is_shortcutted =
        v8_flags.move_prototype_transitions_first &&
        source_map->prototype() != target_map->prototype();
    if (!prototype_transition_is_shortcutted &&
        CanCacheCloneTargetMapTransition(source_map, target_map,
                                         null_proto_literal, isolate)) {
      if (!details.representation().fits_into(
              target_details.representation()) ||
          (target_details.representation().IsDouble() &&
           details.representation().IsSmi())) {
        return false;
      }
      if (!FieldType::NowIs(type, target_type)) {
        return false;
      }
    } else {
      // In the case we cannot connect the maps in the transition tree (e.g.,
      // the clone also involves a proto transition) we cannot keep track of
      // representation dependencies. We can only allow the most generic target
      // representation. The same goes for field types.
      if (!details.representation().MostGenericInPlaceChange().Equals(
              target_details.representation()) ||
          !IsAny(target_type)) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace

static MaybeHandle<JSObject> CloneObjectSlowPath(Isolate* isolate,
                                                 Handle<Object> source,
                                                 int flags) {
  Handle<JSObject> new_object;
  if (flags & ObjectLiteral::kHasNullPrototype) {
    new_object = isolate->factory()->NewJSObjectWithNullProto();
  } else if (IsJSObject(*source) &&
             Cast<JSObject>(*source)->map()->OnlyHasSimpleProperties()) {
    Tagged<Map> source_map = Cast<JSObject>(*source)->map();
    // TODO(olivf, chrome:1204540) It might be interesting to pick a map with
    // more properties, depending how many properties are added by the
    // surrounding literal.
    int properties = source_map->GetInObjectProperties() -
                     source_map->UnusedInObjectProperties();
    DirectHandle<Map> map = isolate->factory()->ObjectLiteralMapFromCache(
        isolate->native_context(), properties);
    new_object = isolate->factory()->NewFastOrSlowJSObjectFromMap(map);
  } else {
    Handle<JSFunction> constructor(isolate->native_context()->object_function(),
                                   isolate);
    new_object = isolate->factory()->NewJSObject(constructor);
  }

  if (IsNullOrUndefined(*source)) {
    return new_object;
  }

  MAYBE_RETURN(
      JSReceiver::SetOrCopyDataProperties(
          isolate, new_object, source,
          PropertiesEnumerationMode::kPropertyAdditionOrder, {}, false),
      MaybeHandle<JSObject>());
  return new_object;
}

RUNTIME_FUNCTION(Runtime_CloneObjectIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> source = args.at(0);
  int flags = args.smi_value_at(1);
  RETURN_RESULT_OR_FAILURE(isolate,
                           CloneObjectSlowPath(isolate, source, flags));
}

namespace {

template <SideStepTransition::Kind kind>
Tagged<Object> GetCloneTargetMap(Isolate* isolate, DirectHandle<Map> source_map,
                                 DirectHandle<Map> override_map) {
  static_assert(kind == SideStepTransition::Kind::kObjectAssign ||
                kind == SideStepTransition::Kind::kCloneObject);
  if (!v8_flags.clone_object_sidestep_transitions) {
    return SideStepTransition::Empty;
  }

  // Ensure we can follow the sidestep transition NativeContext-wise.
  if (!source_map->BelongsToSameNativeContextAs(isolate->context())) {
    return SideStepTransition::Empty;
  }
  Tagged<Object> result = SideStepTransition::Empty;
  TransitionsAccessor transitions(isolate, *source_map);
  if (transitions.HasSideStepTransitions()) {
    result = transitions.GetSideStepTransition(kind);
    if (result.IsHeapObject()) {
      // Exclude deprecated maps.
      auto map = Cast<Map>(result.GetHeapObject());
      bool is_valid = !map->is_deprecated();
      // In the case of object assign we need to check the prototype validity
      // cell on the override map. If the override map changed we cannot assume
      // that it is correct to set all properties without any getter/setter in
      // the prototype chain interfering.
      if constexpr (kind == SideStepTransition::Kind::kObjectAssign) {
        if (is_valid) {
          DCHECK_EQ(*override_map, isolate->object_function()->initial_map());
          Tagged<Object> validity_cell = transitions.GetSideStepTransition(
              SideStepTransition::Kind::kObjectAssignValidityCell);
          is_valid = validity_cell.IsHeapObject() &&
                     Cast<Cell>(validity_cell)->value().ToSmi().value() ==
                         Map::kPrototypeChainValid;
        }
      }
      if (V8_LIKELY(is_valid)) {
        if (result.IsHeapObject()) {
          CHECK_EQ(GetCloneModeForMapPreCheck(source_map, false, isolate),
                   FastCloneObjectMode::kMaybeSupported);
        }
      } else {
        result = SideStepTransition::Empty;
      }
    }
  }
#ifdef DEBUG
  FastCloneObjectMode clone_mode =
      GetCloneModeForMap(source_map, false, isolate);
  if (result == SideStepTransition::Unreachable) {
    switch (clone_mode) {
      case FastCloneObjectMode::kNotSupported:
      case FastCloneObjectMode::kDifferentMap:
        break;
      case FastCloneObjectMode::kEmptyObject:
      case FastCloneObjectMode::kIdenticalMap:
        DCHECK_EQ(kind, SideStepTransition::Kind::kObjectAssign);
        break;
      case FastCloneObjectMode::kMaybeSupported:
        UNREACHABLE();
    }
  } else if (result != SideStepTransition::Empty) {
    Tagged<Map> target = Cast<Map>(result.GetHeapObject());
    switch (clone_mode) {
      case FastCloneObjectMode::kIdenticalMap:
        if (kind == SideStepTransition::Kind::kCloneObject) {
          DCHECK_EQ(*source_map, target);
          break;
        }
        DCHECK_EQ(kind, SideStepTransition::Kind::kObjectAssign);
        [[fallthrough]];
      case FastCloneObjectMode::kDifferentMap:
        DCHECK(CanFastCloneObjectToObjectLiteral(
            source_map, handle(target, isolate), override_map, false, isolate));
        break;
      default:
        UNREACHABLE();
    }
  } else {
    DCHECK_EQ(result, SideStepTransition::Empty);
  }
#endif  // DEBUG
  return result;
}

template <SideStepTransition::Kind kind>
void SetCloneTargetMap(Isolate* isolate, Handle<Map> source_map,
                       DirectHandle<Map> new_target_map,
                       DirectHandle<Map> override_map) {
  if (!v8_flags.clone_object_sidestep_transitions) return;
  DCHECK(CanCacheCloneTargetMapTransition(source_map, new_target_map, false,
                                          isolate));
  DCHECK_EQ(GetCloneTargetMap<kind>(isolate, source_map, override_map),
            SideStepTransition::Empty);
  DCHECK(!new_target_map->is_deprecated());

  // Adding this transition also ensures that when the source map field
  // generalizes, we also generalize the target map.
  DCHECK(IsSmiOrObjectElementsKind(new_target_map->elements_kind()));

  constexpr bool need_validity_cell =
      kind == SideStepTransition::Kind::kObjectAssign;
  DirectHandle<Cell> validity_cell;
  if constexpr (need_validity_cell) {
    // Since we only clone into empty object literals we only need one validity
    // cell on that prototype chain.
    DCHECK_EQ(*override_map, isolate->object_function()->initial_map());
    validity_cell = Cast<Cell>(
        Map::GetOrCreatePrototypeChainValidityCell(override_map, isolate));
  }
  TransitionsAccessor::EnsureHasSideStepTransitions(isolate, source_map);
  TransitionsAccessor transitions(isolate, *source_map);
  transitions.SetSideStepTransition(kind, *new_target_map);
  if constexpr (need_validity_cell) {
    transitions.SetSideStepTransition(
        SideStepTransition::Kind::kObjectAssignValidityCell, *validity_cell);
  }
  DCHECK_EQ(GetCloneTargetMap<kind>(isolate, source_map, override_map),
            *new_target_map);
}

template <SideStepTransition::Kind kind>
void SetCloneTargetMapUnsupported(Isolate* isolate, Handle<Map> source_map,
                                  DirectHandle<Map> override_map) {
  if (!v8_flags.clone_object_sidestep_transitions) return;
  DCHECK_EQ(GetCloneTargetMap<kind>(isolate, source_map, override_map),
            SideStepTransition::Empty);
  DCHECK(CanCacheCloneTargetMapTransition(source_map, {}, false, isolate));
  // Adding this transition also ensures that when the source map field
  // generalizes, we also generalize the target map.
  TransitionsAccessor::EnsureHasSideStepTransitions(isolate, source_map);
  TransitionsAccessor(isolate, *source_map)
      .SetSideStepTransition(kind, SideStepTransition::Unreachable);
  DCHECK_EQ(GetCloneTargetMap<kind>(isolate, source_map, override_map),
            SideStepTransition::Unreachable);
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CloneObjectIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<Object> source = args.at(0);
  int flags = args.smi_value_at(1);

  if (!MigrateDeprecated(isolate, source)) {
    Handle<HeapObject> maybe_vector = args.at<HeapObject>(3);
    std::optional<FeedbackNexus> nexus;
    if (IsFeedbackVector(*maybe_vector)) {
      int index = args.tagged_index_value_at(2);
      FeedbackSlot slot = FeedbackVector::ToSlot(index);
      nexus.emplace(isolate, Cast<FeedbackVector>(maybe_vector), slot);
    }
    if (!IsSmi(*source) && (!nexus || !nexus->IsMegamorphic())) {
      bool null_proto_literal = flags & ObjectLiteral::kHasNullPrototype;
      Handle<Map> source_map(Cast<HeapObject>(source)->map(), isolate);

      // In case we are still slack tracking let's defer a decision. The fast
      // case does not support it.
      if (!source_map->IsInobjectSlackTrackingInProgress()) {
        auto UpdateNexus = [&](Handle<Object> target_map) {
          if (!nexus) return;
          nexus->ConfigureCloneObject(source_map,
                                      MaybeObjectHandle(target_map));
        };
        ReadOnlyRoots roots(isolate);
        bool unsupported = false;
        if (!null_proto_literal) {
          auto maybe_target =
              GetCloneTargetMap<SideStepTransition::Kind::kCloneObject>(
                  isolate, source_map, {});
          if (maybe_target == SideStepTransition::Unreachable) {
            unsupported = true;
          } else if (maybe_target != SideStepTransition::Empty) {
            Handle<Map> target =
                handle(Cast<Map>(maybe_target.GetHeapObject()), isolate);
            UpdateNexus(target);
            return *target;
          }
        }

        FastCloneObjectMode clone_mode =
            unsupported
                ? FastCloneObjectMode::kNotSupported
                : GetCloneModeForMap(source_map, null_proto_literal, isolate);
        auto UpdateState = [&](Handle<Map> target_map) {
          UpdateNexus(target_map);
          if (CanCacheCloneTargetMapTransition(source_map, target_map,
                                               null_proto_literal, isolate)) {
            SetCloneTargetMap<SideStepTransition::Kind::kCloneObject>(
                isolate, source_map, target_map, {});
          }
        };
        switch (clone_mode) {
          case FastCloneObjectMode::kIdenticalMap: {
            UpdateState(source_map);
            // When returning a map the IC miss handler re-starts from the top.
            return *source_map;
          }
          case FastCloneObjectMode::kEmptyObject: {
            UpdateNexus(handle(Smi::zero(), isolate));
            RETURN_RESULT_OR_FAILURE(
                isolate, CloneObjectSlowPath(isolate, source, flags));
          }
          case FastCloneObjectMode::kDifferentMap: {
            Handle<Object> res;
            ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                isolate, res, CloneObjectSlowPath(isolate, source, flags));
            Handle<Map> result_map(Cast<HeapObject>(res)->map(), isolate);
            if (result_map->IsInobjectSlackTrackingInProgress()) {
              return *res;
            }
            if (CanFastCloneObjectToObjectLiteral(
                    source_map, result_map, {}, null_proto_literal, isolate)) {
              DCHECK(result_map->OnlyHasSimpleProperties());
              DCHECK_EQ(source_map->GetInObjectProperties() -
                            source_map->UnusedInObjectProperties(),
                        result_map->GetInObjectProperties() -
                            result_map->UnusedInObjectProperties());
              UpdateState(result_map);
            } else {
              if (CanCacheCloneTargetMapTransition(
                      source_map, {}, null_proto_literal, isolate)) {
                SetCloneTargetMapUnsupported<
                    SideStepTransition::Kind::kCloneObject>(isolate, source_map,
                                                            {});
              }
              if (nexus) {
                nexus->ConfigureMegamorphic();
              }
            }
            return *res;
          }
          case FastCloneObjectMode::kNotSupported: {
            break;
          }
          case FastCloneObjectMode::kMaybeSupported:
            UNREACHABLE();
        }
        DCHECK(clone_mode == FastCloneObjectMode::kNotSupported);
        if (nexus) {
          nexus->ConfigureMegamorphic();
        }
      }
    }
  }

  RETURN_RESULT_OR_FAILURE(isolate,
                           CloneObjectSlowPath(isolate, source, flags));
}

RUNTIME_FUNCTION(Runtime_StoreCallbackProperty) {
  Handle<JSObject> receiver = args.at<JSObject>(0);
  DirectHandle<JSObject> holder = args.at<JSObject>(1);
  DirectHandle<AccessorInfo> info = args.at<AccessorInfo>(2);
  Handle<Name> name = args.at<Name>(3);
  Handle<Object> value = args.at(4);
  HandleScope scope(isolate);

#ifdef V8_RUNTIME_CALL_STATS
  if (V8_UNLIKELY(TracingFlags::is_runtime_stats_enabled())) {
    RETURN_RESULT_OR_FAILURE(
        isolate, Runtime::SetObjectProperty(isolate, receiver, name, value,
                                            StoreOrigin::kMaybeKeyed));
  }
#endif

  PropertyCallbackArguments arguments(isolate, info->data(), *receiver, *holder,
                                      Nothing<ShouldThrow>());
  std::ignore = arguments.CallAccessorSetter(info, name, value);
  RETURN_FAILURE_IF_EXCEPTION(isolate);
  return *value;
}

namespace {

bool MaybeCanCloneObjectForObjectAssign(Handle<JSReceiver> source,
                                        DirectHandle<Map> source_map,
                                        Handle<JSReceiver> target,
                                        Isolate* isolate) {
  FastCloneObjectMode clone_mode =
      GetCloneModeForMap(source_map, false, isolate);
  switch (clone_mode) {
    case FastCloneObjectMode::kIdenticalMap:
    case FastCloneObjectMode::kDifferentMap:
      break;
    case FastCloneObjectMode::kNotSupported:
      return false;
    case FastCloneObjectMode::kEmptyObject:
    case FastCloneObjectMode::kMaybeSupported:
      // Cannot happen since we should only be called with JSObjects.
      UNREACHABLE();
  }

  // We need to be sure that there are no setters or other nastiness installed
  // on the Object.prototype which clash with the properties we intende to copy.
  Handle<FixedArray> keys;
  auto res =
      KeyAccumulator::GetKeys(isolate, source, KeyCollectionMode::kOwnOnly,
                              ONLY_ENUMERABLE, GetKeysConversion::kKeepNumbers);
  CHECK(res.ToHandle(&keys));
  for (int i = 0; i < keys->length(); ++i) {
    Handle<Object> next_key(keys->get(i), isolate);
    PropertyKey key(isolate, next_key);
    LookupIterator it(isolate, target, key);
    switch (it.state()) {
      case LookupIterator::NOT_FOUND:
        break;
      case LookupIterator::DATA:
        if (it.property_attributes() & PropertyAttributes::READ_ONLY) {
          return false;
        }
        break;
      default:
        return false;
    }
  }
  return true;
}

}  // namespace

// Returns one of:
// * A map to be used with FastCloneJSObject
// * Undefined if fast cloning is not possible
// * True if assignment must be skipped (i.e., the runtime already did it)
RUNTIME_FUNCTION(Runtime_ObjectAssignTryFastcase) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  auto source = Cast<JSReceiver>(args.at(0));
  auto target = Cast<JSReceiver>(args.at(1));
  DCHECK(IsJSObject(*source));
  DCHECK(IsJSObject(*target));

  Handle<Map> source_map = handle(source->map(), isolate);
  Handle<Map> target_map = handle(target->map(), isolate);

  DCHECK_EQ(target_map->NumberOfOwnDescriptors(), 0);
  DCHECK(!source_map->is_dictionary_map());
  DCHECK(!target_map->is_dictionary_map());
  DCHECK(!source_map->is_deprecated());
  DCHECK(!target_map->is_deprecated());
  DCHECK(target_map->is_extensible());
  DCHECK(!IsUndefined(*source, isolate) && !IsNull(*source, isolate));
  DCHECK(source_map->BelongsToSameNativeContextAs(isolate->context()));

  ReadOnlyRoots roots(isolate);
  {
    Tagged<Object> maybe_clone_target =
        GetCloneTargetMap<SideStepTransition::Kind::kObjectAssign>(
            isolate, source_map, target_map);
    if (maybe_clone_target == SideStepTransition::Unreachable) {
      return roots.undefined_value();
    } else if (maybe_clone_target != SideStepTransition::Empty) {
      return Cast<Map>(maybe_clone_target.GetHeapObject());
    }
  }

  auto UpdateCache = [&](Handle<Map> clone_target_map) {
    if (CanCacheCloneTargetMapTransition(source_map, clone_target_map, false,
                                         isolate)) {
      SetCloneTargetMap<SideStepTransition::Kind::kObjectAssign>(
          isolate, source_map, clone_target_map, target_map);
    }
  };
  auto UpdateCacheNotClonable = [&]() {
    if (CanCacheCloneTargetMapTransition(source_map, {}, false, isolate)) {
      SetCloneTargetMapUnsupported<SideStepTransition::Kind::kObjectAssign>(
          isolate, source_map, target_map);
    }
  };

  // In case we are still slack tracking let's defer a decision. The fast case
  // does not support it.
  if (source_map->IsInobjectSlackTrackingInProgress() ||
      target_map->IsInobjectSlackTrackingInProgress()) {
    return roots.undefined_value();
  }

  if (MaybeCanCloneObjectForObjectAssign(source, source_map, target, isolate)) {
    CHECK(target->map()->OnlyHasSimpleProperties());
    Maybe<bool> res = JSReceiver::SetOrCopyDataProperties(
        isolate, target, source, PropertiesEnumerationMode::kEnumerationOrder);
    DCHECK(res.FromJust());
    USE(res);
    Handle<Map> clone_target_map = handle(target->map(), isolate);
    if (clone_target_map->IsInobjectSlackTrackingInProgress()) {
      return roots.true_value();
    }
    if (CanFastCloneObjectToObjectLiteral(source_map, clone_target_map,
                                          target_map, false, isolate)) {
      CHECK(target->map()->OnlyHasSimpleProperties());
      UpdateCache(clone_target_map);
    } else {
      UpdateCacheNotClonable();
    }
    // We already did the copying here. Thus, returning true to cause the
    // CSA builtin to skip assigning anything.
    return roots.true_value();
  }
  UpdateCacheNotClonable();
  return roots.undefined_value();
}

/**
 * Loads a property with an interceptor performing post interceptor
 * lookup if interceptor failed.
 */
RUNTIME_FUNCTION(Runtime_LoadPropertyWithInterceptor) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<Name> name = args.at<Name>(0);
  Handle<Object> receiver_arg = args.at(1);
  Handle<JSObject> holder = args.at<JSObject>(2);

  Handle<JSReceiver> receiver;
  if (!TryCast<JSReceiver>(receiver_arg, &receiver)) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, receiver, Object::ConvertReceiver(isolate, receiver_arg));
  }

  {
    Handle<InterceptorInfo> interceptor(holder->GetNamedInterceptor(), isolate);
    PropertyCallbackArguments arguments(isolate, interceptor->data(), *receiver,
                                        *holder, Just(kDontThrow));

    Handle<Object> result = arguments.CallNamedGetter(interceptor, name);
    // An exception was thrown in the interceptor. Propagate.
    RETURN_FAILURE_IF_EXCEPTION_DETECTOR(isolate, arguments);

    if (!result.is_null()) {
      arguments.AcceptSideEffects();
      return *result;
    }
    // If the interceptor didn't handle the request, then there must be no
    // side effects.
  }

  LookupIterator it(isolate, receiver, name, holder);
  // Skip any lookup work until we hit the (possibly non-masking) interceptor.
  while (it.state() != LookupIterator::INTERCEPTOR ||
         !it.GetHolder<JSObject>().is_identical_to(holder)) {
    DCHECK(it.state() != LookupIterator::ACCESS_CHECK || it.HasAccess());
    it.Next();
  }
  // Skip past the interceptor.
  it.Next();
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, Object::GetProperty(&it));

  if (it.IsFound()) return *result;

  int slot = args.tagged_index_value_at(3);
  DirectHandle<FeedbackVector> vector = args.at<FeedbackVector>(4);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind slot_kind = vector->GetKind(vector_slot);
  // It could actually be any kind of load IC slot here but the predicate
  // handles all the cases properly.
  if (!LoadIC::ShouldThrowReferenceError(slot_kind)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Throw a reference error.
  THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewReferenceError(MessageTemplate::kNotDefined, it.name()));
}

RUNTIME_FUNCTION(Runtime_StorePropertyWithInterceptor) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<JSObject> receiver = args.at<JSObject>(1);
  Handle<Name> name = args.at<Name>(2);

  // TODO(ishell): Cache interceptor_holder in the store handler like we do
  // for LoadHandler::kInterceptor case.
  DirectHandle<JSObject> interceptor_holder = receiver;
  if (IsJSGlobalProxy(*receiver) &&
      (!receiver->HasNamedInterceptor() ||
       receiver->GetNamedInterceptor()->non_masking())) {
    interceptor_holder =
        handle(Cast<JSObject>(receiver->map()->prototype()), isolate);
  }
  DCHECK(interceptor_holder->HasNamedInterceptor());
  {
    DirectHandle<InterceptorInfo> interceptor(
        interceptor_holder->GetNamedInterceptor(), isolate);

    DCHECK(!interceptor->non_masking());
    // TODO(ishell, 348688196): why is it known that it shouldn't throw?
    Maybe<ShouldThrow> should_throw = Just(kDontThrow);
    PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                   *receiver, should_throw);

    v8::Intercepted intercepted =
        args.CallNamedSetter(interceptor, name, value);
    // Stores initiated by StoreICs don't care about the exact result of
    // the store operation returned by the callback as long as it doesn't
    // throw an exception.
    constexpr bool ignore_return_value = true;
    InterceptorResult result;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result,
        args.GetBooleanReturnValue(intercepted, "Setter", ignore_return_value));

    switch (result) {
      case InterceptorResult::kFalse:
      case InterceptorResult::kTrue:
        return *value;

      case InterceptorResult::kNotIntercepted:
        // Proceed storing past the interceptor.
        break;
    }
  }

  LookupIterator it(isolate, receiver, name, receiver);
  // Skip past any access check on the receiver.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    DCHECK(it.HasAccess());
    it.Next();
  }
  // Skip past the interceptor on the receiver.
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it.state());
  it.Next();

  MAYBE_RETURN(Object::SetProperty(&it, value, StoreOrigin::kNamed),
               ReadOnlyRoots(isolate).exception());
  return *value;
}

RUNTIME_FUNCTION(Runtime_LoadElementWithInterceptor) {
  // TODO(verwaest): This should probably get the holder and receiver as input.
  HandleScope scope(isolate);
  Handle<JSObject> receiver = args.at<JSObject>(0);
  DCHECK_GE(args.smi_value_at(1), 0);
  uint32_t index = args.smi_value_at(1);

  Handle<InterceptorInfo> interceptor(receiver->GetIndexedInterceptor(),
                                      isolate);
  PropertyCallbackArguments arguments(isolate, interceptor->data(), *receiver,
                                      *receiver, Just(kDontThrow));
  Handle<Object> result = arguments.CallIndexedGetter(interceptor, index);
  // An exception was thrown in the interceptor. Propagate.
  RETURN_FAILURE_IF_EXCEPTION_DETECTOR(isolate, arguments);

  if (result.is_null()) {
    LookupIterator it(isolate, receiver, index, receiver);
    DCHECK_EQ(LookupIterator::INTERCEPTOR, it.state());
    it.Next();
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result,
                                       Object::GetProperty(&it));
  }

  return *result;
}

RUNTIME_FUNCTION(Runtime_KeyedHasIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  int slot = args.tagged_index_value_at(2);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(3);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  KeyedLoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kHasKeyed);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
}

RUNTIME_FUNCTION(Runtime_HasElementWithInterceptor) {
  HandleScope scope(isolate);
  Handle<JSObject> receiver = args.at<JSObject>(0);
  DCHECK_GE(args.smi_value_at(1), 0);
  uint32_t index = args.smi_value_at(1);

  {
    Handle<InterceptorInfo> interceptor(receiver->GetIndexedInterceptor(),
                                        isolate);
    PropertyCallbackArguments arguments(isolate, interceptor->data(), *receiver,
                                        *receiver, Just(kDontThrow));

    if (!IsUndefined(interceptor->query(), isolate)) {
      Handle<Object> result = arguments.CallIndexedQuery(interceptor, index);
      // An exception was thrown in the interceptor. Propagate.
      RETURN_FAILURE_IF_EXCEPTION_DETECTOR(isolate, arguments);
      if (!result.is_null()) {
        int32_t value;
        CHECK(Object::ToInt32(*result, &value));
        // TODO(ishell): PropertyAttributes::ABSENT is not exposed in the Api,
        // so it can't be officially returned. We should fix the tests instead.
        if (value == ABSENT) return ReadOnlyRoots(isolate).false_value();
        arguments.AcceptSideEffects();
        return ReadOnlyRoots(isolate).true_value();
      }
    } else if (!IsUndefined(interceptor->getter(), isolate)) {
      Handle<Object> result = arguments.CallIndexedGetter(interceptor, index);
      // An exception was thrown in the interceptor. Propagate.
      RETURN_FAILURE_IF_EXCEPTION_DETECTOR(isolate, arguments);
      if (!result.is_null()) {
        arguments.AcceptSideEffects();
        return ReadOnlyRoots(isolate).true_value();
      }
    }
    // If the interceptor didn't handle the request, then there must be no
    // side effects.
  }

  LookupIterator it(isolate, receiver, index, receiver);
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it.state());
  it.Next();
  Maybe<bool> maybe = JSReceiver::HasProperty(&it);
  if (maybe.IsNothing()) return ReadOnlyRoots(isolate).exception();
  return ReadOnlyRoots(isolate).boolean_value(maybe.FromJust());
}

}  // namespace internal
}  // namespace v8

"""


```