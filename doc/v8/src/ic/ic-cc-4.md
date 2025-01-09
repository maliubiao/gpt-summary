Response:
My thought process for analyzing the provided V8 source code snippet goes like this:

1. **Understand the Request:** The request asks for a breakdown of the functionality of the given `v8/src/ic/ic.cc` code, specifically focusing on:
    * General functionality.
    * Whether it's Torque code (based on file extension).
    * Connections to JavaScript features (with examples).
    * Logical deductions (input/output).
    * Common user programming errors.
    * A summary of its purpose (as part 5 of 6).

2. **Initial Code Scan:** I'll quickly scan the code for keywords and patterns:
    * `FastCloneObjectMode`, `CanFastCloneObjectToObjectLiteral`, `CloneObjectSlowPath`, `Runtime_CloneObjectIC_Slow`, `Runtime_CloneObjectIC_Miss`, `Runtime_StoreCallbackProperty`, `Runtime_ObjectAssignTryFastcase`, `Runtime_LoadPropertyWithInterceptor`, `Runtime_StorePropertyWithInterceptor`. These strongly suggest the code is related to object cloning and property access optimization within V8's IC (Inline Cache) system.
    * No `.tq` extension is mentioned, so it's likely regular C++ code.
    * The presence of `RUNTIME_FUNCTION` macros points to runtime functions that are called from JavaScript.

3. **Deconstruct Function by Function:** I'll analyze each function individually to understand its specific role:

    * **`GetCloneModeForMap`:**  This function determines if an object with a given `map` can be fast-cloned. It checks various map properties like instance type, elements kind, constructor, prototype, and descriptors (enumerable, configurable, read-only). The logic revolves around identifying maps suitable for direct byte-level copying during cloning. *Hypothesis:*  It's a pre-check function to optimize object literal cloning.

    * **`CanCacheCloneTargetMapTransition`:** This function checks if the transition from a source map to a target map during cloning can be cached. It considers factors like read-only status, deprecation, and whether a target map exists. *Hypothesis:* It aims to improve cloning performance by reusing successful transitions.

    * **`CanFastCloneObjectToObjectLiteral`:** This function is a more detailed check for fast cloning into an object literal. It verifies the compatibility of source and target maps, including binary representation of properties, elements kind, in-object properties layout, and descriptor details (keys, details, field types). The `override_map` parameter suggests handling cases where cloning overwrites an existing object. *Hypothesis:* It determines if a fast byte-copy can occur when cloning into a newly created or existing object literal.

    * **`CloneObjectSlowPath`:** This function handles the slower, more general object cloning process. It creates a new object (potentially with a null prototype) and then copies properties from the source object. It's used when fast cloning isn't possible. *Hypothesis:* This is the fallback mechanism when fast-cloning conditions aren't met.

    * **`Runtime_CloneObjectIC_Slow`:** This is a runtime function that wraps `CloneObjectSlowPath`, making it callable from JavaScript. *Connection to JavaScript:* Directly used when a JavaScript `Object.assign()` or object literal creation triggers the slow-path cloning.

    * **`GetCloneTargetMap` and `SetCloneTargetMap`/`SetCloneTargetMapUnsupported`:** These template functions deal with caching target maps for cloning operations using "sidestep transitions." They store information about successful clone transitions to optimize future cloning of similar objects. The `SideStepTransition` enum indicates different cloning contexts (like `Object.assign` and direct cloning). *Hypothesis:*  This is a mechanism for optimizing cloning by caching successful transitions between object shapes (Maps).

    * **`Runtime_CloneObjectIC_Miss`:** This runtime function is invoked when the inline cache for object cloning misses. It tries to update the cache based on the source object's map and then either performs a fast clone (by returning the target map for a re-attempt) or falls back to the slow path. *Connection to JavaScript:*  Called when the V8 engine can't immediately determine the best way to clone an object.

    * **`Runtime_StoreCallbackProperty`:** This runtime function handles storing a property that involves an accessor (getter/setter). It calls the accessor's setter function. *Connection to JavaScript:* Directly related to how JavaScript setters are invoked during property assignment.

    * **`MaybeCanCloneObjectForObjectAssign`:** This function checks if an object can be fast-cloned within the context of `Object.assign`. It has similar checks to `GetCloneModeForMap` but also considers potential conflicts with properties on the target object's prototype chain. *Hypothesis:*  Specifically for optimizing `Object.assign`.

    * **`Runtime_ObjectAssignTryFastcase`:** This runtime function attempts a fast path for `Object.assign`. It checks if fast cloning is possible, performs the copy if it is, and updates the cache. *Connection to JavaScript:* Directly related to the `Object.assign()` method.

    * **`Runtime_LoadPropertyWithInterceptor`:** This function handles loading a property that might involve an interceptor (a mechanism for dynamically handling property access). It calls the interceptor's getter if present. *Connection to JavaScript:*  Related to the use of `__lookupGetter__` and other forms of dynamic property interception in older JavaScript or within V8's internal workings.

    * **`Runtime_StorePropertyWithInterceptor`:** This function handles storing a property that might involve an interceptor. It calls the interceptor's setter. *Connection to JavaScript:* Related to `__lookupSetter__` and dynamic property interception.

4. **Synthesize and Organize:** Now I'll group the findings and formulate the answers to the specific parts of the request:

    * **Functionality:** Group related functions together (cloning, property access with interceptors). Emphasize the optimization aspect (fast paths, caching).

    * **Torque:**  Clearly state it's likely not Torque due to the lack of `.tq`.

    * **JavaScript Examples:** Create simple, illustrative JavaScript code snippets that would trigger the described functionalities (object literals, `Object.assign`, properties with getters/setters).

    * **Logical Deductions:** Focus on the pre-check functions and the caching mechanisms. Provide clear input/output examples for functions like `GetCloneModeForMap`.

    * **Common Programming Errors:** Think about mistakes related to object mutability, unexpected behavior with getters/setters, and assumptions about object structure.

    * **Summary (Part 5 of 6):**  Emphasize the IC's role in optimizing common JavaScript operations like object creation, cloning, and property access. Highlight the theme of distinguishing fast and slow paths.

5. **Review and Refine:** I'll read through my generated answers to ensure accuracy, clarity, and completeness, making sure I've addressed all aspects of the original request. For instance, I'll double-check that the JavaScript examples are relevant and easy to understand. I'll also ensure that the assumptions for the logical deductions are stated clearly.
这是目录为v8/src/ic/ic.cc的V8源代码的一部分，让我们来分析一下它的功能：

**1. 功能概述:**

这段代码主要负责 V8 JavaScript 引擎中 **Inline Cache (IC)** 的一部分功能，特别是与 **对象克隆 (cloning)** 和 **属性访问 (property access)** 相关的优化。 它包含用于判断是否可以进行快速克隆、执行慢速克隆、以及处理带有拦截器 (interceptors) 的属性的加载和存储的逻辑。

**2. 是否为 Torque 代码:**

根据描述，如果 `v8/src/ic/ic.cc` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。由于这里给出的文件名是 `.cc`，这表明它是 **C++ 源代码**，而不是 Torque 代码。

**3. 与 JavaScript 功能的关系及示例:**

这段代码直接影响 JavaScript 中创建和操作对象的方式，特别是以下几个方面：

* **对象字面量创建和克隆:**  `GetCloneModeForMap`, `CanFastCloneObjectToObjectLiteral`, `CloneObjectSlowPath`, `Runtime_CloneObjectIC_Miss` 这些函数都与高效地克隆对象字面量有关。V8 尝试识别可以快速复制的对象结构，避免逐个属性拷贝的开销。

   ```javascript
   // 对象字面量创建，V8 内部可能会尝试复用或快速创建相似结构的对象
   const obj1 = { a: 1, b: 2 };
   const obj2 = { a: 3, b: 4 };

   // Object.assign 用于合并对象，V8 内部可能会尝试快速拷贝属性
   const mergedObj = Object.assign({}, obj1, { c: 5 });

   // 对象字面量克隆，V8 内部会尝试优化
   const clonedObj = { ...obj1 };
   ```

* **`Object.assign()` 方法:** `Runtime_ObjectAssignTryFastcase` 专门用于尝试优化 `Object.assign()` 的执行，尝试进行快速的对象属性拷贝。

   ```javascript
   const target = {};
   const source = { x: 10, y: 20 };
   Object.assign(target, source); // V8 会尝试优化这个过程
   ```

* **带有访问器属性 (getters/setters) 的对象:** `Runtime_StoreCallbackProperty` 负责处理设置带有 setter 的属性。

   ```javascript
   const obj = {
       _value: 0,
       set value(newValue) {
           this._value = newValue * 2;
       },
       get value() {
           return this._value;
       }
   };
   obj.value = 5; // 调用 setter，Runtime_StoreCallbackProperty 会处理
   console.log(obj.value); // 调用 getter
   ```

* **带有拦截器 (interceptors) 的对象:** `Runtime_LoadPropertyWithInterceptor` 和 `Runtime_StorePropertyWithInterceptor` 处理属性的读取和设置，当对象具有拦截器时。拦截器是一种动态处理属性访问的机制。

   虽然 JavaScript 中不直接暴露创建拦截器的方法（通常是 C++ 代码创建），但理解其作用很重要。例如，某些宿主对象或通过特定 API 创建的对象可能具有拦截器。

**4. 代码逻辑推理 (假设输入与输出):**

**假设输入 (针对 `GetCloneModeForMap`):**

* `map`:  一个指向 V8 `Map` 对象的指针，代表一个对象的形状（例如，属性的类型和位置）。
* `null_proto_literal`: 一个布尔值，指示对象是否通过 `Object.create(null)` 创建或者字面量中使用了 `__proto__: null`。
* `isolate`: 当前 V8 隔离区的指针。

**假设输出 (针对 `GetCloneModeForMap`):**

* `FastCloneObjectMode` 枚举值，指示是否支持快速克隆以及支持哪种类型的快速克隆：
    * `kIdenticalMap`:  可以快速克隆并使用相同的 `Map`。
    * `kDifferentMap`: 可以快速克隆，但需要使用不同的 `Map`。
    * `kNotSupported`: 不支持快速克隆。
    * `kMaybeSupported`: 尚不确定，需要进一步检查。
    * `kEmptyObject`: 目标可以是一个空对象。

**逻辑推理示例 (`GetCloneModeForMap`):**

如果输入的 `map` 代表一个通过 `{}` 创建的普通对象，没有不可枚举或私有属性，并且其原型链是标准的 `Object.prototype`，那么 `GetCloneModeForMap` 很可能返回 `FastCloneObjectMode::kIdenticalMap`，这意味着可以快速克隆并复用相同的对象形状。

如果 `null_proto_literal` 为 `true`，即使其他条件满足，`GetCloneModeForMap` 通常会返回 `FastCloneObjectMode::kDifferentMap`，因为 null 原型对象在某些方面有特殊处理。

**5. 涉及用户常见的编程错误:**

* **意外地在对象上定义了不可枚举的属性:**  如果一个对象的某些属性是不可枚举的，`GetCloneModeForMap` 可能会返回 `kNotSupported`，导致无法进行快速克隆，这可能会影响性能。

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'nonEnum', {
       value: 10,
       enumerable: false // 常见错误：忘记设置为 true
   });
   // 克隆 obj 时可能无法走快速路径
   const cloned = { ...obj };
   ```

* **依赖于对象属性的顺序，但在某些情况下顺序可能不被保证 (特别是使用 `Object.assign` 或对象字面量克隆时):** 虽然 V8 会尽力保持属性顺序，但过度依赖于未明确保证的顺序可能会导致问题。

* **在不理解拦截器的情况下与具有拦截器的对象交互:**  用户可能不清楚某些对象（特别是宿主对象）具有拦截器，这会导致属性访问的行为与预期不同，从而引发错误。

* **过度使用或不必要地使用访问器属性:** 虽然访问器属性提供了灵活性，但过多的使用可能会增加属性访问的开销，影响性能，并且使得 V8 更难进行优化，例如快速克隆。

**6. 功能归纳 (作为第 5 部分):**

作为 V8 Inline Cache 代码的一部分，这段代码主要负责 **优化 JavaScript 对象的克隆和属性访问操作**。它通过分析对象的结构和属性特征，尝试识别可以进行快速复制或访问的场景，从而提升 JavaScript 代码的执行效率。 具体来说，这部分代码关注以下核心功能：

* **对象克隆优化:** 判断对象是否可以进行快速克隆，并提供快速和慢速两种克隆路径。这对于频繁创建和复制对象的场景至关重要。
* **`Object.assign()` 优化:** 尝试优化 `Object.assign()` 的执行过程，提高对象合并的效率。
* **属性访问优化:**  处理带有回调属性（访问器）和拦截器的属性的加载和存储，确保这些复杂的属性访问机制能够正确执行，并在可能的情况下进行优化。

总而言之，这段代码是 V8 引擎为了提升 JavaScript 性能而进行底层优化的一个关键组成部分，它通过精细的逻辑来判断和执行高效的对象操作。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/ic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

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

RUNTIME_FUNCTION(Runtime_LoadElementWi
"""


```