Response: The user wants me to summarize the functionality of the C++ code in `v8/src/objects/map.cc`. This is the second part of the file.

Based on the provided code snippets, I can see several key functionalities related to `Map` objects in V8:

1. **Map Creation and Copying:** Functions like `Copy`, `Create`, `CopyForElementsTransition`, `CopyForPrototypeTransition` are involved in creating new `Map` objects based on existing ones, potentially modifying properties like element kind or prototype.

2. **Property Transitions:** Functions like `TransitionToDataProperty`, `TransitionToAccessorProperty` deal with changing the representation of properties in objects, like adding a new data property or an accessor. These functions also handle transitions to dictionary mode when the number of fast properties exceeds a limit.

3. **Descriptor Management:** Functions like `CopyAddDescriptor`, `CopyInsertDescriptor`, `CopyReplaceDescriptor` are responsible for managing the `DescriptorArray` which stores information about object properties.

4. **Normalization:** The `Normalize` function seems to handle converting objects to a dictionary-based property storage when the fast property storage becomes inefficient.

5. **Prototype Management:** Functions like `SetPrototype`, `TransitionToUpdatePrototype`, `TransitionRootMapToPrototypeForNewObject` handle operations related to setting and transitioning object prototypes.

6. **Inobject Slack Tracking:** Functions like `StartInobjectSlackTracking` and related logic appear to be involved in optimizing the allocation of in-object properties.

7. **Normalized Map Cache:** The `NormalizedMapCache` class seems to be a mechanism for caching normalized (dictionary mode) maps to avoid redundant computations.

Regarding the connection to JavaScript, these `Map` objects are fundamental to how JavaScript objects are represented internally in V8. Each JavaScript object has an associated `Map` that describes its structure and properties.

Let's create some illustrative JavaScript examples.
该C++代码文件（`v8/src/objects/map.cc`的第二部分）主要负责实现V8引擎中`Map`对象的各种操作，这些操作是管理JavaScript对象属性和结构的核心机制。以下是其主要功能的归纳：

**核心功能：管理JavaScript对象的结构和属性**

1. **Map的复制和创建：** 提供了多种复制现有`Map`对象以创建新`Map`对象的方法，例如 `CopyForElementsTransition` (为了元素类型的改变而复制), `CopyForPrototypeTransition` (为了原型链的改变而复制), `Copy` 和 `Create` 等。这些方法允许在保持或修改原有结构的基础上创建新的`Map`。

2. **属性的添加和转换：**
    *   `TransitionToDataProperty`:  当向对象添加新的数据属性时，此函数负责创建或查找合适的`Map`，并更新其描述符数组以存储新属性的信息。
    *   `TransitionToAccessorProperty`: 当向对象添加访问器属性（getter/setter）时，此函数执行类似的操作。
    *   这些函数还处理了从快速属性到慢速属性（字典模式）的转换，当对象拥有过多快速属性时，会调用 `Normalize` 函数。

3. **描述符的管理：** `Map`对象内部维护一个 `DescriptorArray` 来存储对象属性的元数据（例如，属性名、类型、位置等）。代码中包含了 `CopyAddDescriptor`, `CopyInsertDescriptor`, `CopyReplaceDescriptor` 等函数，用于在 `DescriptorArray` 中添加、插入或替换属性描述符。

4. **Map的规范化 (Normalization)：**  `Normalize` 函数负责将对象的属性存储方式从快速属性（存储在固定大小的内存区域）转换为慢速属性（存储在哈希表中，也称为字典模式）。这通常发生在对象动态添加大量属性后，以避免性能下降。

5. **原型链的管理：**
    *   `SetPrototype`:  用于设置对象的原型。
    *   `TransitionToUpdatePrototype`:  当对象的原型发生改变时，此函数用于创建新的`Map`。
    *   `TransitionRootMapToPrototypeForNewObject`: 在创建新对象时，如果原型发生变化，会调用此函数。

6. **内联属性空间的优化 (Inobject Slack Tracking)：**  `StartInobjectSlackTracking` 以及相关的逻辑似乎用于跟踪对象内联属性的剩余空间，以便在后续的对象创建中进行优化。

7. **Map的哈希和等价性判断：**  `Hash` 函数用于计算`Map`的哈希值，而 `EquivalentToForTransition`, `EquivalentToForElementsKindTransition`, `EquivalentToForNormalization` 等函数用于判断两个`Map`在不同场景下是否等价，这对于 `Map` 的共享和优化非常重要。

8. **规范化Map的缓存 (NormalizedMapCache)：**  `NormalizedMapCache`  类提供了一种缓存已经规范化的`Map`的机制，以避免重复的规范化过程，提高性能。

**与JavaScript功能的关联和示例：**

`Map` 对象在V8引擎中直接对应于JavaScript对象的内部表示。当你操作JavaScript对象时，V8引擎会在底层操作其关联的`Map`对象。

**示例 1：添加数据属性**

```javascript
const obj = {};
obj.a = 1; // 触发 Map 的 TransitionToDataProperty
```

在上述JavaScript代码中，当向空对象 `obj` 添加属性 `a` 时，V8会查找或创建一个适合存储该属性的 `Map` 对象。`v8/src/objects/map.cc` 中的 `TransitionToDataProperty` 函数会被调用，负责创建新的 `Map` 或复用已有的 `Map`，并将属性 `a` 的信息添加到该 `Map` 的 `DescriptorArray` 中。

**示例 2：添加访问器属性**

```javascript
const obj = {
  get b() { return this._b; },
  set b(value) { this._b = value; }
}; // 触发 Map 的 TransitionToAccessorProperty
```

当定义带有 getter 和 setter 的属性 `b` 时，`TransitionToAccessorProperty` 函数会被调用。V8会创建一个新的 `Map`，并在其 `DescriptorArray` 中存储关于访问器属性 `b` 的信息，包括 getter 和 setter 函数的引用。

**示例 3：动态添加大量属性导致规范化**

```javascript
const obj = {};
for (let i = 0; i < 100; i++) {
  obj[`prop${i}`] = i; // 可能会触发 Map 的 Normalize
}
```

当向对象动态添加大量属性时，起初V8可能会使用快速属性来存储它们。但当属性数量超过一定阈值后，为了性能考虑，V8会调用 `Normalize` 函数将对象的属性存储方式转换为更灵活但访问速度稍慢的字典模式。

**示例 4：修改原型**

```javascript
const parent = {};
const child = Object.create(parent); // 触发 Map 相关的原型链管理机制
```

当使用 `Object.create` 创建对象 `child` 并指定 `parent` 为其原型时，V8会更新 `child` 对象关联的 `Map`，使其指向 `parent` 对象的 `Map` 作为原型链的一部分。`v8/src/objects/map.cc` 中的原型链管理函数（如 `SetPrototype` 或 `TransitionToUpdatePrototype`）会参与此过程。

总而言之，`v8/src/objects/map.cc` 的这部分代码是V8引擎中至关重要的组成部分，它直接影响着JavaScript对象的内存布局、属性访问性能以及原型继承的实现。理解这部分代码的功能有助于深入理解V8引擎的工作原理。

Prompt: 
```
这是目录为v8/src/objects/map.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
sition_symbol);
  if (!maybe_transition.is_null()) {
    return maybe_transition.ToHandleChecked();
  }
  initial_map->NotifyLeafMapLayoutChange(isolate);

  // Create new map taking descriptors from the |function_map| and all
  // the other details from the |initial_map|.
  Handle<Map> map =
      Map::CopyInitialMap(isolate, function_map, initial_map->instance_size(),
                          initial_map->GetInObjectProperties(),
                          initial_map->UnusedPropertyFields());
  map->SetConstructor(initial_map->GetConstructor());
  map->set_prototype(initial_map->prototype());
  map->set_construction_counter(initial_map->construction_counter());

  if (TransitionsAccessor::CanHaveMoreTransitions(isolate, initial_map)) {
    Map::ConnectTransition(isolate, initial_map, map, transition_symbol,
                           SPECIAL_TRANSITION);
  }
  return map;
}

Handle<Map> Map::CopyForElementsTransition(Isolate* isolate, Handle<Map> map) {
  DCHECK(!map->IsDetached(isolate));
  DCHECK(!map->is_dictionary_map());
  Handle<Map> new_map = CopyDropDescriptors(isolate, map);

  if (map->owns_descriptors()) {
    // In case the map owned its own descriptors, share the descriptors and
    // transfer ownership to the new map.
    // The properties did not change, so reuse descriptors.
    map->set_owns_descriptors(false);
    new_map->InitializeDescriptors(isolate, map->instance_descriptors(isolate));
  } else {
    // In case the map did not own its own descriptors, a split is forced by
    // copying the map; creating a new descriptor array cell.
    DirectHandle<DescriptorArray> descriptors(
        map->instance_descriptors(isolate), isolate);
    int number_of_own_descriptors = map->NumberOfOwnDescriptors();
    DirectHandle<DescriptorArray> new_descriptors = DescriptorArray::CopyUpTo(
        isolate, descriptors, number_of_own_descriptors);
    new_map->InitializeDescriptors(isolate, *new_descriptors);
  }
  return new_map;
}

Handle<Map> Map::CopyForPrototypeTransition(Isolate* isolate, Handle<Map> map,
                                            Handle<JSPrototype> prototype) {
  // For simplicity we always copy descriptors although it would be possible to
  // share them in some situations.
  Handle<Map> new_map =
      Copy(isolate, map, "TransitionToPrototype", PROTOTYPE_TRANSITION);
  Map::SetPrototype(isolate, new_map, prototype);
  return new_map;
}

Handle<Map> Map::Copy(Isolate* isolate, Handle<Map> map, const char* reason,
                      TransitionKindFlag kind) {
  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  DirectHandle<DescriptorArray> new_descriptors = DescriptorArray::CopyUpTo(
      isolate, descriptors, number_of_own_descriptors);
  auto res =
      CopyReplaceDescriptors(isolate, map, new_descriptors, OMIT_TRANSITION,
                             MaybeHandle<Name>(), reason, kind);
  return res;
}

Handle<Map> Map::Create(Isolate* isolate, int inobject_properties) {
  Handle<Map> copy_handle =
      Copy(isolate, handle(isolate->object_function()->initial_map(), isolate),
           "MapCreate");
  DisallowGarbageCollection no_gc;
  Tagged<Map> copy = *copy_handle;

  // Check that we do not overflow the instance size when adding the extra
  // inobject properties. If the instance size overflows, we allocate as many
  // properties as we can as inobject properties.
  if (inobject_properties > JSObject::kMaxInObjectProperties) {
    inobject_properties = JSObject::kMaxInObjectProperties;
  }

  int new_instance_size =
      JSObject::kHeaderSize + kTaggedSize * inobject_properties;

  // Adjust the map with the extra inobject properties.
  copy->set_instance_size(new_instance_size);
  copy->SetInObjectPropertiesStartInWords(JSObject::kHeaderSize / kTaggedSize);
  DCHECK_EQ(copy->GetInObjectProperties(), inobject_properties);
  copy->SetInObjectUnusedPropertyFields(inobject_properties);
  copy->set_visitor_id(Map::GetVisitorId(copy));

  return copy_handle;
}

Handle<Map> Map::CopyForPreventExtensions(
    Isolate* isolate, Handle<Map> map, PropertyAttributes attrs_to_add,
    Handle<Symbol> transition_marker, const char* reason,
    bool old_map_is_dictionary_elements_kind) {
  int num_descriptors = map->NumberOfOwnDescriptors();
  DirectHandle<DescriptorArray> new_desc =
      DescriptorArray::CopyUpToAddAttributes(
          isolate, handle(map->instance_descriptors(isolate), isolate),
          num_descriptors, attrs_to_add);
  // Do not track transitions during bootstrapping.
  TransitionFlag flag =
      isolate->bootstrapper()->IsActive() ? OMIT_TRANSITION : INSERT_TRANSITION;
  Handle<Map> new_map =
      CopyReplaceDescriptors(isolate, map, new_desc, flag, transition_marker,
                             reason, SPECIAL_TRANSITION);
  new_map->set_is_extensible(false);
  if (!IsTypedArrayOrRabGsabTypedArrayElementsKind(map->elements_kind())) {
    ElementsKind new_kind = IsStringWrapperElementsKind(map->elements_kind())
                                ? SLOW_STRING_WRAPPER_ELEMENTS
                                : DICTIONARY_ELEMENTS;
    if (v8_flags.enable_sealed_frozen_elements_kind &&
        !old_map_is_dictionary_elements_kind) {
      switch (map->elements_kind()) {
        case PACKED_ELEMENTS:
          if (attrs_to_add == SEALED) {
            new_kind = PACKED_SEALED_ELEMENTS;
          } else if (attrs_to_add == FROZEN) {
            new_kind = PACKED_FROZEN_ELEMENTS;
          } else {
            new_kind = PACKED_NONEXTENSIBLE_ELEMENTS;
          }
          break;
        case PACKED_NONEXTENSIBLE_ELEMENTS:
          if (attrs_to_add == SEALED) {
            new_kind = PACKED_SEALED_ELEMENTS;
          } else if (attrs_to_add == FROZEN) {
            new_kind = PACKED_FROZEN_ELEMENTS;
          }
          break;
        case PACKED_SEALED_ELEMENTS:
          if (attrs_to_add == FROZEN) {
            new_kind = PACKED_FROZEN_ELEMENTS;
          }
          break;
        case HOLEY_ELEMENTS:
          if (attrs_to_add == SEALED) {
            new_kind = HOLEY_SEALED_ELEMENTS;
          } else if (attrs_to_add == FROZEN) {
            new_kind = HOLEY_FROZEN_ELEMENTS;
          } else {
            new_kind = HOLEY_NONEXTENSIBLE_ELEMENTS;
          }
          break;
        case HOLEY_NONEXTENSIBLE_ELEMENTS:
          if (attrs_to_add == SEALED) {
            new_kind = HOLEY_SEALED_ELEMENTS;
          } else if (attrs_to_add == FROZEN) {
            new_kind = HOLEY_FROZEN_ELEMENTS;
          }
          break;
        case HOLEY_SEALED_ELEMENTS:
          if (attrs_to_add == FROZEN) {
            new_kind = HOLEY_FROZEN_ELEMENTS;
          }
          break;
        default:
          break;
      }
    }
    new_map->set_elements_kind(new_kind);
  }
  return new_map;
}

namespace {

bool CanHoldValue(Tagged<DescriptorArray> descriptors, InternalIndex descriptor,
                  PropertyConstness constness, Tagged<Object> value) {
  PropertyDetails details = descriptors->GetDetails(descriptor);
  if (details.location() == PropertyLocation::kField) {
    if (details.kind() == PropertyKind::kData) {
      return IsGeneralizableTo(constness, details.constness()) &&
             Object::FitsRepresentation(value, details.representation()) &&
             FieldType::NowContains(descriptors->GetFieldType(descriptor),
                                    value);
    } else {
      DCHECK_EQ(PropertyKind::kAccessor, details.kind());
      return false;
    }

  } else {
    DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
    DCHECK_EQ(PropertyConstness::kConst, details.constness());
    DCHECK_EQ(PropertyKind::kAccessor, details.kind());
    return false;
  }
  UNREACHABLE();
}

Handle<Map> UpdateDescriptorForValue(Isolate* isolate, Handle<Map> map,
                                     InternalIndex descriptor,
                                     PropertyConstness constness,
                                     DirectHandle<Object> value) {
  if (CanHoldValue(map->instance_descriptors(isolate), descriptor, constness,
                   *value)) {
    return map;
  }

  PropertyAttributes attributes =
      map->instance_descriptors(isolate)->GetDetails(descriptor).attributes();
  Representation representation =
      Object::OptimalRepresentation(*value, isolate);
  Handle<FieldType> type = Object::OptimalType(*value, isolate, representation);

  MapUpdater mu(isolate, map);
  return mu.ReconfigureToDataField(descriptor, attributes, constness,
                                   representation, type);
}

}  // namespace

// static
Handle<Map> Map::PrepareForDataProperty(Isolate* isolate, Handle<Map> map,
                                        InternalIndex descriptor,
                                        PropertyConstness constness,
                                        DirectHandle<Object> value) {
  // The map should already be fully updated before storing the property.
  DCHECK(!map->is_deprecated());
  // Dictionaries can store any property value.
  DCHECK(!map->is_dictionary_map());
  return UpdateDescriptorForValue(isolate, map, descriptor, constness, value);
}

Handle<Map> Map::TransitionToDataProperty(Isolate* isolate, Handle<Map> map,
                                          Handle<Name> name,
                                          DirectHandle<Object> value,
                                          PropertyAttributes attributes,
                                          PropertyConstness constness,
                                          StoreOrigin store_origin) {
  RCS_SCOPE(isolate,
            map->IsDetached(isolate)
                ? RuntimeCallCounterId::kPrototypeMap_TransitionToDataProperty
                : RuntimeCallCounterId::kMap_TransitionToDataProperty);

  DCHECK(IsUniqueName(*name));
  DCHECK(!map->is_dictionary_map());

  // Migrate to the newest map before storing the property.
  map = Update(isolate, map);

  MaybeHandle<Map> maybe_transition = TransitionsAccessor::SearchTransition(
      isolate, map, *name, PropertyKind::kData, attributes);
  Handle<Map> transition;
  if (maybe_transition.ToHandle(&transition)) {
    InternalIndex descriptor = transition->LastAdded();

    DCHECK_EQ(attributes, transition->instance_descriptors(isolate)
                              ->GetDetails(descriptor)
                              .attributes());

    return UpdateDescriptorForValue(isolate, transition, descriptor, constness,
                                    value);
  }

  // Do not track transitions during bootstrapping.
  TransitionFlag flag =
      isolate->bootstrapper()->IsActive() ? OMIT_TRANSITION : INSERT_TRANSITION;
  MaybeHandle<Map> maybe_map;
  if (!map->TooManyFastProperties(store_origin)) {
    Representation representation =
        Object::OptimalRepresentation(*value, isolate);
    Handle<FieldType> type =
        Object::OptimalType(*value, isolate, representation);
    maybe_map = Map::CopyWithField(isolate, map, name, type, attributes,
                                   constness, representation, flag);
  }

  Handle<Map> result;
  if (!maybe_map.ToHandle(&result)) {
    const char* reason = "TooManyFastProperties";
#if V8_TRACE_MAPS
    std::unique_ptr<base::ScopedVector<char>> buffer;
    if (v8_flags.log_maps) {
      base::ScopedVector<char> name_buffer(100);
      name->NameShortPrint(name_buffer);
      buffer.reset(new base::ScopedVector<char>(128));
      SNPrintF(*buffer, "TooManyFastProperties %s", name_buffer.begin());
      reason = buffer->begin();
    }
#endif
    Handle<Object> maybe_constructor(map->GetConstructor(), isolate);
    if (v8_flags.feedback_normalization && map->new_target_is_base() &&
        IsJSFunction(*maybe_constructor) &&
        !Cast<JSFunction>(*maybe_constructor)->shared()->native()) {
      auto constructor = Cast<JSFunction>(maybe_constructor);
      DCHECK_NE(*constructor, constructor->native_context()->object_function());
      Handle<Map> initial_map(constructor->initial_map(), isolate);
      result = Map::Normalize(isolate, initial_map, CLEAR_INOBJECT_PROPERTIES,
                              reason);
      initial_map->DeprecateTransitionTree(isolate);
      Handle<JSReceiver> prototype(Cast<JSReceiver>(result->prototype()),
                                   isolate);
      JSFunction::SetInitialMap(isolate, constructor, result, prototype);

      // Deoptimize all code that embeds the previous initial map.
      DependentCode::DeoptimizeDependencyGroups(
          isolate, *initial_map, DependentCode::kInitialMapChangedGroup);
      if (!result->EquivalentToForNormalization(*map,
                                                CLEAR_INOBJECT_PROPERTIES)) {
        result =
            Map::Normalize(isolate, map, CLEAR_INOBJECT_PROPERTIES, reason);
      }
    } else {
      result = Map::Normalize(isolate, map, CLEAR_INOBJECT_PROPERTIES, reason);
    }
  }

  return result;
}

Handle<Map> Map::TransitionToAccessorProperty(Isolate* isolate, Handle<Map> map,
                                              Handle<Name> name,
                                              InternalIndex descriptor,
                                              DirectHandle<Object> getter,
                                              DirectHandle<Object> setter,
                                              PropertyAttributes attributes) {
  RCS_SCOPE(
      isolate,
      map->IsDetached(isolate)
          ? RuntimeCallCounterId::kPrototypeMap_TransitionToAccessorProperty
          : RuntimeCallCounterId::kMap_TransitionToAccessorProperty);

  // At least one of the accessors needs to be a new value.
  DCHECK(!IsNull(*getter, isolate) || !IsNull(*setter, isolate));
  DCHECK(IsUniqueName(*name));

  // Migrate to the newest map before transitioning to the new property.
  map = Update(isolate, map);

  // Dictionary maps can always have additional data properties.
  if (map->is_dictionary_map()) return map;

  PropertyNormalizationMode mode = map->is_prototype_map()
                                       ? KEEP_INOBJECT_PROPERTIES
                                       : CLEAR_INOBJECT_PROPERTIES;

  MaybeHandle<Map> maybe_transition = TransitionsAccessor::SearchTransition(
      isolate, map, *name, PropertyKind::kAccessor, attributes);
  Handle<Map> transition;
  if (maybe_transition.ToHandle(&transition)) {
    Tagged<DescriptorArray> descriptors =
        transition->instance_descriptors(isolate);
    InternalIndex last_descriptor = transition->LastAdded();
    DCHECK(descriptors->GetKey(last_descriptor)->Equals(*name));

    DCHECK_EQ(PropertyKind::kAccessor,
              descriptors->GetDetails(last_descriptor).kind());
    DCHECK_EQ(attributes,
              descriptors->GetDetails(last_descriptor).attributes());

    Handle<Object> maybe_pair(descriptors->GetStrongValue(last_descriptor),
                              isolate);
    if (!IsAccessorPair(*maybe_pair)) {
      return Map::Normalize(isolate, map, mode,
                            "TransitionToAccessorFromNonPair");
    }

    auto pair = Cast<AccessorPair>(maybe_pair);
    if (!pair->Equals(*getter, *setter)) {
      return Map::Normalize(isolate, map, mode,
                            "TransitionToDifferentAccessor");
    }

    return transition;
  }

  Handle<AccessorPair> pair;
  Tagged<DescriptorArray> old_descriptors = map->instance_descriptors(isolate);
  if (descriptor.is_found()) {
    if (descriptor != map->LastAdded()) {
      return Map::Normalize(isolate, map, mode, "AccessorsOverwritingNonLast");
    }
    PropertyDetails old_details = old_descriptors->GetDetails(descriptor);
    if (old_details.kind() != PropertyKind::kAccessor) {
      return Map::Normalize(isolate, map, mode,
                            "AccessorsOverwritingNonAccessors");
    }

    if (old_details.attributes() != attributes) {
      return Map::Normalize(isolate, map, mode, "AccessorsWithAttributes");
    }

    Handle<Object> maybe_pair(old_descriptors->GetStrongValue(descriptor),
                              isolate);
    if (!IsAccessorPair(*maybe_pair)) {
      return Map::Normalize(isolate, map, mode, "AccessorsOverwritingNonPair");
    }

    auto current_pair = Cast<AccessorPair>(maybe_pair);
    if (current_pair->Equals(*getter, *setter)) return map;

    bool overwriting_accessor = false;
    if (!IsNull(*getter, isolate) &&
        !IsNull(current_pair->get(ACCESSOR_GETTER), isolate) &&
        current_pair->get(ACCESSOR_GETTER) != *getter) {
      overwriting_accessor = true;
    }
    if (!IsNull(*setter, isolate) &&
        !IsNull(current_pair->get(ACCESSOR_SETTER), isolate) &&
        current_pair->get(ACCESSOR_SETTER) != *setter) {
      overwriting_accessor = true;
    }
    if (overwriting_accessor) {
      return Map::Normalize(isolate, map, mode,
                            "AccessorsOverwritingAccessors");
    }

    pair = AccessorPair::Copy(isolate, Cast<AccessorPair>(maybe_pair));
  } else if (map->NumberOfOwnDescriptors() >= kMaxNumberOfDescriptors ||
             map->TooManyFastProperties(StoreOrigin::kNamed)) {
    return Map::Normalize(isolate, map, CLEAR_INOBJECT_PROPERTIES,
                          "TooManyAccessors");
  } else {
    pair = isolate->factory()->NewAccessorPair();
  }

  pair->SetComponents(*getter, *setter);

  // Do not track transitions during bootstrapping.
  TransitionFlag flag =
      isolate->bootstrapper()->IsActive() ? OMIT_TRANSITION : INSERT_TRANSITION;
  Descriptor d = Descriptor::AccessorConstant(name, pair, attributes);
  return Map::CopyInsertDescriptor(isolate, map, &d, flag);
}

Handle<Map> Map::CopyAddDescriptor(Isolate* isolate, Handle<Map> map,
                                   Descriptor* descriptor,
                                   TransitionFlag flag) {
  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);

  // Share descriptors only if map owns descriptors and is not an initial map.
  if (flag == INSERT_TRANSITION && map->owns_descriptors() &&
      !IsUndefined(map->GetBackPointer(), isolate) &&
      TransitionsAccessor::CanHaveMoreTransitions(isolate, map)) {
    return ShareDescriptor(isolate, map, descriptors, descriptor);
  }

  int nof = map->NumberOfOwnDescriptors();
  DirectHandle<DescriptorArray> new_descriptors =
      DescriptorArray::CopyUpTo(isolate, descriptors, nof, 1);
  new_descriptors->Append(descriptor);

  return CopyReplaceDescriptors(isolate, map, new_descriptors, flag,
                                descriptor->GetKey(), "CopyAddDescriptor",
                                SIMPLE_PROPERTY_TRANSITION);
}

Handle<Map> Map::CopyInsertDescriptor(Isolate* isolate, Handle<Map> map,
                                      Descriptor* descriptor,
                                      TransitionFlag flag) {
  DirectHandle<DescriptorArray> old_descriptors(
      map->instance_descriptors(isolate), isolate);

  // We replace the key if it is already present.
  InternalIndex index =
      old_descriptors->SearchWithCache(isolate, *descriptor->GetKey(), *map);
  if (index.is_found()) {
    return CopyReplaceDescriptor(isolate, map, old_descriptors, descriptor,
                                 index, flag);
  }
  return CopyAddDescriptor(isolate, map, descriptor, flag);
}

Handle<Map> Map::CopyReplaceDescriptor(
    Isolate* isolate, Handle<Map> map,
    DirectHandle<DescriptorArray> descriptors, Descriptor* descriptor,
    InternalIndex insertion_index, TransitionFlag flag) {
  Handle<Name> key = descriptor->GetKey();
  DCHECK_EQ(*key, descriptors->GetKey(insertion_index));
  // This function does not support replacing property fields as
  // that would break property field counters.
  DCHECK_NE(PropertyLocation::kField, descriptor->GetDetails().location());
  DCHECK_NE(PropertyLocation::kField,
            descriptors->GetDetails(insertion_index).location());

  DirectHandle<DescriptorArray> new_descriptors = DescriptorArray::CopyUpTo(
      isolate, descriptors, map->NumberOfOwnDescriptors());

  new_descriptors->Replace(insertion_index, descriptor);

  TransitionKindFlag simple_flag =
      (insertion_index.as_int() == descriptors->number_of_descriptors() - 1)
          ? SIMPLE_PROPERTY_TRANSITION
          : PROPERTY_TRANSITION;
  return CopyReplaceDescriptors(isolate, map, new_descriptors, flag, key,
                                "CopyReplaceDescriptor", simple_flag);
}

int Map::Hash(Isolate* isolate, Tagged<HeapObject> prototype) {
  // For performance reasons we only hash the 2 most variable fields of a map:
  // prototype and bit_field2.

  int prototype_hash;
  if (IsNull(prototype)) {
    // No identity hash for null, so just pick a random number.
    prototype_hash = 1;
  } else {
    Tagged<JSReceiver> receiver = Cast<JSReceiver>(prototype);
    prototype_hash = receiver->GetOrCreateIdentityHash(isolate).value();
  }

  return prototype_hash ^ bit_field2();
}

namespace {

bool CheckEquivalentModuloProto(const Tagged<Map> first,
                                const Tagged<Map> second) {
  return first->GetConstructorRaw() == second->GetConstructorRaw() &&
         first->instance_type() == second->instance_type() &&
         first->bit_field() == second->bit_field() &&
         first->is_extensible() == second->is_extensible() &&
         first->new_target_is_base() == second->new_target_is_base();
}

}  // namespace

bool Map::EquivalentToForTransition(const Tagged<Map> other,
                                    ConcurrencyMode cmode,
                                    Handle<HeapObject> new_prototype) const {
  CHECK_EQ(GetConstructor(), other->GetConstructor());
  CHECK_EQ(instance_type(), other->instance_type());

  if (bit_field() != other->bit_field()) return false;
  if (new_prototype.is_null()) {
    if (prototype() != other->prototype()) return false;
  } else {
    if (*new_prototype != other->prototype()) return false;
  }
  if (new_target_is_base() != other->new_target_is_base()) return false;
  if (InstanceTypeChecker::IsJSFunction(instance_type())) {
    // JSFunctions require more checks to ensure that sloppy function is
    // not equivalent to strict function.
    int nof =
        std::min(NumberOfOwnDescriptors(), other->NumberOfOwnDescriptors());
    Tagged<DescriptorArray> this_descriptors =
        IsConcurrent(cmode) ? instance_descriptors(kAcquireLoad)
                            : instance_descriptors();
    Tagged<DescriptorArray> that_descriptors =
        IsConcurrent(cmode) ? other->instance_descriptors(kAcquireLoad)
                            : other->instance_descriptors();
    return this_descriptors->IsEqualUpTo(that_descriptors, nof);
  }
  return true;
}

bool Map::EquivalentToForElementsKindTransition(const Tagged<Map> other,
                                                ConcurrencyMode cmode) const {
  if (!EquivalentToForTransition(other, cmode)) {
    return false;
  }
#ifdef DEBUG
  // Ensure that we don't try to generate elements kind transitions from maps
  // with fields that may be generalized in-place. This must already be handled
  // during addition of a new field.
  Tagged<DescriptorArray> descriptors = IsConcurrent(cmode)
                                            ? instance_descriptors(kAcquireLoad)
                                            : instance_descriptors();
  for (InternalIndex i : IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.location() == PropertyLocation::kField) {
      DCHECK(IsMostGeneralFieldType(details.representation(),
                                    descriptors->GetFieldType(i)));
    }
  }
#endif
  return true;
}

bool Map::EquivalentToForNormalization(const Tagged<Map> other,
                                       ElementsKind elements_kind,
                                       Tagged<HeapObject> other_prototype,
                                       PropertyNormalizationMode mode) const {
  int properties =
      mode == CLEAR_INOBJECT_PROPERTIES ? 0 : other->GetInObjectProperties();
  // Make sure the elements_kind bits are in bit_field2.
  DCHECK_EQ(this->elements_kind(),
            Map::Bits2::ElementsKindBits::decode(bit_field2()));
  int adjusted_other_bit_field2 =
      Map::Bits2::ElementsKindBits::update(other->bit_field2(), elements_kind);
  return CheckEquivalentModuloProto(*this, other) &&
         prototype() == other_prototype &&
         bit_field2() == adjusted_other_bit_field2 &&
         GetInObjectProperties() == properties &&
         JSObject::GetEmbedderFieldCount(*this) ==
             JSObject::GetEmbedderFieldCount(other);
}

int Map::ComputeMinObjectSlack(Isolate* isolate) {
  // Has to be an initial map.
  DCHECK(IsUndefined(GetBackPointer(), isolate));

  int slack = UnusedPropertyFields();
  TransitionsAccessor transitions(isolate, *this);
  TransitionsAccessor::TraverseCallback callback = [&](Tagged<Map> map) {
    slack = std::min(slack, map->UnusedPropertyFields());
  };
  transitions.TraverseTransitionTree(callback);
  return slack;
}

void Map::SetInstanceDescriptors(Isolate* isolate,
                                 Tagged<DescriptorArray> descriptors,
                                 int number_of_own_descriptors,
                                 WriteBarrierMode barrier_mode) {
  DCHECK_IMPLIES(barrier_mode == WriteBarrierMode::SKIP_WRITE_BARRIER,
                 HeapLayout::InReadOnlySpace(descriptors));
  set_instance_descriptors(descriptors, kReleaseStore, barrier_mode);
  SetNumberOfOwnDescriptors(number_of_own_descriptors);
#ifndef V8_DISABLE_WRITE_BARRIERS
  WriteBarrier::ForDescriptorArray(descriptors, number_of_own_descriptors);
#endif
}

// static
Handle<PrototypeInfo> Map::GetOrCreatePrototypeInfo(
    DirectHandle<JSObject> prototype, Isolate* isolate) {
  DCHECK(IsJSObjectThatCanBeTrackedAsPrototype(*prototype));
  {
    Tagged<PrototypeInfo> prototype_info;
    if (prototype->map()->TryGetPrototypeInfo(&prototype_info)) {
      return handle(prototype_info, isolate);
    }
  }
  Handle<PrototypeInfo> proto_info = isolate->factory()->NewPrototypeInfo();
  prototype->map()->set_prototype_info(*proto_info, kReleaseStore);
  return proto_info;
}

// static
Handle<PrototypeInfo> Map::GetOrCreatePrototypeInfo(
    DirectHandle<Map> prototype_map, Isolate* isolate) {
  {
    Tagged<Object> maybe_proto_info = prototype_map->prototype_info();
    if (PrototypeInfo::IsPrototypeInfoFast(maybe_proto_info)) {
      return handle(Cast<PrototypeInfo>(maybe_proto_info), isolate);
    }
  }
  Handle<PrototypeInfo> proto_info = isolate->factory()->NewPrototypeInfo();
  prototype_map->set_prototype_info(*proto_info, kReleaseStore);
  return proto_info;
}

// static
void Map::SetShouldBeFastPrototypeMap(DirectHandle<Map> map, bool value,
                                      Isolate* isolate) {
  DCHECK(map->is_prototype_map());
  if (value == false && !map->has_prototype_info()) {
    // "False" is the implicit default value, so there's nothing to do.
    return;
  }
  GetOrCreatePrototypeInfo(map, isolate)->set_should_be_fast_map(value);
}

// static
Handle<UnionOf<Smi, Cell>> Map::GetOrCreatePrototypeChainValidityCell(
    DirectHandle<Map> map, Isolate* isolate) {
  Handle<Object> maybe_prototype;
  if (IsJSGlobalObjectMap(*map)) {
    DCHECK(map->is_prototype_map());
    // Global object is prototype of a global proxy and therefore we can
    // use its validity cell for guarding global object's prototype change.
    maybe_prototype = isolate->global_object();
  } else {
    maybe_prototype =
        handle(map->GetPrototypeChainRootMap(isolate)->prototype(), isolate);
  }
  if (!IsJSObjectThatCanBeTrackedAsPrototype(*maybe_prototype)) {
    return handle(Map::kPrototypeChainValidSmi, isolate);
  }
  auto prototype = Cast<JSObject>(maybe_prototype);
  // Ensure the prototype is registered with its own prototypes so its cell
  // will be invalidated when necessary.
  JSObject::LazyRegisterPrototypeUser(handle(prototype->map(), isolate),
                                      isolate);

  Tagged<Object> maybe_cell =
      prototype->map()->prototype_validity_cell(kRelaxedLoad);
  // Return existing cell if it's still valid.
  if (IsCell(maybe_cell)) {
    Tagged<Cell> cell = Cast<Cell>(maybe_cell);
    if (cell->value() == Map::kPrototypeChainValidSmi) {
      return handle(cell, isolate);
    }
  }
  // Otherwise create a new cell.
  Handle<Cell> cell = isolate->factory()->NewCell(Map::kPrototypeChainValidSmi);
  prototype->map()->set_prototype_validity_cell(*cell, kRelaxedStore);
  return cell;
}

// static
bool Map::IsPrototypeChainInvalidated(Tagged<Map> map) {
  DCHECK(map->is_prototype_map());
  Tagged<Object> maybe_cell = map->prototype_validity_cell(kRelaxedLoad);
  if (IsCell(maybe_cell)) {
    Tagged<Cell> cell = Cast<Cell>(maybe_cell);
    return cell->value() != Map::kPrototypeChainValidSmi;
  }
  return true;
}

// static
void Map::SetPrototype(Isolate* isolate, DirectHandle<Map> map,
                       Handle<JSPrototype> prototype,
                       bool enable_prototype_setup_mode) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kMap_SetPrototype);

  if (IsJSObjectThatCanBeTrackedAsPrototype(*prototype)) {
    DirectHandle<JSObject> prototype_jsobj = Cast<JSObject>(prototype);
    JSObject::OptimizeAsPrototype(prototype_jsobj, enable_prototype_setup_mode);
  } else {
    DCHECK(IsNull(*prototype, isolate) || IsJSProxy(*prototype) ||
           IsWasmObject(*prototype) ||
           HeapLayout::InWritableSharedSpace(*prototype));
  }

  WriteBarrierMode wb_mode =
      IsNull(*prototype, isolate) ? SKIP_WRITE_BARRIER : UPDATE_WRITE_BARRIER;
  map->set_prototype(*prototype, wb_mode);
}

void Map::StartInobjectSlackTracking() {
  DCHECK(!this->IsInobjectSlackTrackingInProgress());
  if (UnusedPropertyFields() == 0) return;
  set_construction_counter(Map::kSlackTrackingCounterStart);
}

Handle<Map> Map::TransitionRootMapToPrototypeForNewObject(
    Isolate* isolate, Handle<Map> map, Handle<JSPrototype> prototype) {
  DCHECK(IsUndefined(map->GetBackPointer()));
  Handle<Map> new_map = TransitionToUpdatePrototype(isolate, map, prototype);
  if (new_map->GetBackPointer() != *map &&
      map->IsInobjectSlackTrackingInProgress()) {
    // Advance the construction count on the base map to keep it in sync with
    // the transitioned map.
    map->InobjectSlackTrackingStep(isolate);
  }
  return new_map;
}

Handle<Map> Map::TransitionToUpdatePrototype(Isolate* isolate, Handle<Map> map,
                                             Handle<JSPrototype> prototype) {
  Handle<Map> new_map;
  DCHECK_IMPLIES(v8_flags.move_prototype_transitions_first,
                 IsUndefined(map->GetBackPointer()));
  if (auto maybe_map = TransitionsAccessor::GetPrototypeTransition(
          isolate, *map, *prototype)) {
    new_map = handle(*maybe_map, isolate);
  } else {
    new_map = CopyForPrototypeTransition(isolate, map, prototype);
    if (!map->IsDetached(isolate)) {
      TransitionsAccessor::PutPrototypeTransition(isolate, map, prototype,
                                                  new_map);
    }
  }
  DCHECK_IMPLIES(map->IsInobjectSlackTrackingInProgress(),
                 new_map->IsInobjectSlackTrackingInProgress());
  CHECK_IMPLIES(map->IsInobjectSlackTrackingInProgress(),
                map->construction_counter() <= new_map->construction_counter());
  return new_map;
}

Handle<NormalizedMapCache> NormalizedMapCache::New(Isolate* isolate) {
  Handle<WeakFixedArray> array(
      isolate->factory()->NewWeakFixedArray(kEntries, AllocationType::kOld));
  return Cast<NormalizedMapCache>(array);
}

MaybeHandle<Map> NormalizedMapCache::Get(Isolate* isolate,
                                         DirectHandle<Map> fast_map,
                                         ElementsKind elements_kind,
                                         Tagged<HeapObject> prototype,
                                         PropertyNormalizationMode mode) {
  DisallowGarbageCollection no_gc;
  Tagged<MaybeObject> value =
      WeakFixedArray::get(GetIndex(isolate, *fast_map, *prototype));
  Tagged<HeapObject> heap_object;
  if (!value.GetHeapObjectIfWeak(&heap_object)) {
    return MaybeHandle<Map>();
  }

  Tagged<Map> normalized_map = Cast<Map>(heap_object);
  CHECK(normalized_map->is_dictionary_map());
  if (!normalized_map->EquivalentToForNormalization(*fast_map, elements_kind,
                                                    prototype, mode)) {
    return MaybeHandle<Map>();
  }
  return handle(normalized_map, isolate);
}

void NormalizedMapCache::Set(Isolate* isolate, DirectHandle<Map> fast_map,
                             DirectHandle<Map> normalized_map) {
  DisallowGarbageCollection no_gc;
  DCHECK(normalized_map->is_dictionary_map());
  WeakFixedArray::set(GetIndex(isolate, *fast_map, normalized_map->prototype()),
                      MakeWeak(*normalized_map));
}

}  // namespace v8::internal

"""


```