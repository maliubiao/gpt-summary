Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-objects.cc`. They have also specified several constraints and formats for the answer.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The code deals with the internal representation and manipulation of JavaScript objects within the V8 engine. Keywords like `JSObject`, `Map`, `properties`, `elements`, `migration`, and `normalization` are strong indicators.

2. **Break Down Functionality by Examining Functions:** Go through each function in the snippet and understand its role:
    * `MigrateToMap`: This is a central function for changing an object's map (shape/structure). It handles transitions between different property storage mechanisms (fast and slow).
    * `ForceSetPrototype`:  Explicitly sets the prototype of an object.
    * `SetPropertyWithInterceptor`: Deals with property setting when interceptors are involved.
    * `GetElementsTransitionMap`: Retrieves the appropriate map for changing the element storage kind.
    * `AllocateStorageForMap`: Allocates the underlying storage for an object based on its map.
    * `MigrateInstance` and `TryMigrateInstance`: Functions related to migrating an object to an updated map, potentially optimizing its structure.
    * `TryFastAddDataProperty`: Attempts to add a property in an optimized, fast way.
    * `AddProperty`:  A general function for adding properties.
    * `DefineOwnPropertyIgnoreAttributes` and `SetOwnPropertyIgnoreAttributes`, `SetOwnElementIgnoreAttributes`, `DefinePropertyOrElementIgnoreAttributes`: Functions for defining or setting own properties, potentially bypassing certain attribute checks.
    * `GetPropertyAttributesWithInterceptor`: Retrieves property attributes when interceptors are present.
    * `NormalizeProperties`: Converts an object's properties to a dictionary-based storage (slow properties).
    * `MigrateSlowToFast`:  The reverse of `NormalizeProperties`, converting from dictionary-based to faster storage.
    * `RequireSlowElements`: Marks the element dictionary as needing slow elements behavior.
    * `NormalizeElements`:  Converts an object's elements (array-like properties) to a dictionary-based storage.
    * `DeletePropertyWithInterceptor`: Handles property deletion with interceptors.
    * `CreateDataProperty`: Creates a data property on an object.

3. **Group Related Functionality:** Notice patterns and group functions with similar purposes:
    * **Map Management:** `MigrateToMap`, `GetElementsTransitionMap`, `AllocateStorageForMap`, `MigrateInstance`, `TryMigrateInstance`
    * **Property Manipulation (Adding/Defining/Setting):** `TryFastAddDataProperty`, `AddProperty`, `DefineOwnPropertyIgnoreAttributes`, `SetOwnPropertyIgnoreAttributes`, `SetOwnElementIgnoreAttributes`, `DefinePropertyOrElementIgnoreAttributes`, `CreateDataProperty`
    * **Property Manipulation with Interceptors:** `SetPropertyWithInterceptor`, `GetPropertyAttributesWithInterceptor`, `DeletePropertyWithInterceptor`
    * **Property Storage Conversion (Fast/Slow):** `NormalizeProperties`, `MigrateSlowToFast`, `NormalizeElements`, `RequireSlowElements`
    * **Prototype Manipulation:** `ForceSetPrototype`

4. **Identify JavaScript Connections:** For functions related to property manipulation, it's straightforward to provide JavaScript equivalents:
    * Adding/setting properties:  `object.propertyName = value;` or `object['propertyName'] = value;`
    * Defining properties with attributes: `Object.defineProperty(object, 'propertyName', { ... });`
    * Deleting properties: `delete object.propertyName;`
    * Setting prototype: `Object.setPrototypeOf(object, prototype);` or `object.__proto__ = prototype;`

5. **Look for Code Logic and Potential Errors:**
    * **Map Migration:**  The code handles different scenarios (fast-to-fast, fast-to-slow, slow-to-fast). A common error is trying to access properties on an object while it's in an inconsistent state during migration.
    * **Interceptors:** Interceptors add a layer of complexity, and errors can occur if the interceptor's logic is flawed or throws an exception.
    * **Property Attributes:**  Misunderstanding or incorrectly setting property attributes (like `writable`, `enumerable`, `configurable`) is a common JavaScript error.
    * **Fast/Slow Property Transitions:**  Performance issues can arise if objects are constantly switching between fast and slow property storage.

6. **Address the ".tq" Question:**  The code ends in `.cc`, so it's C++, not Torque. Explain what Torque is and its purpose in V8.

7. **Formulate Hypotheses for Input/Output (if applicable):**  For functions like `MigrateToMap` or `AddProperty`, provide a simple example of an object and the expected state after the function executes.

8. **Structure the Response:** Organize the information clearly according to the user's request (functionality, JavaScript examples, code logic, common errors, and the overall summary). Use headings and bullet points for better readability.

9. **Review and Refine:** Ensure the response is accurate, comprehensive, and addresses all aspects of the prompt. Check for clarity and conciseness. For example, initially I might have just listed the function names, but then realized I needed to explain *what* each function does. Also, double-checking the constraints like the "part 5 of 8" is important.
```cpp
property_count);
  }

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  for (InternalIndex i : InternalIndex::Range(real_size)) {
    PropertyDetails details = descs->GetDetails(i);
    Handle<Name> key(descs->GetKey(isolate, i), isolate);
    Handle<Object> value;
    if (details.location() == PropertyLocation::kField) {
      FieldIndex index = FieldIndex::ForDetails(*map, details);
      if (details.kind() == PropertyKind::kData) {
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
        if (details.representation().IsDouble()) {
          DCHECK(IsHeapNumber(*value, isolate));
          double old_value = Cast<HeapNumber>(value)->value();
          value = isolate->factory()->NewHeapNumber(old_value);
        }
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
      }

    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
      value = handle(descs->GetStrongValue(isolate, i), isolate);
    }
    DCHECK(!value.is_null());
    PropertyConstness constness = V8_DICT_PROPERTY_CONST_TRACKING_BOOL
                                      ? details.constness()
                                      : PropertyConstness::kMutable;
    PropertyDetails d(details.kind(), details.attributes(), constness);

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      ord_dictionary =
          SwissNameDictionary::Add(isolate, ord_dictionary, key, value, d);
    } else {
      dictionary = NameDictionary::Add(isolate, dictionary, key, value, d);
    }
  }

  if constexpr (!V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // Copy the next enumeration index from instance descriptor.
    dictionary->set_next_enumeration_index(real_size + 1);
    // TODO(pthier): Add flags to swiss dictionaries.
    dictionary->set_may_have_interesting_properties(
        map->may_have_interesting_properties());
  }

  // From here on we cannot fail and we shouldn't GC anymore.
  DisallowGarbageCollection no_gc;

  Heap* heap = isolate->heap();

  // Resize the object in the heap if necessary.
  int old_instance_size = map->instance_size();
  int new_instance_size = new_map->instance_size();
  int instance_size_delta = old_instance_size - new_instance_size;
  DCHECK_GE(instance_size_delta, 0);

  if (instance_size_delta > 0) {
    heap->NotifyObjectSizeChange(*object, old_instance_size, new_instance_size,
                                 ClearRecordedSlots::kYes);
  }

  // We are storing the new map using release store after creating a filler for
  // the left-over space to avoid races with the sweeper thread.
  object->set_map(isolate, *new_map, kReleaseStore);

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    object->SetProperties(*ord_dictionary);
  } else {
    object->SetProperties(*dictionary);
  }

  // Ensure that in-object space of slow-mode object does not contain random
  // garbage.
  int inobject_properties = new_map->GetInObjectProperties();
  if (inobject_properties) {
    for (int i = 0; i < inobject_properties; i++) {
      FieldIndex index = FieldIndex::ForPropertyIndex(*new_map, i);
      object->FastPropertyAtPut(index, Smi::zero());
    }
  }

#ifdef DEBUG
  if (v8_flags.trace_normalization) {
    StdoutStream os;
    os << "Object properties have been normalized:\n";
    Print(*object, os);
  }
#endif
}

}  // namespace

void JSObject::MigrateToMap(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Map> new_map,
                            int expected_additional_properties) {
  if (object->map(isolate) == *new_map) return;
  DirectHandle<Map> old_map(object->map(isolate), isolate);
  NotifyMapChange(old_map, new_map, isolate);

  if (old_map->is_dictionary_map()) {
    // For slow-to-fast migrations JSObject::MigrateSlowToFast()
    // must be used instead.
    CHECK(new_map->is_dictionary_map());

    // Slow-to-slow migration is trivial.
    object->set_map(isolate, *new_map, kReleaseStore);
  } else if (!new_map->is_dictionary_map()) {
    MigrateFastToFast(isolate, object, new_map);
    if (old_map->is_prototype_map()) {
      DCHECK(!old_map->is_stable());
      DCHECK(new_map->is_stable());
      DCHECK(new_map->owns_descriptors());
      DCHECK(old_map->owns_descriptors());
      // Transfer ownership to the new map. Keep the descriptor pointer of the
      // old map intact because the concurrent marker might be iterating the
      // object with the old map.
      old_map->set_owns_descriptors(false);
      DCHECK(old_map->is_abandoned_prototype_map());
      // Ensure that no transition was inserted for prototype migrations.
      DCHECK_EQ(0,
                TransitionsAccessor(isolate, *old_map).NumberOfTransitions());
      DCHECK(IsUndefined(new_map->GetBackPointer(isolate), isolate));
      DCHECK(object->map(isolate) != *old_map);
    }
  } else {
    MigrateFastToSlow(isolate, object, new_map, expected_additional_properties);
  }

  // Careful: Don't allocate here!
  // For some callers of this method, |object| might be in an inconsistent
  // state now: the new map might have a new elements_kind, but the object's
  // elements pointer hasn't been updated yet. Callers will fix this, but in
  // the meantime, (indirectly) calling JSObjectVerify() must be avoided.
  // When adding code here, add a DisallowGarbageCollection too.
}

void JSObject::ForceSetPrototype(Isolate* isolate,
                                 DirectHandle<JSObject> object,
                                 Handle<JSPrototype> proto) {
  // object.__proto__ = proto;
  Handle<Map> old_map = Handle<Map>(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Copy(isolate, old_map, "ForceSetPrototype");
  Map::SetPrototype(isolate, new_map, proto);
  JSObject::MigrateToMap(isolate, object, new_map);
}

Maybe<InterceptorResult> JSObject::SetPropertyWithInterceptor(
    LookupIterator* it, Maybe<ShouldThrow> should_throw, Handle<Object> value) {
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  return SetPropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                            should_throw, value);
}

Handle<Map> JSObject::GetElementsTransitionMap(DirectHandle<JSObject> object,
                                               ElementsKind to_kind) {
  Handle<Map> map(object->map(), object->GetIsolate());
  return Map::TransitionElementsTo(object->GetIsolate(), map, to_kind);
}

void JSObject::AllocateStorageForMap(Handle<JSObject> object, Handle<Map> map) {
  DCHECK(object->map()->GetInObjectProperties() ==
         map->GetInObjectProperties());
  ElementsKind obj_kind = object->map()->elements_kind();
  ElementsKind map_kind = map->elements_kind();
  Isolate* isolate = object->GetIsolate();
  if (map_kind != obj_kind) {
    ElementsKind to_kind = GetMoreGeneralElementsKind(map_kind, obj_kind);
    if (IsDictionaryElementsKind(obj_kind)) {
      to_kind = obj_kind;
    }
    if (IsDictionaryElementsKind(to_kind)) {
      NormalizeElements(object);
    } else {
      TransitionElementsKind(object, to_kind);
    }
    map = MapUpdater{isolate, map}.ReconfigureElementsKind(to_kind);
  }
  int number_of_fields = map->NumberOfFields(ConcurrencyMode::kSynchronous);
  int inobject = map->GetInObjectProperties();
  int unused = map->UnusedPropertyFields();
  int total_size = number_of_fields + unused;
  int external = total_size - inobject;
  // Allocate mutable double boxes if necessary. It is always necessary if we
  // have external properties, but is also necessary if we only have inobject
  // properties but don't unbox double fields.

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);
  DirectHandle<FixedArray> storage =
      isolate->factory()->NewFixedArray(inobject);

  DirectHandle<PropertyArray> array =
      isolate->factory()->NewPropertyArray(external);

  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    Representation representation = details.representation();
    if (!representation.IsDouble()) continue;
    FieldIndex index = FieldIndex::ForDetails(*map, details);
    auto box = isolate->factory()->NewHeapNumberWithHoleNaN();
    if (index.is_inobject()) {
      storage->set(index.property_index(), *box);
    } else {
      array->set(index.outobject_array_index(), *box);
    }
  }

  object->SetProperties(*array);
  for (int i = 0; i < inobject; i++) {
    FieldIndex index = FieldIndex::ForPropertyIndex(*map, i);
    Tagged<Object> value = storage->get(i);
    object->FastPropertyAtPut(index, value);
  }
  object->set_map(isolate, *map, kReleaseStore);
}

void JSObject::MigrateInstance(Isolate* isolate,
                               DirectHandle<JSObject> object) {
  Handle<Map> original_map(object->map(), isolate);
  DirectHandle<Map> map = Map::Update(isolate, original_map);
  map->set_is_migration_target(true);
  JSObject::MigrateToMap(isolate, object, map);
  if (v8_flags.trace_migration) {
    object->PrintInstanceMigration(stdout, *original_map, *map);
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
}

// static
bool JSObject::TryMigrateInstance(Isolate* isolate,
                                  DirectHandle<JSObject> object) {
  DisallowDeoptimization no_deoptimization(isolate);
  Handle<Map> original_map(object->map(), isolate);
  Handle<Map> new_map;
  if (!Map::TryUpdate(isolate, original_map).ToHandle(&new_map)) {
    return false;
  }
  JSObject::MigrateToMap(isolate, object, new_map);
  if (v8_flags.trace_migration && *original_map != object->map()) {
    object->PrintInstanceMigration(stdout, *original_map, object->map());
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
  return true;
}

namespace {

bool TryFastAddDataProperty(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Name> name, DirectHandle<Object> value,
                            PropertyAttributes attributes) {
  DCHECK(IsUniqueName(*name));
  Tagged<Map> map =
      TransitionsAccessor(isolate, object->map())
          .SearchTransition(*name, PropertyKind::kData, attributes);
  if (map.is_null()) return false;
  DCHECK(!map->is_dictionary_map());

  Handle<Map> new_map = handle(map, isolate);
  if (map->is_deprecated()) {
    new_map = Map::Update(isolate, new_map);
    if (new_map->is_dictionary_map()) return false;
  }

  InternalIndex descriptor = new_map->LastAdded();
  new_map = Map::PrepareForDataProperty(isolate, new_map, descriptor,
                                        PropertyConstness::kConst, value);
  JSObject::MigrateToMap(isolate, object, new_map);
  // TODO(leszeks): Avoid re-loading the property details, which we already
  // loaded in PrepareForDataProperty.
  object->WriteToField(descriptor,
                       new_map->instance_descriptors()->GetDetails(descriptor),
                       *value);
  return true;
}

}  // namespace

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           Handle<Name> name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  name = isolate->factory()->InternalizeName(name);
  if (TryFastAddDataProperty(isolate, object, name, value, attributes)) {
    return;
  }

  LookupIterator it(isolate, object, name, object,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_NE(LookupIterator::ACCESS_CHECK, it.state());
#ifdef DEBUG
  uint32_t index;
  DCHECK(!IsJSProxy(*object));
  DCHECK(!IsWasmObject(*object));
  DCHECK(!name->AsArrayIndex(&index));
  Maybe<PropertyAttributes> maybe = GetPropertyAttributes(&it);
  DCHECK(maybe.IsJust());
  DCHECK(!it.IsFound());
  DCHECK(object->map()->is_extensible() || name->IsPrivate());
#endif
  CHECK(Object::AddDataProperty(&it, value, attributes,
                                Just(ShouldThrow::kThrowOnError),
                                StoreOrigin::kNamed)
            .IsJust());
}

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           const char* name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  JSObject::AddProperty(isolate, object,
                        isolate->factory()->InternalizeUtf8String(name), value,
                        attributes);
}

// Reconfigures a property to a data property with attributes, even if it is not
// reconfigurable.
// Requires a LookupIterator that does not look at the prototype chain beyond
// hidden prototypes.
MaybeHandle<Object> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    AccessorInfoHandling handling, EnforceDefineSemantics semantics) {
  MAYBE_RETURN_NULL(DefineOwnPropertyIgnoreAttributes(
      it, value, attributes, Just(ShouldThrow::kThrowOnError), handling,
      semantics));
  return value;
}

Maybe<bool> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    Maybe<ShouldThrow> should_throw, AccessorInfoHandling handling,
    EnforceDefineSemantics semantics, StoreOrigin store_origin) {
  it->UpdateProtector();

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::JSPROXY:
      case LookupIterator::WASM_OBJECT:
      case LookupIterator::TRANSITION:
        UNREACHABLE();

      case LookupIterator::ACCESS_CHECK:
        if (!it->HasAccess()) {
          Isolate* isolate = it->isolate();
          RETURN_ON_EXCEPTION_VALUE(
              isolate,
              isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
              Nothing<bool>());
          UNREACHABLE();
        }
        continue;

      // If there's an interceptor, try to store the property with the
      // interceptor.
      // In case of success, the attributes will have been reset to the default
      // attributes of the interceptor, rather than the incoming attributes.
      //
      // TODO(verwaest): JSProxy afterwards verify the attributes that the
      // JSProxy claims it has, and verifies that they are compatible. If not,
      // they throw. Here we should do the same.
      case LookupIterator::INTERCEPTOR: {
        InterceptorResult result;
        if (semantics == EnforceDefineSemantics::kDefine) {
          PropertyDescriptor descriptor;
          descriptor.set_configurable((attributes & DONT_DELETE) != 0);
          descriptor.set_enumerable((attributes & DONT_ENUM) != 0);
          descriptor.set_writable((attributes & READ_ONLY) != 0);
          descriptor.set_value(Cast<JSAny>(value));
          if (!DefinePropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                                     should_throw, &descriptor)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
        } else {
          DCHECK_EQ(semantics, EnforceDefineSemantics::kSet);
          if (handling == DONT_FORCE_FIELD) {
            if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                     .To(&result)) {
              // An exception was thrown in the interceptor. Propagate.
              return Nothing<bool>();
            }
          } else {
            result = InterceptorResult::kNotIntercepted;
          }
        }
        switch (result) {
          case InterceptorResult::kFalse:
            return Just(false);
          case InterceptorResult::kTrue:
            return Just(true);
          case InterceptorResult::kNotIntercepted:
            // Proceed lookup.
            break;
        }

        if (semantics == EnforceDefineSemantics::kDefine) {
          it->Restart();
          Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
              it->isolate(), it, value, should_throw);
          if (can_define.IsNothing() || !can_define.FromJust()) {
            return can_define;
          }
        }

        // The interceptor declined to handle the operation, so proceed defining
        // own property without the interceptor.
        Isolate* isolate = it->isolate();
        Handle<JSAny> receiver = it->GetReceiver();
        LookupIterator own_lookup(isolate, receiver, it->GetKey(),
                                  LookupIterator::OWN_SKIP_INTERCEPTOR);
        return JSObject::DefineOwnPropertyIgnoreAttributes(
            &own_lookup, value, attributes, should_throw, handling, semantics,
            store_origin);
      }

      case LookupIterator::ACCESSOR: {
        Handle<Object> accessors = it->GetAccessors();

        // Special handling for AccessorInfo, which behaves like a data
        // property.
        if (IsAccessorInfo(*accessors) && handling == DONT_FORCE_FIELD) {
          PropertyAttributes current_attributes = it->property_attributes();
          // Ensure the context isn't changed after calling into accessors.
          AssertNoContextChange ncc(it->isolate());

          // Update the attributes before calling the setter. The setter may
          // later change the shape of the property.
          if (current_attributes != attributes) {
            it->TransitionToAccessorPair(accessors, attributes);
          }

          return Object::SetPropertyWithAccessor(it, value, should_throw);
        }

        it->ReconfigureDataProperty(value, attributes);
        return Just(true);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Object::RedefineIncompatibleProperty(
            it->isolate(), it->GetName(), value, should_throw);

      case LookupIterator::DATA: {
        // Regular property update if the attributes match.
        if (it->property_attributes() == attributes) {
          return Object::SetDataProperty(it, value);
        }

        // The non-matching attribute case for JSTypedArrays has already been
        // handled by JSTypedArray::DefineOwnProperty.
        DCHECK(!it->IsElement() ||
               !Cast<JSObject>(it->GetReceiver())
                    ->HasTypedArrayOrRabGsabTypedArrayElements());
        // Reconfigure the data property if the attributes mismatch.
        it->ReconfigureDataProperty(value, attributes);

        return Just(true);
      }

      case LookupIterator::NOT_FOUND:
        return Object::AddDataProperty(it, value, attributes, should_throw,
                                       store_origin, semantics);
    }
    UNREACHABLE();
  }
}

MaybeHandle<Object> JSObject::SetOwnPropertyIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsTheHole(*value));
  LookupIterator it(object->GetIsolate(), object, name, object,
                    LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::SetOwnElementIgnoreAttributes(
    Handle<JSObject> object, size_t index, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsJSTypedArray(*object));
  Isolate* isolate = object->GetIsolate();
  LookupIterator it(isolate, object, index, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::DefinePropertyOrElementIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithInterceptor(
    LookupIterator* it) {
  return GetPropertyAttributesWithInterceptorInternal(it, it->GetInterceptor());
}

void JSObject::NormalizeProperties(Isolate* isolate,
                                   DirectHandle<JSObject> object,
                                   PropertyNormalizationMode mode,
                                   int expected_additional_properties,
                                   bool use_cache, const char* reason) {
  if (!object->HasFastProperties()) return;

  Handle<Map> map(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Normalize(isolate, map, map->elements_kind(),
                                             {}, mode, use_cache, reason);

  JSObject::MigrateToMap(isolate, object, new_map,
                         expected_additional_properties);
}

void JSObject::MigrateSlowToFast(DirectHandle<JSObject> object,
                                 int unused_property_fields,
                                 const char* reason) {
  if (object->HasFastProperties()) return;
  DCHECK(!IsJSGlobalObject(*object));
  Isolate* isolate = object->GetIsolate();
  Factory* factory = isolate->factory();

  Handle<NameDictionary> dictionary;
  DirectHandle<SwissNameDictionary> swiss_dictionary;
  int number_of_elements;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    swiss_dictionary = handle(object->property_dictionary_swiss(), isolate);
    number_of_elements = swiss_dictionary->NumberOfElements();
  } else {
    dictionary = handle(object->property_dictionary(), isolate);
    number_of_elements = dictionary->NumberOfElements();
  }

  // Make sure we preserve dictionary representation if there are too many
  // descriptors.
  if (number_of_elements > kMaxNumberOfDescriptors) return;

  DirectHandle<FixedArray> iteration_order;
  int iteration_length;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // |iteration_order| remains empty handle, we don't need it.
    iteration_length = swiss_dictionary->UsedCapacity();
  } else {
    iteration_order = NameDictionary::IterationIndices(isolate, dictionary);
    iteration_length = dictionary->NumberOfElements();
  }

  int number_of_fields = 0;

  // Compute the length of the instance descriptor.
  ReadOnlyRoots roots(isolate);
  for (int i = 0; i < iteration_length; i++) {
    PropertyKind kind;
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key)) {
        // Ignore deleted entries.
        continue;
      }
      kind = swiss_dictionary->DetailsAt(index).kind();
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      DCHECK(dictionary->IsKey(roots, dictionary->KeyAt(isolate, index)));
      kind = dictionary->DetailsAt(index).kind();
    }

    if (kind == PropertyKind::kData) {
      number_of_fields += 1;
    }
  }

  Handle<Map> old_map(object->map(), isolate);

  int inobject_props = old_map->GetInObjectProperties();

  // Allocate new map.
  Handle<Map> new_map = Map::CopyDropDescriptors(isolate, old_map);
  // We should not only set this bit if we need to. We should not retain the
  // old bit because turning a map into dictionary always sets this bit.
  new_map->set_may_have_interesting_properties(
      new_map->has_named_interceptor() || new_map->is_access_check_needed());
  new_map->set_is_dictionary_map(false);

  NotifyMapChange(old_map, new_map, isolate);

  if (number_of_elements == 0) {
    DisallowGarbageCollection no_gc;
    DCHECK_LE(unused_property_fields, inobject_props);
    // Transform the object.
    new_map->SetInObjectUnusedPropertyFields(inobject_props);
    object->set_map(isolate, *new_map, kReleaseStore);
    object->SetProperties(ReadOnlyRoots(isolate).empty_fixed_array());
    // Check that it really works.
    DCHECK(object->HasFastProperties());
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("SlowToFast", old_map, new_map, reason));
    }
    return;
  }

  // Allocate the instance descriptor.
  DirectHandle<DescriptorArray> descriptors =
      DescriptorArray::Allocate(isolate, number_of_elements, 0);

  int number_of_allocated_fields =
      number_of_fields + unused_property_fields - inobject_props;
  if (number_of_allocated_fields < 0) {
    // There is enough inobject space for all fields (including unused).
    number_of_allocated_fields = 0;
    unused_property_fields = inobject_props - number_of_fields;
  }

  // Allocate the property array for the fields.
  DirectHandle<PropertyArray> fields =
      factory->NewPropertyArray(number_of_allocated_fields);

  bool is_transitionable_elements_kind =
      IsTransitionableFastElementsKind(old_map->elements_kind());

  // Fill in the instance descriptor and the fields.
  int current_offset = 0;
  int descriptor_index = 0;
  for (int i = 0; i < iteration_length; i++) {
    Tagged<Name> k;
    Tagged<Object> value;
    PropertyDetails details = PropertyDetails::Empty();

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key_obj = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key_obj)) {
        continue;
      }
      k = Cast<Name>(key_obj);

      value = swiss_dictionary->ValueAt(index);
      details = swiss_dictionary->DetailsAt(index);
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      k = dictionary->NameAt(index);

      value = dictionary->ValueAt(index);
      details = dictionary->DetailsAt(index);
    }

    // Dictionary keys are internalized upon insertion.
    // TODO(jkummerow): Turn this into a DCHECK if it's not hit in the wild.
    CHECK(IsUniqueName(k));
    Handle<Name> key(k, isolate);

    // Properly mark the {new_map} if the {key} is an "interesting symbol".
    if (key->IsInteresting(isolate)) {
      new_map->set_may_have_interesting_properties(true);
    }

    DCHECK_EQ(PropertyLocation::
Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
property_count);
  }

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  for (InternalIndex i : InternalIndex::Range(real_size)) {
    PropertyDetails details = descs->GetDetails(i);
    Handle<Name> key(descs->GetKey(isolate, i), isolate);
    Handle<Object> value;
    if (details.location() == PropertyLocation::kField) {
      FieldIndex index = FieldIndex::ForDetails(*map, details);
      if (details.kind() == PropertyKind::kData) {
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
        if (details.representation().IsDouble()) {
          DCHECK(IsHeapNumber(*value, isolate));
          double old_value = Cast<HeapNumber>(value)->value();
          value = isolate->factory()->NewHeapNumber(old_value);
        }
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
      }

    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
      value = handle(descs->GetStrongValue(isolate, i), isolate);
    }
    DCHECK(!value.is_null());
    PropertyConstness constness = V8_DICT_PROPERTY_CONST_TRACKING_BOOL
                                      ? details.constness()
                                      : PropertyConstness::kMutable;
    PropertyDetails d(details.kind(), details.attributes(), constness);

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      ord_dictionary =
          SwissNameDictionary::Add(isolate, ord_dictionary, key, value, d);
    } else {
      dictionary = NameDictionary::Add(isolate, dictionary, key, value, d);
    }
  }

  if constexpr (!V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // Copy the next enumeration index from instance descriptor.
    dictionary->set_next_enumeration_index(real_size + 1);
    // TODO(pthier): Add flags to swiss dictionaries.
    dictionary->set_may_have_interesting_properties(
        map->may_have_interesting_properties());
  }

  // From here on we cannot fail and we shouldn't GC anymore.
  DisallowGarbageCollection no_gc;

  Heap* heap = isolate->heap();

  // Resize the object in the heap if necessary.
  int old_instance_size = map->instance_size();
  int new_instance_size = new_map->instance_size();
  int instance_size_delta = old_instance_size - new_instance_size;
  DCHECK_GE(instance_size_delta, 0);

  if (instance_size_delta > 0) {
    heap->NotifyObjectSizeChange(*object, old_instance_size, new_instance_size,
                                 ClearRecordedSlots::kYes);
  }

  // We are storing the new map using release store after creating a filler for
  // the left-over space to avoid races with the sweeper thread.
  object->set_map(isolate, *new_map, kReleaseStore);

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    object->SetProperties(*ord_dictionary);
  } else {
    object->SetProperties(*dictionary);
  }

  // Ensure that in-object space of slow-mode object does not contain random
  // garbage.
  int inobject_properties = new_map->GetInObjectProperties();
  if (inobject_properties) {
    for (int i = 0; i < inobject_properties; i++) {
      FieldIndex index = FieldIndex::ForPropertyIndex(*new_map, i);
      object->FastPropertyAtPut(index, Smi::zero());
    }
  }

#ifdef DEBUG
  if (v8_flags.trace_normalization) {
    StdoutStream os;
    os << "Object properties have been normalized:\n";
    Print(*object, os);
  }
#endif
}

}  // namespace

void JSObject::MigrateToMap(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Map> new_map,
                            int expected_additional_properties) {
  if (object->map(isolate) == *new_map) return;
  DirectHandle<Map> old_map(object->map(isolate), isolate);
  NotifyMapChange(old_map, new_map, isolate);

  if (old_map->is_dictionary_map()) {
    // For slow-to-fast migrations JSObject::MigrateSlowToFast()
    // must be used instead.
    CHECK(new_map->is_dictionary_map());

    // Slow-to-slow migration is trivial.
    object->set_map(isolate, *new_map, kReleaseStore);
  } else if (!new_map->is_dictionary_map()) {
    MigrateFastToFast(isolate, object, new_map);
    if (old_map->is_prototype_map()) {
      DCHECK(!old_map->is_stable());
      DCHECK(new_map->is_stable());
      DCHECK(new_map->owns_descriptors());
      DCHECK(old_map->owns_descriptors());
      // Transfer ownership to the new map. Keep the descriptor pointer of the
      // old map intact because the concurrent marker might be iterating the
      // object with the old map.
      old_map->set_owns_descriptors(false);
      DCHECK(old_map->is_abandoned_prototype_map());
      // Ensure that no transition was inserted for prototype migrations.
      DCHECK_EQ(0,
                TransitionsAccessor(isolate, *old_map).NumberOfTransitions());
      DCHECK(IsUndefined(new_map->GetBackPointer(isolate), isolate));
      DCHECK(object->map(isolate) != *old_map);
    }
  } else {
    MigrateFastToSlow(isolate, object, new_map, expected_additional_properties);
  }

  // Careful: Don't allocate here!
  // For some callers of this method, |object| might be in an inconsistent
  // state now: the new map might have a new elements_kind, but the object's
  // elements pointer hasn't been updated yet. Callers will fix this, but in
  // the meantime, (indirectly) calling JSObjectVerify() must be avoided.
  // When adding code here, add a DisallowGarbageCollection too.
}

void JSObject::ForceSetPrototype(Isolate* isolate,
                                 DirectHandle<JSObject> object,
                                 Handle<JSPrototype> proto) {
  // object.__proto__ = proto;
  Handle<Map> old_map = Handle<Map>(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Copy(isolate, old_map, "ForceSetPrototype");
  Map::SetPrototype(isolate, new_map, proto);
  JSObject::MigrateToMap(isolate, object, new_map);
}

Maybe<InterceptorResult> JSObject::SetPropertyWithInterceptor(
    LookupIterator* it, Maybe<ShouldThrow> should_throw, Handle<Object> value) {
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  return SetPropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                            should_throw, value);
}

Handle<Map> JSObject::GetElementsTransitionMap(DirectHandle<JSObject> object,
                                               ElementsKind to_kind) {
  Handle<Map> map(object->map(), object->GetIsolate());
  return Map::TransitionElementsTo(object->GetIsolate(), map, to_kind);
}

void JSObject::AllocateStorageForMap(Handle<JSObject> object, Handle<Map> map) {
  DCHECK(object->map()->GetInObjectProperties() ==
         map->GetInObjectProperties());
  ElementsKind obj_kind = object->map()->elements_kind();
  ElementsKind map_kind = map->elements_kind();
  Isolate* isolate = object->GetIsolate();
  if (map_kind != obj_kind) {
    ElementsKind to_kind = GetMoreGeneralElementsKind(map_kind, obj_kind);
    if (IsDictionaryElementsKind(obj_kind)) {
      to_kind = obj_kind;
    }
    if (IsDictionaryElementsKind(to_kind)) {
      NormalizeElements(object);
    } else {
      TransitionElementsKind(object, to_kind);
    }
    map = MapUpdater{isolate, map}.ReconfigureElementsKind(to_kind);
  }
  int number_of_fields = map->NumberOfFields(ConcurrencyMode::kSynchronous);
  int inobject = map->GetInObjectProperties();
  int unused = map->UnusedPropertyFields();
  int total_size = number_of_fields + unused;
  int external = total_size - inobject;
  // Allocate mutable double boxes if necessary. It is always necessary if we
  // have external properties, but is also necessary if we only have inobject
  // properties but don't unbox double fields.

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);
  DirectHandle<FixedArray> storage =
      isolate->factory()->NewFixedArray(inobject);

  DirectHandle<PropertyArray> array =
      isolate->factory()->NewPropertyArray(external);

  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    Representation representation = details.representation();
    if (!representation.IsDouble()) continue;
    FieldIndex index = FieldIndex::ForDetails(*map, details);
    auto box = isolate->factory()->NewHeapNumberWithHoleNaN();
    if (index.is_inobject()) {
      storage->set(index.property_index(), *box);
    } else {
      array->set(index.outobject_array_index(), *box);
    }
  }

  object->SetProperties(*array);
  for (int i = 0; i < inobject; i++) {
    FieldIndex index = FieldIndex::ForPropertyIndex(*map, i);
    Tagged<Object> value = storage->get(i);
    object->FastPropertyAtPut(index, value);
  }
  object->set_map(isolate, *map, kReleaseStore);
}

void JSObject::MigrateInstance(Isolate* isolate,
                               DirectHandle<JSObject> object) {
  Handle<Map> original_map(object->map(), isolate);
  DirectHandle<Map> map = Map::Update(isolate, original_map);
  map->set_is_migration_target(true);
  JSObject::MigrateToMap(isolate, object, map);
  if (v8_flags.trace_migration) {
    object->PrintInstanceMigration(stdout, *original_map, *map);
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
}

// static
bool JSObject::TryMigrateInstance(Isolate* isolate,
                                  DirectHandle<JSObject> object) {
  DisallowDeoptimization no_deoptimization(isolate);
  Handle<Map> original_map(object->map(), isolate);
  Handle<Map> new_map;
  if (!Map::TryUpdate(isolate, original_map).ToHandle(&new_map)) {
    return false;
  }
  JSObject::MigrateToMap(isolate, object, new_map);
  if (v8_flags.trace_migration && *original_map != object->map()) {
    object->PrintInstanceMigration(stdout, *original_map, object->map());
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
  return true;
}

namespace {

bool TryFastAddDataProperty(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Name> name, DirectHandle<Object> value,
                            PropertyAttributes attributes) {
  DCHECK(IsUniqueName(*name));
  Tagged<Map> map =
      TransitionsAccessor(isolate, object->map())
          .SearchTransition(*name, PropertyKind::kData, attributes);
  if (map.is_null()) return false;
  DCHECK(!map->is_dictionary_map());

  Handle<Map> new_map = handle(map, isolate);
  if (map->is_deprecated()) {
    new_map = Map::Update(isolate, new_map);
    if (new_map->is_dictionary_map()) return false;
  }

  InternalIndex descriptor = new_map->LastAdded();
  new_map = Map::PrepareForDataProperty(isolate, new_map, descriptor,
                                        PropertyConstness::kConst, value);
  JSObject::MigrateToMap(isolate, object, new_map);
  // TODO(leszeks): Avoid re-loading the property details, which we already
  // loaded in PrepareForDataProperty.
  object->WriteToField(descriptor,
                       new_map->instance_descriptors()->GetDetails(descriptor),
                       *value);
  return true;
}

}  // namespace

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           Handle<Name> name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  name = isolate->factory()->InternalizeName(name);
  if (TryFastAddDataProperty(isolate, object, name, value, attributes)) {
    return;
  }

  LookupIterator it(isolate, object, name, object,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_NE(LookupIterator::ACCESS_CHECK, it.state());
#ifdef DEBUG
  uint32_t index;
  DCHECK(!IsJSProxy(*object));
  DCHECK(!IsWasmObject(*object));
  DCHECK(!name->AsArrayIndex(&index));
  Maybe<PropertyAttributes> maybe = GetPropertyAttributes(&it);
  DCHECK(maybe.IsJust());
  DCHECK(!it.IsFound());
  DCHECK(object->map()->is_extensible() || name->IsPrivate());
#endif
  CHECK(Object::AddDataProperty(&it, value, attributes,
                                Just(ShouldThrow::kThrowOnError),
                                StoreOrigin::kNamed)
            .IsJust());
}

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           const char* name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  JSObject::AddProperty(isolate, object,
                        isolate->factory()->InternalizeUtf8String(name), value,
                        attributes);
}

// Reconfigures a property to a data property with attributes, even if it is not
// reconfigurable.
// Requires a LookupIterator that does not look at the prototype chain beyond
// hidden prototypes.
MaybeHandle<Object> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    AccessorInfoHandling handling, EnforceDefineSemantics semantics) {
  MAYBE_RETURN_NULL(DefineOwnPropertyIgnoreAttributes(
      it, value, attributes, Just(ShouldThrow::kThrowOnError), handling,
      semantics));
  return value;
}

Maybe<bool> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    Maybe<ShouldThrow> should_throw, AccessorInfoHandling handling,
    EnforceDefineSemantics semantics, StoreOrigin store_origin) {
  it->UpdateProtector();

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::JSPROXY:
      case LookupIterator::WASM_OBJECT:
      case LookupIterator::TRANSITION:
        UNREACHABLE();

      case LookupIterator::ACCESS_CHECK:
        if (!it->HasAccess()) {
          Isolate* isolate = it->isolate();
          RETURN_ON_EXCEPTION_VALUE(
              isolate,
              isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
              Nothing<bool>());
          UNREACHABLE();
        }
        continue;

      // If there's an interceptor, try to store the property with the
      // interceptor.
      // In case of success, the attributes will have been reset to the default
      // attributes of the interceptor, rather than the incoming attributes.
      //
      // TODO(verwaest): JSProxy afterwards verify the attributes that the
      // JSProxy claims it has, and verifies that they are compatible. If not,
      // they throw. Here we should do the same.
      case LookupIterator::INTERCEPTOR: {
        InterceptorResult result;
        if (semantics == EnforceDefineSemantics::kDefine) {
          PropertyDescriptor descriptor;
          descriptor.set_configurable((attributes & DONT_DELETE) != 0);
          descriptor.set_enumerable((attributes & DONT_ENUM) != 0);
          descriptor.set_writable((attributes & READ_ONLY) != 0);
          descriptor.set_value(Cast<JSAny>(value));
          if (!DefinePropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                                     should_throw, &descriptor)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
        } else {
          DCHECK_EQ(semantics, EnforceDefineSemantics::kSet);
          if (handling == DONT_FORCE_FIELD) {
            if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                     .To(&result)) {
              // An exception was thrown in the interceptor. Propagate.
              return Nothing<bool>();
            }
          } else {
            result = InterceptorResult::kNotIntercepted;
          }
        }
        switch (result) {
          case InterceptorResult::kFalse:
            return Just(false);
          case InterceptorResult::kTrue:
            return Just(true);
          case InterceptorResult::kNotIntercepted:
            // Proceed lookup.
            break;
        }

        if (semantics == EnforceDefineSemantics::kDefine) {
          it->Restart();
          Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
              it->isolate(), it, value, should_throw);
          if (can_define.IsNothing() || !can_define.FromJust()) {
            return can_define;
          }
        }

        // The interceptor declined to handle the operation, so proceed defining
        // own property without the interceptor.
        Isolate* isolate = it->isolate();
        Handle<JSAny> receiver = it->GetReceiver();
        LookupIterator own_lookup(isolate, receiver, it->GetKey(),
                                  LookupIterator::OWN_SKIP_INTERCEPTOR);
        return JSObject::DefineOwnPropertyIgnoreAttributes(
            &own_lookup, value, attributes, should_throw, handling, semantics,
            store_origin);
      }

      case LookupIterator::ACCESSOR: {
        Handle<Object> accessors = it->GetAccessors();

        // Special handling for AccessorInfo, which behaves like a data
        // property.
        if (IsAccessorInfo(*accessors) && handling == DONT_FORCE_FIELD) {
          PropertyAttributes current_attributes = it->property_attributes();
          // Ensure the context isn't changed after calling into accessors.
          AssertNoContextChange ncc(it->isolate());

          // Update the attributes before calling the setter. The setter may
          // later change the shape of the property.
          if (current_attributes != attributes) {
            it->TransitionToAccessorPair(accessors, attributes);
          }

          return Object::SetPropertyWithAccessor(it, value, should_throw);
        }

        it->ReconfigureDataProperty(value, attributes);
        return Just(true);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Object::RedefineIncompatibleProperty(
            it->isolate(), it->GetName(), value, should_throw);

      case LookupIterator::DATA: {
        // Regular property update if the attributes match.
        if (it->property_attributes() == attributes) {
          return Object::SetDataProperty(it, value);
        }

        // The non-matching attribute case for JSTypedArrays has already been
        // handled by JSTypedArray::DefineOwnProperty.
        DCHECK(!it->IsElement() ||
               !Cast<JSObject>(it->GetReceiver())
                    ->HasTypedArrayOrRabGsabTypedArrayElements());
        // Reconfigure the data property if the attributes mismatch.
        it->ReconfigureDataProperty(value, attributes);

        return Just(true);
      }

      case LookupIterator::NOT_FOUND:
        return Object::AddDataProperty(it, value, attributes, should_throw,
                                       store_origin, semantics);
    }
    UNREACHABLE();
  }
}

MaybeHandle<Object> JSObject::SetOwnPropertyIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsTheHole(*value));
  LookupIterator it(object->GetIsolate(), object, name, object,
                    LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::SetOwnElementIgnoreAttributes(
    Handle<JSObject> object, size_t index, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsJSTypedArray(*object));
  Isolate* isolate = object->GetIsolate();
  LookupIterator it(isolate, object, index, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::DefinePropertyOrElementIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithInterceptor(
    LookupIterator* it) {
  return GetPropertyAttributesWithInterceptorInternal(it, it->GetInterceptor());
}

void JSObject::NormalizeProperties(Isolate* isolate,
                                   DirectHandle<JSObject> object,
                                   PropertyNormalizationMode mode,
                                   int expected_additional_properties,
                                   bool use_cache, const char* reason) {
  if (!object->HasFastProperties()) return;

  Handle<Map> map(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Normalize(isolate, map, map->elements_kind(),
                                             {}, mode, use_cache, reason);

  JSObject::MigrateToMap(isolate, object, new_map,
                         expected_additional_properties);
}

void JSObject::MigrateSlowToFast(DirectHandle<JSObject> object,
                                 int unused_property_fields,
                                 const char* reason) {
  if (object->HasFastProperties()) return;
  DCHECK(!IsJSGlobalObject(*object));
  Isolate* isolate = object->GetIsolate();
  Factory* factory = isolate->factory();

  Handle<NameDictionary> dictionary;
  DirectHandle<SwissNameDictionary> swiss_dictionary;
  int number_of_elements;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    swiss_dictionary = handle(object->property_dictionary_swiss(), isolate);
    number_of_elements = swiss_dictionary->NumberOfElements();
  } else {
    dictionary = handle(object->property_dictionary(), isolate);
    number_of_elements = dictionary->NumberOfElements();
  }

  // Make sure we preserve dictionary representation if there are too many
  // descriptors.
  if (number_of_elements > kMaxNumberOfDescriptors) return;

  DirectHandle<FixedArray> iteration_order;
  int iteration_length;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // |iteration_order| remains empty handle, we don't need it.
    iteration_length = swiss_dictionary->UsedCapacity();
  } else {
    iteration_order = NameDictionary::IterationIndices(isolate, dictionary);
    iteration_length = dictionary->NumberOfElements();
  }

  int number_of_fields = 0;

  // Compute the length of the instance descriptor.
  ReadOnlyRoots roots(isolate);
  for (int i = 0; i < iteration_length; i++) {
    PropertyKind kind;
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key)) {
        // Ignore deleted entries.
        continue;
      }
      kind = swiss_dictionary->DetailsAt(index).kind();
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      DCHECK(dictionary->IsKey(roots, dictionary->KeyAt(isolate, index)));
      kind = dictionary->DetailsAt(index).kind();
    }

    if (kind == PropertyKind::kData) {
      number_of_fields += 1;
    }
  }

  Handle<Map> old_map(object->map(), isolate);

  int inobject_props = old_map->GetInObjectProperties();

  // Allocate new map.
  Handle<Map> new_map = Map::CopyDropDescriptors(isolate, old_map);
  // We should not only set this bit if we need to. We should not retain the
  // old bit because turning a map into dictionary always sets this bit.
  new_map->set_may_have_interesting_properties(
      new_map->has_named_interceptor() || new_map->is_access_check_needed());
  new_map->set_is_dictionary_map(false);

  NotifyMapChange(old_map, new_map, isolate);

  if (number_of_elements == 0) {
    DisallowGarbageCollection no_gc;
    DCHECK_LE(unused_property_fields, inobject_props);
    // Transform the object.
    new_map->SetInObjectUnusedPropertyFields(inobject_props);
    object->set_map(isolate, *new_map, kReleaseStore);
    object->SetProperties(ReadOnlyRoots(isolate).empty_fixed_array());
    // Check that it really works.
    DCHECK(object->HasFastProperties());
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("SlowToFast", old_map, new_map, reason));
    }
    return;
  }

  // Allocate the instance descriptor.
  DirectHandle<DescriptorArray> descriptors =
      DescriptorArray::Allocate(isolate, number_of_elements, 0);

  int number_of_allocated_fields =
      number_of_fields + unused_property_fields - inobject_props;
  if (number_of_allocated_fields < 0) {
    // There is enough inobject space for all fields (including unused).
    number_of_allocated_fields = 0;
    unused_property_fields = inobject_props - number_of_fields;
  }

  // Allocate the property array for the fields.
  DirectHandle<PropertyArray> fields =
      factory->NewPropertyArray(number_of_allocated_fields);

  bool is_transitionable_elements_kind =
      IsTransitionableFastElementsKind(old_map->elements_kind());

  // Fill in the instance descriptor and the fields.
  int current_offset = 0;
  int descriptor_index = 0;
  for (int i = 0; i < iteration_length; i++) {
    Tagged<Name> k;
    Tagged<Object> value;
    PropertyDetails details = PropertyDetails::Empty();

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key_obj = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key_obj)) {
        continue;
      }
      k = Cast<Name>(key_obj);

      value = swiss_dictionary->ValueAt(index);
      details = swiss_dictionary->DetailsAt(index);
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      k = dictionary->NameAt(index);

      value = dictionary->ValueAt(index);
      details = dictionary->DetailsAt(index);
    }

    // Dictionary keys are internalized upon insertion.
    // TODO(jkummerow): Turn this into a DCHECK if it's not hit in the wild.
    CHECK(IsUniqueName(k));
    Handle<Name> key(k, isolate);

    // Properly mark the {new_map} if the {key} is an "interesting symbol".
    if (key->IsInteresting(isolate)) {
      new_map->set_may_have_interesting_properties(true);
    }

    DCHECK_EQ(PropertyLocation::kField, details.location());
    DCHECK_IMPLIES(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                   details.constness() == PropertyConstness::kMutable);

    Descriptor d;
    if (details.kind() == PropertyKind::kData) {
      // Ensure that we make constant field only when elements kind is not
      // transitionable.
      PropertyConstness constness = is_transitionable_elements_kind
                                        ? PropertyConstness::kMutable
                                        : PropertyConstness::kConst;
      // TODO(v8:11248): Consider always setting constness to kMutable
      // once all prototypes stay in dictionary mode and we are not interested
      // in tracking constness for fast mode properties anymore.

      d = Descriptor::DataField(
          key, current_offset, details.attributes(), constness,
          // TODO(verwaest): value->OptimalRepresentation();
          Representation::Tagged(), MaybeObjectHandle(FieldType::Any(isolate)));
    } else {
      DCHECK_EQ(PropertyKind::kAccessor, details.kind());
      d = Descriptor::AccessorConstant(key, handle(value, isolate),
                                       details.attributes());
    }
    details = d.GetDetails();
    if (details.location() == PropertyLocation::kField) {
      if (current_offset < inobject_props) {
        object->InObjectPropertyAtPut(current_offset, value,
                                      UPDATE_WRITE_BARRIER);
      } else {
        int offset = current_offset - inobject_props;
        fields->set(offset, value);
      }
      current_offset += details.field_width_in_words();
    }
    descriptors->Set(InternalIndex(descriptor_index++), &d);
  }
  DCHECK_EQ(current_offset, number_of_fields);
  DCHECK_EQ(descriptor_index, number_of_elements);

  descriptors->Sort();

  DisallowGarbageCollection no_gc;
  new_map->InitializeDescriptors(isolate, *descriptors);
  if (number_of_allocated_fields == 0) {
    new_map->SetInObjectUnusedPropertyFields(unused_property_fields);
  } else {
    new_map->SetOutOfObjectUnusedPropertyFields(unused_property_fields);
  }

  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("SlowToFast", old_map, new_map, reason));
  }
  // Transform the object.
  object->set_map(isolate, *new_map, kReleaseStore);

  object->SetProperties(*fields);
  DCHECK(IsJSObject(*object));

  // Check that it really works.
  DCHECK(object->HasFastProperties());
}

void JSObject::RequireSlowElements(Tagged<NumberDictionary> dictionary) {
  DCHECK_NE(dictionary,
            ReadOnlyRoots(GetIsolate()).empty_slow_element_dictionary());
  if (dictionary->requires_slow_elements()) return;
  dictionary->set_requires_slow_elements();
  if (map()->is_prototype_map()) {
    // If this object is a prototype (the callee will check), invalidate any
    // prototype chains involving it.
    InvalidatePrototypeChains(map());
  }
}

Handle<NumberDictionary> JSObject::NormalizeElements(Handle<JSObject> object) {
  DCHECK(!object->HasTypedArrayOrRabGsabTypedArrayElements());
  Isolate* isolate = object->GetIsolate();
  bool is_sloppy_arguments = object->HasSloppyArgumentsElements();
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements = object->elements();

    if (is_sloppy_arguments) {
      elements = Cast<SloppyArgumentsElements>(elements)->arguments();
    }

    if (IsNumberDictionary(elements)) {
      return handle(Cast<NumberDictionary>(elements), isolate);
    }
  }

  DCHECK(object->HasSmiOrObjectElements() || object->HasDoubleElements() ||
         object->HasFastArgumentsElements() ||
         object->HasFastStringWrapperElements() ||
         object->HasSealedElements() || object->HasNonextensibleElements());

  Handle<NumberDictionary> dictionary =
      object->GetElementsAccessor()->Normalize(object);

  // Switch to using the dictionary as the backing storage for elements.
  ElementsKind target_kind =
      is_sloppy_arguments                      ? SLOW_SLOPPY_ARGUMENTS_ELEMENTS
      : object->HasFastStringWrapperElements() ? SLOW_STRING_WRAPPER_ELEMENTS
                                               : DICTIONARY_ELEMENTS;
  DirectHandle<Map> new_map =
      JSObject::GetElementsTransitionMap(object, target_kind);
  // Set the new map first to satify the elements type assert in set_elements().
  JSObject::MigrateToMap(isolate, object, new_map);

  if (is_sloppy_arguments) {
    Cast<SloppyArgumentsElements>(object->elements())
        ->set_arguments(*dictionary);
  } else {
    object->set_elements(*dictionary);
  }

#ifdef DEBUG
  if (v8_flags.trace_normalization) {
    StdoutStream os;
    os << "Object elements have been normalized:\n";
    Print(*object, os);
  }
#endif

  DCHECK(object->HasDictionaryElements() ||
         object->HasSlowArgumentsElements() ||
         object->HasSlowStringWrapperElements());
  return dictionary;
}

Maybe<InterceptorResult> JSObject::DeletePropertyWithInterceptor(
    LookupIterator* it, ShouldThrow should_throw) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  Handle<InterceptorInfo> interceptor(it->GetInterceptor());
  if (IsUndefined(interceptor->deleter(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }
  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }

  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(should_throw));

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedDeleter(interceptor, it->array_index())
          : args.CallNamedDeleter(interceptor, it->name());

  return args.GetBooleanReturnValue(intercepted, "Deleter");
}

Maybe<bool> JSObject::CreateDataProperty(Isolate* isolate,
                                         Handle<JSObject> object,
                                         PropertyKey key, Handle<Object> value,
                                         Maybe<ShouldThrow> should_throw) {
  if (!key.is_element()) {
    if (TryFastAddDataProperty(isolate, object, key.name(), value, NONE)) {
      return Just(true);
    }
  }

  LookupIterator it(isolate, object, key, LookupIterator::OWN);
  Maybe<bool> c
"""


```