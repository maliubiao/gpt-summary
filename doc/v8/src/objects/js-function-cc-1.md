Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-function.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `js-function.cc` strongly suggests this code deals with the internal representation and manipulation of JavaScript functions within V8.

2. **Analyze the key functions:**  Go through the provided functions and understand what each one does. Look for keywords like "prototype", "map", "constructor", "instance", "initial", "derived".

3. **Group related functionalities:**  Notice patterns and group functions that perform similar tasks. For example, functions related to setting up the initial state of a function, or functions related to creating derived maps for subclasses.

4. **Relate to JavaScript concepts:** Connect the internal V8 operations to corresponding JavaScript features. For instance, setting the prototype relates to the `prototype` property in JavaScript.

5. **Look for conditional logic and edge cases:** Pay attention to `if` statements and specific checks. These often handle different scenarios or potential issues.

6. **Infer assumptions and potential errors:**  Based on the code, think about what kind of inputs are expected and what could go wrong if those expectations are not met.

7. **Synthesize a summary:**  Combine the identified functionalities and their JavaScript counterparts into a concise overview.

8. **Address specific instructions:**  Ensure the summary explicitly mentions if the code could be Torque if the filename ended in `.tq`, uses JavaScript examples, explains code logic with hypothetical inputs and outputs, and provides common programming errors related to the code.

**Detailed breakdown of the code:**

* **`SetInstancePrototype`**: Handles setting the `prototype` property of a function. It deals with cases where the provided prototype is not a `JSReceiver` (an object). In such cases, it creates a special tuple to store the non-object prototype.
* **`SetInitialMap`**:  Sets the initial `Map` (V8's internal representation of object structure) for a function. This includes setting the prototype and constructor.
* **`EnsureHasInitialMap`**:  Ensures a function has an initial map. It calculates the expected number of properties and creates a suitable map if one doesn't exist. It also handles the creation and linking of the `prototype` object.
* **`GetDerivedMap`**:  This is crucial for inheritance. It retrieves or creates the appropriate `Map` for objects created using `new` with a subclass constructor. It has a fast path for simple subclasses and a slower path for proxies or when the prototype might not be a `JSReceiver`.
* **`GetDerivedRabGsabTypedArrayMap` and `GetDerivedRabGsabDataViewMap`**:  Specifically handle the creation of Maps for subclasses of TypedArrays and DataViews, considering the Resizable ArrayBuffer (RAB) and Growable SharedArrayBuffer (GSAB).
* **`ComputeInstanceSizeWithMinSlack`**: Calculates the minimum size an instance of the function will occupy in memory, considering potential slack space for future property additions.
* **`GetDebugName` and `SetName`**: Deal with getting and setting the debug name of a function.
* **`ToString`**:  Generates the string representation of a function, similar to what you see when you convert a function to a string in JavaScript. It handles native code, class constructors, and source code availability.
* **`CalculateExpectedNofProperties`**: Estimates the number of properties an object created by the function is likely to have. This helps in efficiently allocating memory for the object.
* **`CalculateInstanceSizeHelper`**:  Calculates the instance size and number of in-object properties based on various factors.
* **`ClearAllTypeFeedbackInfoForTesting`**:  A testing utility to clear type feedback information associated with the function.

**Addressing the specific instructions:**

* **`.tq` extension:** The code is in `.cc`, not `.tq`, so it's C++ code, not Torque.
* **JavaScript relationship:** Many of these functions directly relate to fundamental JavaScript concepts like function creation, prototypes, inheritance, and the `toString()` method.
* **Code logic and examples:**  Illustrate the function behavior with simple examples.
* **Common errors:** Think about typical mistakes developers make related to prototypes and inheritance.
```cpp
         IsGeneratorFunction(function->shared()->kind()));
  Isolate* isolate = function->GetIsolate();
  Handle<JSReceiver> construct_prototype;

  // If the value is not a JSReceiver, store the value in the map's
  // constructor field so it can be accessed. Also, set the prototype
  // used for constructing objects to the original object prototype.
  // See ECMA-262 13.2.2.
  if (!IsJSReceiver(*value)) {
    // Copy the map so this does not affect unrelated functions.
    // Remove map transitions because they point to maps with a
    // different prototype.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(function->map(), isolate), "SetPrototype");

    // Create a new {constructor, non-instance_prototype} tuple and store it
    // in Map::constructor field.
    DirectHandle<Object> constructor(new_map->GetConstructor(), isolate);
    DirectHandle<Tuple2> non_instance_prototype_constructor_tuple =
        isolate->factory()->NewTuple2(constructor, value, AllocationType::kOld);

    new_map->set_has_non_instance_prototype(true);
    new_map->SetConstructor(*non_instance_prototype_constructor_tuple);

    JSObject::MigrateToMap(isolate, function, new_map);

    FunctionKind kind = function->shared()->kind();
    DirectHandle<Context> native_context(function->native_context(), isolate);

    construct_prototype = Handle<JSReceiver>(
        IsGeneratorFunction(kind)
            ? IsAsyncFunction(kind)
                  ? native_context->initial_async_generator_prototype()
                  : native_context->initial_generator_prototype()
            : native_context->initial_object_prototype(),
        isolate);
  } else {
    construct_prototype = Cast<JSReceiver>(value);
    function->map()->set_has_non_instance_prototype(false);
  }

  SetInstancePrototype(isolate, function, construct_prototype);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype) {
  SetInitialMap(isolate, function, map, prototype, function);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype,
                               DirectHandle<JSFunction> constructor) {
  if (map->prototype() != *prototype) {
    Map::SetPrototype(isolate, map, prototype);
  }
  map->SetConstructor(*constructor);
  function->set_prototype_or_initial_map(*map, kReleaseStore);
  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("InitialMap", Handle<Map>(), map, "",
                          SharedFunctionInfo::DebugName(
                              isolate, handle(function->shared(), isolate))));
  }
}

void JSFunction::EnsureHasInitialMap(Handle<JSFunction> function) {
  DCHECK(function->has_prototype_slot());
  DCHECK(IsConstructor(*function) ||
         IsResumableFunction(function->shared()->kind()));
  if (function->has_initial_map()) return;
  Isolate* isolate = function->GetIsolate();

  int expected_nof_properties =
      CalculateExpectedNofProperties(isolate, function);

  // {CalculateExpectedNofProperties} can have had the side effect of creating
  // the initial map (e.g. it could have triggered an optimized compilation
  // whose dependency installation reentered {EnsureHasInitialMap}).
  if (function->has_initial_map()) return;

  // Create a new map with the size and number of in-object properties suggested
  // by the function.
  InstanceType instance_type;
  if (IsResumableFunction(function->shared()->kind())) {
    instance_type = IsAsyncGeneratorFunction(function->shared()->kind())
                        ? JS_ASYNC_GENERATOR_OBJECT_TYPE
                        : JS_GENERATOR_OBJECT_TYPE;
  } else {
    instance_type = JS_OBJECT_TYPE;
  }

  int instance_size;
  int inobject_properties;
  CalculateInstanceSizeHelper(instance_type, false, 0, expected_nof_properties,
                              &instance_size, &inobject_properties);

  Handle<NativeContext> creation_context(function->native_context(), isolate);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      creation_context, instance_type, instance_size,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);

  // Fetch or allocate prototype.
  Handle<JSPrototype> prototype;
  if (function->has_instance_prototype()) {
    prototype = handle(function->instance_prototype(), isolate);
    map->set_prototype(*prototype);
  } else {
    prototype = isolate->factory()->NewFunctionPrototype(function);
    Map::SetPrototype(isolate, map, prototype);
  }
  DCHECK(map->has_fast_object_elements());

  // Finally link initial map and constructor function.
  // This is a CHECK since the prototype could be Null according to the type
  // system.
  // TODO(leszeks): Figure out if this CHECK is needed.
  CHECK(IsJSReceiver(*prototype));
  JSFunction::SetInitialMap(isolate, function, map, prototype);
  map->StartInobjectSlackTracking();
}

namespace {

#ifdef DEBUG
bool CanSubclassHaveInobjectProperties(InstanceType instance_type) {
  switch (instance_type) {
    case JS_API_OBJECT_TYPE:
    case JS_ARRAY_BUFFER_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARRAY_TYPE:
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
    case JS_DATE_TYPE:
    case JS_GENERATOR_OBJECT_TYPE:
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
#ifdef V8_INTL_SUPPORT
    case JS_COLLATOR_TYPE:
    case JS_DATE_TIME_FORMAT_TYPE:
    case JS_DISPLAY_NAMES_TYPE:
    case JS_DURATION_FORMAT_TYPE:
    case JS_LIST_FORMAT_TYPE:
    case JS_LOCALE_TYPE:
    case JS_NUMBER_FORMAT_TYPE:
    case JS_PLURAL_RULES_TYPE:
    case JS_RELATIVE_TIME_FORMAT_TYPE:
    case JS_SEGMENT_ITERATOR_TYPE:
    case JS_SEGMENTER_TYPE:
    case JS_SEGMENTS_TYPE:
    case JS_V8_BREAK_ITERATOR_TYPE:
#endif
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case JS_MAP_TYPE:
    case JS_MESSAGE_OBJECT_TYPE:
    case JS_OBJECT_TYPE:
    case JS_ERROR_TYPE:
    case JS_FINALIZATION_REGISTRY_TYPE:
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_PROMISE_TYPE:
    case JS_REG_EXP_TYPE:
    case JS_SET_TYPE:
    case JS_SHADOW_REALM_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_TYPED_ARRAY_TYPE:
    case JS_PRIMITIVE_WRAPPER_TYPE:
    case JS_TEMPORAL_CALENDAR_TYPE:
    case JS_TEMPORAL_DURATION_TYPE:
    case JS_TEMPORAL_INSTANT_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
    case JS_TEMPORAL_TIME_ZONE_TYPE:
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
    case JS_WEAK_MAP_TYPE:
    case JS_WEAK_REF_TYPE:
    case JS_WEAK_SET_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
    case WASM_INSTANCE_OBJECT_TYPE:
    case WASM_MEMORY_OBJECT_TYPE:
    case WASM_MODULE_OBJECT_TYPE:
    case WASM_TABLE_OBJECT_TYPE:
    case WASM_VALUE_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;

    case BIGINT_TYPE:
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
    case BYTECODE_ARRAY_TYPE:
    case BYTE_ARRAY_TYPE:
    case CELL_TYPE:
    case INSTRUCTION_STREAM_TYPE:
    case FILLER_TYPE:
    case FIXED_ARRAY_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case FIXED_DOUBLE_ARRAY_TYPE:
    case FEEDBACK_METADATA_TYPE:
    case FOREIGN_TYPE:
    case FREE_SPACE_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HEAP_NUMBER_TYPE:
    case JS_BOUND_FUNCTION_TYPE:
    case JS_GLOBAL_OBJECT_TYPE:
    case JS_GLOBAL_PROXY_TYPE:
    case JS_PROXY_TYPE:
    case JS_WRAPPED_FUNCTION_TYPE:
    case MAP_TYPE:
    case ODDBALL_TYPE:
    case PROPERTY_CELL_TYPE:
    case CONTEXT_SIDE_PROPERTY_CELL_TYPE:
    case SHARED_FUNCTION_INFO_TYPE:
    case SYMBOL_TYPE:
    case ALLOCATION_SITE_TYPE:

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype, size) \
  case FIXED_##TYPE##_ARRAY_TYPE:
#undef TYPED_ARRAY_CASE

#define MAKE_STRUCT_CASE(TYPE, Name, name) case TYPE:
      STRUCT_LIST(MAKE_STRUCT_CASE)
#undef MAKE_STRUCT_CASE
      // We must not end up here for these instance types at all.
      UNREACHABLE();

    default:
      if (InstanceTypeChecker::IsJSApiObject(instance_type)) return true;
      return false;
  }
}
#endif  // DEBUG

bool FastInitializeDerivedMap(Isolate* isolate, Handle<JSFunction> new_target,
                              DirectHandle<JSFunction> constructor,
                              Handle<Map> constructor_initial_map) {
  // Use the default intrinsic prototype instead.
  if (!new_target->has_prototype_slot()) return false;
  // Check that |function|'s initial map still in sync with the |constructor|,
  // otherwise we must create a new initial map for |function|.
  if (new_target->has_initial_map() &&
      new_target->initial_map()->GetConstructor() == *constructor) {
    DCHECK(IsJSReceiver(new_target->instance_prototype()));
    return true;
  }
  InstanceType instance_type = constructor_initial_map->instance_type();
  DCHECK(CanSubclassHaveInobjectProperties(instance_type));
  // Create a new map with the size and number of in-object properties
  // suggested by |function|.

  // Link initial map and constructor function if the new.target is actually a
  // subclass constructor.
  if (!IsDerivedConstructor(new_target->shared()->kind())) return false;

  int instance_size;
  int in_object_properties;
  int embedder_fields =
      JSObject::GetEmbedderFieldCount(*constructor_initial_map);
  // Constructor expects certain number of in-object properties to be in the
  // object. However, CalculateExpectedNofProperties() may return smaller value
  // if 1) the constructor is not in the prototype chain of new_target, or
  // 2) the prototype chain is modified during iteration, or 3) compilation
  // failure occur during prototype chain iteration.
  // So we take the maximum of two values.
  int expected_nof_properties = std::max(
      static_cast<int>(constructor->shared()->expected_nof_properties()),
      JSFunction::CalculateExpectedNofProperties(isolate, new_target));
  JSFunction::CalculateInstanceSizeHelper(
      instance_type, constructor_initial_map->has_prototype_slot(),
      embedder_fields, expected_nof_properties, &instance_size,
      &in_object_properties);

  int pre_allocated = constructor_initial_map->GetInObjectProperties() -
                      constructor_initial_map->UnusedPropertyFields();
  CHECK_LE(constructor_initial_map->UsedInstanceSize(), instance_size);
  int unused_property_fields = in_object_properties - pre_allocated;
  Handle<Map> map =
      Map::CopyInitialMap(isolate, constructor_initial_map, instance_size,
                          in_object_properties, unused_property_fields);
  map->set_new_target_is_base(false);
  Handle<JSPrototype> prototype(new_target->instance_prototype(), isolate);
  JSFunction::SetInitialMap(isolate, new_target, map, prototype, constructor);
  DCHECK(IsJSReceiver(new_target->instance_prototype()));
  map->construction_counter() = Map::kNoSlackTracking;
  map->StartInobjectSlackTracking();
  return true;
}

}  // namespace

// static
MaybeHandle<Map> JSFunction::GetDerivedMap(Isolate* isolate,
                                           Handle<JSFunction> constructor,
                                           Handle<JSReceiver> new_target) {
  EnsureHasInitialMap(constructor);

  Handle<Map> constructor_initial_map(constructor->initial_map(), isolate);
  if (*new_target == *constructor) return constructor_initial_map;

  DirectHandle<Map> result_map;
  // Fast case, new.target is a subclass of constructor. The map is cacheable
  // (and may already have been cached). new.target.prototype is guaranteed to
  // be a JSReceiver.
  InstanceType new_target_instance_type = new_target->map()->instance_type();
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type)) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    if (FastInitializeDerivedMap(isolate, function, constructor,
                                 constructor_initial_map)) {
      return handle(function->initial_map(), isolate);
    }
  }

  // Slow path, new.target is either a proxy object or can't cache the map.
  // new.target.prototype is not guaranteed to be a JSReceiver, and may need to
  // fall back to the intrinsicDefaultProto.
  Handle<Object> prototype;
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type) &&
      Cast<JSFunction>(new_target)->has_prototype_slot()) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    // Make sure the new.target.prototype is cached.
    EnsureHasInitialMap(function);
    prototype = handle(function->prototype(), isolate);
  } else {
    // The new.target is a constructor but it's not a JSFunction with
    // a prototype slot, so get the prototype property.
    Handle<String> prototype_string = isolate->factory()->prototype_string();
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, prototype,
        JSReceiver::GetProperty(isolate, new_target, prototype_string));
    // The above prototype lookup might change the constructor and its
    // prototype, hence we have to reload the initial map.
    EnsureHasInitialMap(constructor);
    constructor_initial_map = handle(constructor->initial_map(), isolate);
  }

  // If prototype is not a JSReceiver, fetch the intrinsicDefaultProto from the
  // correct realm. Rather than directly fetching the .prototype, we fetch the
  // constructor that points to the .prototype. This relies on
  // constructor.prototype being FROZEN for those constructors.
  if (!IsJSReceiver(*prototype)) {
    Handle<NativeContext> native_context;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, native_context,
                               JSReceiver::GetFunctionRealm(new_target));
    DirectHandle<Object> maybe_index = JSReceiver::GetDataProperty(
        isolate, constructor,
        isolate->factory()->native_context_index_symbol());
    int index = IsSmi(*maybe_index) ? Smi::ToInt(*maybe_index)
                                    : Context::OBJECT_FUNCTION_INDEX;
    DirectHandle<JSFunction> realm_constructor(
        Cast<JSFunction>(native_context->get(index)), isolate);
    prototype = handle(realm_constructor->prototype(), isolate);
  }
  DCHECK_EQ(constructor_initial_map->constructor_or_back_pointer(),
            *constructor);
  return Map::GetDerivedMap(isolate, constructor_initial_map,
                            Cast<JSReceiver>(prototype));
}

namespace {

// Assert that the computations in TypedArrayElementsKindToConstructorIndex and
// TypedArrayElementsKindToRabGsabCtorIndex are sound.
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                         \
  static_assert(Context::TYPE##_ARRAY_FUN_INDEX ==                        \
                Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX +              \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND); \
  static_assert(Context::RAB_GSAB_##TYPE##_ARRAY_MAP_INDEX ==             \
                Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX +           \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND);

TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

int TypedArrayElementsKindToConstructorIndex(ElementsKind elements_kind) {
  return Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

int TypedArrayElementsKindToRabGsabCtorIndex(ElementsKind elements_kind) {
  return Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

}  // namespace

MaybeHandle<Map> JSFunction::GetDerivedRabGsabTypedArrayMap(
    Isolate* isolate, Handle<JSFunction> constructor,
    Handle<JSReceiver> new_target) {
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  {
    DisallowHeapAllocation no_alloc;
    Tagged<NativeContext> context = isolate->context()->native_context();
    int ctor_index =
        TypedArrayElementsKindToConstructorIndex(map->elements_kind());
    if (*new_target == context->get(ctor_index)) {
      ctor_index =
          TypedArrayElementsKindToRabGsabCtorIndex(map->elements_kind());
      return handle(Cast<Map>(context->get(ctor_index)), isolate);
    }
  }

  // This only happens when subclassing TypedArrays. Create a new map with the
  // corresponding RAB / GSAB ElementsKind. Note: the map is not cached and
  // reused -> every array gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_elements_kind(
      GetCorrespondingRabGsabElementsKind(map->elements_kind()));
  return rab_gsab_map;
}

MaybeHandle<Map> JSFunction::GetDerivedRabGsabDataViewMap(
    Isolate* isolate, Handle<JSReceiver> new_target) {
  DirectHandle<Context> context(isolate->context()->native_context(), isolate);
  Handle<JSFunction> constructor(context->data_view_fun(), isolate);
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  if (*map == constructor->initial_map()) {
    return handle(Cast<Map>(context->js_rab_gsab_data_view_map()), isolate);
  }

  // This only happens when subclassing DataViews. Create a new map with the
  // JS_RAB_GSAB_DATA_VIEW instance type. Note: the map is not cached and
  // reused -> every data view gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_instance_type(JS_RAB_GSAB_DATA_VIEW_TYPE);
  return rab_gsab_map;
}

int JSFunction::ComputeInstanceSizeWithMinSlack(Isolate* isolate) {
  CHECK(has_initial_map());
  if (initial_map()->IsInobjectSlackTrackingInProgress()) {
    int slack = initial_map()->ComputeMinObjectSlack(isolate);
    return initial_map()->InstanceSizeFromSlack(slack);
  }
  return initial_map()->instance_size();
}

std::unique_ptr<char[]> JSFunction::DebugNameCStr() {
  return shared()->DebugNameCStr();
}

void JSFunction::PrintName(FILE* out) {
  PrintF(out, "%s", DebugNameCStr().get());
}

namespace {

bool UseFastFunctionNameLookup(Isolate* isolate, Tagged<Map> map) {
  DCHECK(IsJSFunctionMap(map));
  if (map->NumberOfOwnDescriptors() <
      JSFunction::kMinDescriptorsForFastBindAndWrap) {
    return false;
  }
  DCHECK(!map->is_dictionary_map());
  Tagged<HeapObject> value;
  ReadOnlyRoots roots(isolate);
  auto descriptors = map->instance_descriptors(isolate);
  InternalIndex kNameIndex{JSFunction::kNameDescriptorIndex};
  if (descriptors->GetKey(kNameIndex) != roots.name_string() ||
      !descriptors->GetValue(kNameIndex)
           .GetHeapObjectIfStrong(isolate, &value)) {
    return false;
  }
  return IsAccessorInfo(value);
}

}  // namespace

Handle<String> JSFunction::GetDebugName(Handle<JSFunction> function) {
  // Below we use the same fast-path that we already established for
  // Function.prototype.bind(), where we avoid a slow "name" property
  // lookup if the DescriptorArray for the |function| still has the
  // "name" property at the original spot and that property is still
  // implemented via an AccessorInfo (which effectively means that
  // it must be the FunctionNameGetter).
  Isolate* isolate = function->GetIsolate();
  if (!UseFastFunctionNameLookup(isolate, function->map())) {
    // Normally there should be an else case for the fast-path check
    // above, which should invoke JSFunction::GetName(), since that's
    // what the FunctionNameGetter does, however GetDataProperty() has
    // never invoked accessors and thus always returned undefined for
    // JSFunction where the "name" property is untouched, so we retain
    // that exact behavior and go with SharedFunctionInfo::DebugName()
    // in case of the fast-path.
    Handle<Object> name =
        GetDataProperty(isolate, function, isolate->factory()->name_string());
    if (IsString(*name)) return Cast<String>(name);
  }
  return SharedFunctionInfo::DebugName(isolate,
                                       handle(function->shared(), isolate));
}

bool JSFunction::SetName(Handle<JSFunction> function, Handle<Name> name,
                         DirectHandle<String> prefix) {
  Isolate* isolate = function->GetIsolate();
  Handle<String> function_name;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                   Name::ToFunctionName(isolate, name), false);
  if (prefix->length() > 0) {
    IncrementalStringBuilder builder(isolate);
    builder.AppendString(prefix);
    builder.AppendCharacter(' ');
    builder.AppendString(function_name);
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                     indirect_handle(builder.Finish(), isolate),
                                     false);
  }
  RETURN_ON_EXCEPTION_VALUE(
      isolate,
      JSObject::DefinePropertyOrElementIgnoreAttributes(
          function, isolate->factory()->name_string(), function_name,
          static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY)),
      false);
  return true;
}

namespace {

Handle<String> NativeCodeFunctionSourceString(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared_info) {
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("function ");
  builder.AppendString(handle(shared_info->Name(), isolate));
  builder.AppendCStringLiteral("() { [native code] }");
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

}  // namespace

// static
Handle<String> JSFunction::ToString(DirectHandle<JSFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  DirectHandle<SharedFunctionInfo> shared_info(function->shared(), isolate);

  // Check if {function} should hide its source code.
  if (!shared_info->IsUserJavaScript()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  if (IsClassConstructor(shared_info->kind())) {
    // Check if we should print {function} as a class.
    DirectHandle<Object> maybe_class_positions = JSReceiver::GetDataProperty(
        isolate, indirect_handle(function, isolate),
        isolate->factory()->class_positions_symbol());
    if (IsClassPositions(*maybe_class_positions)) {
      Tagged<ClassPositions> class_positions =
          Cast<ClassPositions>(*maybe_class_positions);
      int start_position = class_positions->start();
      int end_position = class_positions->end();
      Handle<String> script_source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(script_source, start_position,
                                              end_position);
    }
  }

  // Check if we have source code for the {function}.
  if (!shared_info->HasSourceCode()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  // If this function was compiled from asm.js, use the recorded offset
  // information.
#if V8_ENABLE_WEBASSEMBLY
  if (shared_info->HasWasmExportedFunctionData()) {
    DirectHandle<WasmExportedFunctionData> function_data(
        shared_info->wasm_exported_function_data(), isolate);
    const wasm::WasmModule* module = function_data->instance_data()->module();
    if (is_asmjs_module(module)) {
      std::pair<int, int> offsets =
          module->asm_js_offset_information->GetFunctionOffsets(
              declared_function_index(module, function_data->function_index()));
      Handle<String> source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(source, offsets.first,
                                              offsets.second);
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (shared_info->function_token_position() == kNoSourcePosition) {
    // If the function token position isn't valid, return [native code] to
    // ensure calling eval on the returned source code throws rather than
    // giving inconsistent call behaviour.
    isolate->CountUsage(
        v8::Isolate::UseCounterFeature::kFunctionTokenOffsetTooLongForToString);
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }
  return Cast<String>(
      SharedFunctionInfo::GetSourceCodeHarmony(isolate, shared_info));
}

// static
int JSFunction::CalculateExpectedNofProperties(Isolate* isolate,
                                               Handle<JSFunction> function) {
  int expected_nof_properties = 0;
  for (PrototypeIterator iter(isolate, function,
### 提示词
```
这是目录为v8/src/objects/js-function.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-function.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
IsGeneratorFunction(function->shared()->kind()));
  Isolate* isolate = function->GetIsolate();
  Handle<JSReceiver> construct_prototype;

  // If the value is not a JSReceiver, store the value in the map's
  // constructor field so it can be accessed.  Also, set the prototype
  // used for constructing objects to the original object prototype.
  // See ECMA-262 13.2.2.
  if (!IsJSReceiver(*value)) {
    // Copy the map so this does not affect unrelated functions.
    // Remove map transitions because they point to maps with a
    // different prototype.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(function->map(), isolate), "SetPrototype");

    // Create a new {constructor, non-instance_prototype} tuple and store it
    // in Map::constructor field.
    DirectHandle<Object> constructor(new_map->GetConstructor(), isolate);
    DirectHandle<Tuple2> non_instance_prototype_constructor_tuple =
        isolate->factory()->NewTuple2(constructor, value, AllocationType::kOld);

    new_map->set_has_non_instance_prototype(true);
    new_map->SetConstructor(*non_instance_prototype_constructor_tuple);

    JSObject::MigrateToMap(isolate, function, new_map);

    FunctionKind kind = function->shared()->kind();
    DirectHandle<Context> native_context(function->native_context(), isolate);

    construct_prototype = Handle<JSReceiver>(
        IsGeneratorFunction(kind)
            ? IsAsyncFunction(kind)
                  ? native_context->initial_async_generator_prototype()
                  : native_context->initial_generator_prototype()
            : native_context->initial_object_prototype(),
        isolate);
  } else {
    construct_prototype = Cast<JSReceiver>(value);
    function->map()->set_has_non_instance_prototype(false);
  }

  SetInstancePrototype(isolate, function, construct_prototype);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype) {
  SetInitialMap(isolate, function, map, prototype, function);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype,
                               DirectHandle<JSFunction> constructor) {
  if (map->prototype() != *prototype) {
    Map::SetPrototype(isolate, map, prototype);
  }
  map->SetConstructor(*constructor);
  function->set_prototype_or_initial_map(*map, kReleaseStore);
  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("InitialMap", Handle<Map>(), map, "",
                          SharedFunctionInfo::DebugName(
                              isolate, handle(function->shared(), isolate))));
  }
}

void JSFunction::EnsureHasInitialMap(Handle<JSFunction> function) {
  DCHECK(function->has_prototype_slot());
  DCHECK(IsConstructor(*function) ||
         IsResumableFunction(function->shared()->kind()));
  if (function->has_initial_map()) return;
  Isolate* isolate = function->GetIsolate();

  int expected_nof_properties =
      CalculateExpectedNofProperties(isolate, function);

  // {CalculateExpectedNofProperties} can have had the side effect of creating
  // the initial map (e.g. it could have triggered an optimized compilation
  // whose dependency installation reentered {EnsureHasInitialMap}).
  if (function->has_initial_map()) return;

  // Create a new map with the size and number of in-object properties suggested
  // by the function.
  InstanceType instance_type;
  if (IsResumableFunction(function->shared()->kind())) {
    instance_type = IsAsyncGeneratorFunction(function->shared()->kind())
                        ? JS_ASYNC_GENERATOR_OBJECT_TYPE
                        : JS_GENERATOR_OBJECT_TYPE;
  } else {
    instance_type = JS_OBJECT_TYPE;
  }

  int instance_size;
  int inobject_properties;
  CalculateInstanceSizeHelper(instance_type, false, 0, expected_nof_properties,
                              &instance_size, &inobject_properties);

  Handle<NativeContext> creation_context(function->native_context(), isolate);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      creation_context, instance_type, instance_size,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);

  // Fetch or allocate prototype.
  Handle<JSPrototype> prototype;
  if (function->has_instance_prototype()) {
    prototype = handle(function->instance_prototype(), isolate);
    map->set_prototype(*prototype);
  } else {
    prototype = isolate->factory()->NewFunctionPrototype(function);
    Map::SetPrototype(isolate, map, prototype);
  }
  DCHECK(map->has_fast_object_elements());

  // Finally link initial map and constructor function.
  // This is a CHECK since the prototype could be Null according to the type
  // system.
  // TODO(leszeks): Figure out if this CHECK is needed.
  CHECK(IsJSReceiver(*prototype));
  JSFunction::SetInitialMap(isolate, function, map, prototype);
  map->StartInobjectSlackTracking();
}

namespace {

#ifdef DEBUG
bool CanSubclassHaveInobjectProperties(InstanceType instance_type) {
  switch (instance_type) {
    case JS_API_OBJECT_TYPE:
    case JS_ARRAY_BUFFER_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARRAY_TYPE:
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
    case JS_DATE_TYPE:
    case JS_GENERATOR_OBJECT_TYPE:
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
#ifdef V8_INTL_SUPPORT
    case JS_COLLATOR_TYPE:
    case JS_DATE_TIME_FORMAT_TYPE:
    case JS_DISPLAY_NAMES_TYPE:
    case JS_DURATION_FORMAT_TYPE:
    case JS_LIST_FORMAT_TYPE:
    case JS_LOCALE_TYPE:
    case JS_NUMBER_FORMAT_TYPE:
    case JS_PLURAL_RULES_TYPE:
    case JS_RELATIVE_TIME_FORMAT_TYPE:
    case JS_SEGMENT_ITERATOR_TYPE:
    case JS_SEGMENTER_TYPE:
    case JS_SEGMENTS_TYPE:
    case JS_V8_BREAK_ITERATOR_TYPE:
#endif
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case JS_MAP_TYPE:
    case JS_MESSAGE_OBJECT_TYPE:
    case JS_OBJECT_TYPE:
    case JS_ERROR_TYPE:
    case JS_FINALIZATION_REGISTRY_TYPE:
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_PROMISE_TYPE:
    case JS_REG_EXP_TYPE:
    case JS_SET_TYPE:
    case JS_SHADOW_REALM_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_TYPED_ARRAY_TYPE:
    case JS_PRIMITIVE_WRAPPER_TYPE:
    case JS_TEMPORAL_CALENDAR_TYPE:
    case JS_TEMPORAL_DURATION_TYPE:
    case JS_TEMPORAL_INSTANT_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
    case JS_TEMPORAL_TIME_ZONE_TYPE:
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
    case JS_WEAK_MAP_TYPE:
    case JS_WEAK_REF_TYPE:
    case JS_WEAK_SET_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
    case WASM_INSTANCE_OBJECT_TYPE:
    case WASM_MEMORY_OBJECT_TYPE:
    case WASM_MODULE_OBJECT_TYPE:
    case WASM_TABLE_OBJECT_TYPE:
    case WASM_VALUE_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;

    case BIGINT_TYPE:
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
    case BYTECODE_ARRAY_TYPE:
    case BYTE_ARRAY_TYPE:
    case CELL_TYPE:
    case INSTRUCTION_STREAM_TYPE:
    case FILLER_TYPE:
    case FIXED_ARRAY_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case FIXED_DOUBLE_ARRAY_TYPE:
    case FEEDBACK_METADATA_TYPE:
    case FOREIGN_TYPE:
    case FREE_SPACE_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HEAP_NUMBER_TYPE:
    case JS_BOUND_FUNCTION_TYPE:
    case JS_GLOBAL_OBJECT_TYPE:
    case JS_GLOBAL_PROXY_TYPE:
    case JS_PROXY_TYPE:
    case JS_WRAPPED_FUNCTION_TYPE:
    case MAP_TYPE:
    case ODDBALL_TYPE:
    case PROPERTY_CELL_TYPE:
    case CONTEXT_SIDE_PROPERTY_CELL_TYPE:
    case SHARED_FUNCTION_INFO_TYPE:
    case SYMBOL_TYPE:
    case ALLOCATION_SITE_TYPE:

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype, size) \
  case FIXED_##TYPE##_ARRAY_TYPE:
#undef TYPED_ARRAY_CASE

#define MAKE_STRUCT_CASE(TYPE, Name, name) case TYPE:
      STRUCT_LIST(MAKE_STRUCT_CASE)
#undef MAKE_STRUCT_CASE
      // We must not end up here for these instance types at all.
      UNREACHABLE();

    default:
      if (InstanceTypeChecker::IsJSApiObject(instance_type)) return true;
      return false;
  }
}
#endif  // DEBUG

bool FastInitializeDerivedMap(Isolate* isolate, Handle<JSFunction> new_target,
                              DirectHandle<JSFunction> constructor,
                              Handle<Map> constructor_initial_map) {
  // Use the default intrinsic prototype instead.
  if (!new_target->has_prototype_slot()) return false;
  // Check that |function|'s initial map still in sync with the |constructor|,
  // otherwise we must create a new initial map for |function|.
  if (new_target->has_initial_map() &&
      new_target->initial_map()->GetConstructor() == *constructor) {
    DCHECK(IsJSReceiver(new_target->instance_prototype()));
    return true;
  }
  InstanceType instance_type = constructor_initial_map->instance_type();
  DCHECK(CanSubclassHaveInobjectProperties(instance_type));
  // Create a new map with the size and number of in-object properties
  // suggested by |function|.

  // Link initial map and constructor function if the new.target is actually a
  // subclass constructor.
  if (!IsDerivedConstructor(new_target->shared()->kind())) return false;

  int instance_size;
  int in_object_properties;
  int embedder_fields =
      JSObject::GetEmbedderFieldCount(*constructor_initial_map);
  // Constructor expects certain number of in-object properties to be in the
  // object. However, CalculateExpectedNofProperties() may return smaller value
  // if 1) the constructor is not in the prototype chain of new_target, or
  // 2) the prototype chain is modified during iteration, or 3) compilation
  // failure occur during prototype chain iteration.
  // So we take the maximum of two values.
  int expected_nof_properties = std::max(
      static_cast<int>(constructor->shared()->expected_nof_properties()),
      JSFunction::CalculateExpectedNofProperties(isolate, new_target));
  JSFunction::CalculateInstanceSizeHelper(
      instance_type, constructor_initial_map->has_prototype_slot(),
      embedder_fields, expected_nof_properties, &instance_size,
      &in_object_properties);

  int pre_allocated = constructor_initial_map->GetInObjectProperties() -
                      constructor_initial_map->UnusedPropertyFields();
  CHECK_LE(constructor_initial_map->UsedInstanceSize(), instance_size);
  int unused_property_fields = in_object_properties - pre_allocated;
  Handle<Map> map =
      Map::CopyInitialMap(isolate, constructor_initial_map, instance_size,
                          in_object_properties, unused_property_fields);
  map->set_new_target_is_base(false);
  Handle<JSPrototype> prototype(new_target->instance_prototype(), isolate);
  JSFunction::SetInitialMap(isolate, new_target, map, prototype, constructor);
  DCHECK(IsJSReceiver(new_target->instance_prototype()));
  map->set_construction_counter(Map::kNoSlackTracking);
  map->StartInobjectSlackTracking();
  return true;
}

}  // namespace

// static
MaybeHandle<Map> JSFunction::GetDerivedMap(Isolate* isolate,
                                           Handle<JSFunction> constructor,
                                           Handle<JSReceiver> new_target) {
  EnsureHasInitialMap(constructor);

  Handle<Map> constructor_initial_map(constructor->initial_map(), isolate);
  if (*new_target == *constructor) return constructor_initial_map;

  DirectHandle<Map> result_map;
  // Fast case, new.target is a subclass of constructor. The map is cacheable
  // (and may already have been cached). new.target.prototype is guaranteed to
  // be a JSReceiver.
  InstanceType new_target_instance_type = new_target->map()->instance_type();
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type)) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    if (FastInitializeDerivedMap(isolate, function, constructor,
                                 constructor_initial_map)) {
      return handle(function->initial_map(), isolate);
    }
  }

  // Slow path, new.target is either a proxy object or can't cache the map.
  // new.target.prototype is not guaranteed to be a JSReceiver, and may need to
  // fall back to the intrinsicDefaultProto.
  Handle<Object> prototype;
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type) &&
      Cast<JSFunction>(new_target)->has_prototype_slot()) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    // Make sure the new.target.prototype is cached.
    EnsureHasInitialMap(function);
    prototype = handle(function->prototype(), isolate);
  } else {
    // The new.target is a constructor but it's not a JSFunction with
    // a prototype slot, so get the prototype property.
    Handle<String> prototype_string = isolate->factory()->prototype_string();
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, prototype,
        JSReceiver::GetProperty(isolate, new_target, prototype_string));
    // The above prototype lookup might change the constructor and its
    // prototype, hence we have to reload the initial map.
    EnsureHasInitialMap(constructor);
    constructor_initial_map = handle(constructor->initial_map(), isolate);
  }

  // If prototype is not a JSReceiver, fetch the intrinsicDefaultProto from the
  // correct realm. Rather than directly fetching the .prototype, we fetch the
  // constructor that points to the .prototype. This relies on
  // constructor.prototype being FROZEN for those constructors.
  if (!IsJSReceiver(*prototype)) {
    Handle<NativeContext> native_context;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, native_context,
                               JSReceiver::GetFunctionRealm(new_target));
    DirectHandle<Object> maybe_index = JSReceiver::GetDataProperty(
        isolate, constructor,
        isolate->factory()->native_context_index_symbol());
    int index = IsSmi(*maybe_index) ? Smi::ToInt(*maybe_index)
                                    : Context::OBJECT_FUNCTION_INDEX;
    DirectHandle<JSFunction> realm_constructor(
        Cast<JSFunction>(native_context->get(index)), isolate);
    prototype = handle(realm_constructor->prototype(), isolate);
  }
  DCHECK_EQ(constructor_initial_map->constructor_or_back_pointer(),
            *constructor);
  return Map::GetDerivedMap(isolate, constructor_initial_map,
                            Cast<JSReceiver>(prototype));
}

namespace {

// Assert that the computations in TypedArrayElementsKindToConstructorIndex and
// TypedArrayElementsKindToRabGsabCtorIndex are sound.
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                         \
  static_assert(Context::TYPE##_ARRAY_FUN_INDEX ==                        \
                Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX +              \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND); \
  static_assert(Context::RAB_GSAB_##TYPE##_ARRAY_MAP_INDEX ==             \
                Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX +           \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND);

TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

int TypedArrayElementsKindToConstructorIndex(ElementsKind elements_kind) {
  return Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

int TypedArrayElementsKindToRabGsabCtorIndex(ElementsKind elements_kind) {
  return Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

}  // namespace

MaybeHandle<Map> JSFunction::GetDerivedRabGsabTypedArrayMap(
    Isolate* isolate, Handle<JSFunction> constructor,
    Handle<JSReceiver> new_target) {
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  {
    DisallowHeapAllocation no_alloc;
    Tagged<NativeContext> context = isolate->context()->native_context();
    int ctor_index =
        TypedArrayElementsKindToConstructorIndex(map->elements_kind());
    if (*new_target == context->get(ctor_index)) {
      ctor_index =
          TypedArrayElementsKindToRabGsabCtorIndex(map->elements_kind());
      return handle(Cast<Map>(context->get(ctor_index)), isolate);
    }
  }

  // This only happens when subclassing TypedArrays. Create a new map with the
  // corresponding RAB / GSAB ElementsKind. Note: the map is not cached and
  // reused -> every array gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_elements_kind(
      GetCorrespondingRabGsabElementsKind(map->elements_kind()));
  return rab_gsab_map;
}

MaybeHandle<Map> JSFunction::GetDerivedRabGsabDataViewMap(
    Isolate* isolate, Handle<JSReceiver> new_target) {
  DirectHandle<Context> context(isolate->context()->native_context(), isolate);
  Handle<JSFunction> constructor(context->data_view_fun(), isolate);
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  if (*map == constructor->initial_map()) {
    return handle(Cast<Map>(context->js_rab_gsab_data_view_map()), isolate);
  }

  // This only happens when subclassing DataViews. Create a new map with the
  // JS_RAB_GSAB_DATA_VIEW instance type. Note: the map is not cached and
  // reused -> every data view gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_instance_type(JS_RAB_GSAB_DATA_VIEW_TYPE);
  return rab_gsab_map;
}

int JSFunction::ComputeInstanceSizeWithMinSlack(Isolate* isolate) {
  CHECK(has_initial_map());
  if (initial_map()->IsInobjectSlackTrackingInProgress()) {
    int slack = initial_map()->ComputeMinObjectSlack(isolate);
    return initial_map()->InstanceSizeFromSlack(slack);
  }
  return initial_map()->instance_size();
}

std::unique_ptr<char[]> JSFunction::DebugNameCStr() {
  return shared()->DebugNameCStr();
}

void JSFunction::PrintName(FILE* out) {
  PrintF(out, "%s", DebugNameCStr().get());
}

namespace {

bool UseFastFunctionNameLookup(Isolate* isolate, Tagged<Map> map) {
  DCHECK(IsJSFunctionMap(map));
  if (map->NumberOfOwnDescriptors() <
      JSFunction::kMinDescriptorsForFastBindAndWrap) {
    return false;
  }
  DCHECK(!map->is_dictionary_map());
  Tagged<HeapObject> value;
  ReadOnlyRoots roots(isolate);
  auto descriptors = map->instance_descriptors(isolate);
  InternalIndex kNameIndex{JSFunction::kNameDescriptorIndex};
  if (descriptors->GetKey(kNameIndex) != roots.name_string() ||
      !descriptors->GetValue(kNameIndex)
           .GetHeapObjectIfStrong(isolate, &value)) {
    return false;
  }
  return IsAccessorInfo(value);
}

}  // namespace

Handle<String> JSFunction::GetDebugName(Handle<JSFunction> function) {
  // Below we use the same fast-path that we already established for
  // Function.prototype.bind(), where we avoid a slow "name" property
  // lookup if the DescriptorArray for the |function| still has the
  // "name" property at the original spot and that property is still
  // implemented via an AccessorInfo (which effectively means that
  // it must be the FunctionNameGetter).
  Isolate* isolate = function->GetIsolate();
  if (!UseFastFunctionNameLookup(isolate, function->map())) {
    // Normally there should be an else case for the fast-path check
    // above, which should invoke JSFunction::GetName(), since that's
    // what the FunctionNameGetter does, however GetDataProperty() has
    // never invoked accessors and thus always returned undefined for
    // JSFunction where the "name" property is untouched, so we retain
    // that exact behavior and go with SharedFunctionInfo::DebugName()
    // in case of the fast-path.
    Handle<Object> name =
        GetDataProperty(isolate, function, isolate->factory()->name_string());
    if (IsString(*name)) return Cast<String>(name);
  }
  return SharedFunctionInfo::DebugName(isolate,
                                       handle(function->shared(), isolate));
}

bool JSFunction::SetName(Handle<JSFunction> function, Handle<Name> name,
                         DirectHandle<String> prefix) {
  Isolate* isolate = function->GetIsolate();
  Handle<String> function_name;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                   Name::ToFunctionName(isolate, name), false);
  if (prefix->length() > 0) {
    IncrementalStringBuilder builder(isolate);
    builder.AppendString(prefix);
    builder.AppendCharacter(' ');
    builder.AppendString(function_name);
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                     indirect_handle(builder.Finish(), isolate),
                                     false);
  }
  RETURN_ON_EXCEPTION_VALUE(
      isolate,
      JSObject::DefinePropertyOrElementIgnoreAttributes(
          function, isolate->factory()->name_string(), function_name,
          static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY)),
      false);
  return true;
}

namespace {

Handle<String> NativeCodeFunctionSourceString(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared_info) {
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("function ");
  builder.AppendString(handle(shared_info->Name(), isolate));
  builder.AppendCStringLiteral("() { [native code] }");
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

}  // namespace

// static
Handle<String> JSFunction::ToString(DirectHandle<JSFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  DirectHandle<SharedFunctionInfo> shared_info(function->shared(), isolate);

  // Check if {function} should hide its source code.
  if (!shared_info->IsUserJavaScript()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  if (IsClassConstructor(shared_info->kind())) {
    // Check if we should print {function} as a class.
    DirectHandle<Object> maybe_class_positions = JSReceiver::GetDataProperty(
        isolate, indirect_handle(function, isolate),
        isolate->factory()->class_positions_symbol());
    if (IsClassPositions(*maybe_class_positions)) {
      Tagged<ClassPositions> class_positions =
          Cast<ClassPositions>(*maybe_class_positions);
      int start_position = class_positions->start();
      int end_position = class_positions->end();
      Handle<String> script_source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(script_source, start_position,
                                              end_position);
    }
  }

  // Check if we have source code for the {function}.
  if (!shared_info->HasSourceCode()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  // If this function was compiled from asm.js, use the recorded offset
  // information.
#if V8_ENABLE_WEBASSEMBLY
  if (shared_info->HasWasmExportedFunctionData()) {
    DirectHandle<WasmExportedFunctionData> function_data(
        shared_info->wasm_exported_function_data(), isolate);
    const wasm::WasmModule* module = function_data->instance_data()->module();
    if (is_asmjs_module(module)) {
      std::pair<int, int> offsets =
          module->asm_js_offset_information->GetFunctionOffsets(
              declared_function_index(module, function_data->function_index()));
      Handle<String> source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(source, offsets.first,
                                              offsets.second);
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (shared_info->function_token_position() == kNoSourcePosition) {
    // If the function token position isn't valid, return [native code] to
    // ensure calling eval on the returned source code throws rather than
    // giving inconsistent call behaviour.
    isolate->CountUsage(
        v8::Isolate::UseCounterFeature::kFunctionTokenOffsetTooLongForToString);
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }
  return Cast<String>(
      SharedFunctionInfo::GetSourceCodeHarmony(isolate, shared_info));
}

// static
int JSFunction::CalculateExpectedNofProperties(Isolate* isolate,
                                               Handle<JSFunction> function) {
  int expected_nof_properties = 0;
  for (PrototypeIterator iter(isolate, function, kStartAtReceiver);
       !iter.IsAtEnd(); iter.Advance()) {
    Handle<JSReceiver> current =
        PrototypeIterator::GetCurrent<JSReceiver>(iter);
    if (!IsJSFunction(*current)) break;
    Handle<JSFunction> func = Cast<JSFunction>(current);
    // The super constructor should be compiled for the number of expected
    // properties to be available.
    DirectHandle<SharedFunctionInfo> shared(func->shared(), isolate);
    IsCompiledScope is_compiled_scope(shared->is_compiled_scope(isolate));
    if (is_compiled_scope.is_compiled() ||
        Compiler::Compile(isolate, func, Compiler::CLEAR_EXCEPTION,
                          &is_compiled_scope)) {
      DCHECK(shared->is_compiled());
      int count = shared->expected_nof_properties();
      // Check that the estimate is sensible.
      if (expected_nof_properties <= JSObject::kMaxInObjectProperties - count) {
        expected_nof_properties += count;
      } else {
        return JSObject::kMaxInObjectProperties;
      }
    } else {
      // In case there was a compilation error proceed iterating in case there
      // will be a builtin function in the prototype chain that requires
      // certain number of in-object properties.
      continue;
    }
  }
  // Inobject slack tracking will reclaim redundant inobject space
  // later, so we can afford to adjust the estimate generously,
  // meaning we over-allocate by at least 8 slots in the beginning.
  if (expected_nof_properties > 0) {
    expected_nof_properties += 8;
    if (expected_nof_properties > JSObject::kMaxInObjectProperties) {
      expected_nof_properties = JSObject::kMaxInObjectProperties;
    }
  }
  return expected_nof_properties;
}

// static
void JSFunction::CalculateInstanceSizeHelper(InstanceType instance_type,
                                             bool has_prototype_slot,
                                             int requested_embedder_fields,
                                             int requested_in_object_properties,
                                             int* instance_size,
                                             int* in_object_properties) {
  DCHECK_LE(static_cast<unsigned>(requested_embedder_fields),
            JSObject::kMaxEmbedderFields);
  int header_size = JSObject::GetHeaderSize(instance_type, has_prototype_slot);
  requested_embedder_fields *= kEmbedderDataSlotSizeInTaggedSlots;

  int max_nof_fields =
      (JSObject::kMaxInstanceSize - header_size) >> kTaggedSizeLog2;
  CHECK_LE(max_nof_fields, JSObject::kMaxInObjectProperties);
  CHECK_LE(static_cast<unsigned>(requested_embedder_fields),
           static_cast<unsigned>(max_nof_fields));
  *in_object_properties = std::min(requested_in_object_properties,
                                   max_nof_fields - requested_embedder_fields);
  *instance_size =
      header_size +
      ((requested_embedder_fields + *in_object_properties) << kTaggedSizeLog2);
  CHECK_EQ(*in_object_properties,
           ((*instance_size - header_size) >> kTaggedSizeLog2) -
               requested_embedder_fields);
  CHECK_LE(static_cast<unsigned>(*instance_size),
           static_cast<unsigned>(JSObject::kMaxInstanceSize));
}

void JSFunction::ClearAllTypeFeedbackInfoForTesting() {
  Isolate* isolate = GetIsolate();
  ResetIfCodeFlushed(isolate);
  if (has_feedback_vector()) {
    Tagged<FeedbackVector> vector = feedback_vector();
    if (vector->ClearAllSlotsForTesting(isolate)) {
      IC::OnFeedbackChanged(isolate, vector, FeedbackSlot::Invalid(),
                            "ClearAllTypeFeedbackInfoForTesting");
    }
  }
}

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"
```