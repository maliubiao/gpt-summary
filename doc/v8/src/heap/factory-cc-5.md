Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/heap/factory.cc`. I need to analyze the code and identify its primary purpose and the roles of the different functions.

Here's a breakdown of the steps:

1. **Identify the file's purpose:** The file `factory.cc` is located in the `v8/src/heap` directory, suggesting it's responsible for creating objects within the V8 heap. The class name `Factory` reinforces this idea.

2. **Analyze individual functions:** Go through each function and determine what kind of object it creates and any specific initialization it performs. Pay attention to the `New...` naming convention, which is a strong indicator of object creation.

3. **Check for Torque source:** The filename doesn't end with `.tq`, so it's not a Torque source file.

4. **Relate to JavaScript functionality:**  Identify if the created objects directly correspond to JavaScript concepts. For instance, creating `String`, `DebugInfo`, `JSObject`, `Map`, `Function`, `Promise`, etc., directly relates to JavaScript features.

5. **Provide JavaScript examples:** For functions with JavaScript relevance, illustrate how these objects are used or created in JavaScript.

6. **Demonstrate code logic:** For functions with clear logic, create hypothetical input and output examples. Functions like `NewStringFromAscii` are good candidates for this.

7. **Highlight common programming errors:**  Consider if the functions' purpose relates to areas where JavaScript developers might make mistakes. For example, the handling of arguments objects and the distinction between strict and sloppy mode.

8. **Summarize the overall functionality:** Combine the individual function analyses to provide a concise summary of the file's role.

**Detailed Function Analysis and Planning:**

* **`NewStringFromAsciiChecked`:** Creates a `String` object from an ASCII string. JavaScript example: `'hello'`. Input/Output example: `value = 123`, Output: `"123"`.
* **`NewDebugInfo`:** Creates `DebugInfo` for debugging purposes. JavaScript relevance:  Debugger statements, breakpoints.
* **`NewBreakPointInfo`, `NewBreakPoint`:** Creates objects related to breakpoints. JavaScript relevance: Setting breakpoints in the debugger.
* **`NewCallSiteInfo`:** Creates information about call sites in the stack. JavaScript relevance: Stack traces, error reporting.
* **`NewStackFrameInfo`:**  Creates information about a single stack frame. JavaScript relevance: Stack traces.
* **`NewStackTraceInfo`:**  Creates a collection of stack frame information. JavaScript relevance: Full stack traces.
* **`NewArgumentsObject`:** Creates the `arguments` object inside functions. JavaScript example: function `foo() { console.log(arguments); }`. Common error: Assuming `arguments` is always an array.
* **`ObjectLiteralMapFromCache`:** Optimizes map creation for object literals. JavaScript example: `{ a: 1, b: 2 }`.
* **`NewMegaDomHandler`, `NewLoadHandler`, `NewStoreHandler`:** These seem related to internal V8 handling of property access, possibly optimized for DOM objects. Less direct JavaScript correlation for examples.
* **`SetRegExpAtomData`, `SetRegExpIrregexpData`, `SetRegExpExperimentalData`, `NewAtomRegExpData`, `NewIrRegExpData`, `NewExperimentalRegExpData`:** These functions handle the internal representation of regular expressions. JavaScript example: `/abc/`, `new RegExp('abc')`.
* **`GlobalConstantFor`:** Returns handles to global constants like `undefined`, `NaN`, `Infinity`. JavaScript relevance: These are fundamental JavaScript values.
* **`ToPrimitiveHintString`:** Converts `ToPrimitiveHint` enum to a string. Internal V8 usage.
* **`CreateSloppyFunctionMap`, `CreateStrictFunctionMap`, `CreateClassFunctionMap`:** Create map objects for different types of functions (sloppy, strict, class constructors). JavaScript relevance: Function declarations, class declarations, strict mode.
* **`NewJSPromiseWithoutHook`, `NewJSPromise`:** Creates `Promise` objects. JavaScript example: `new Promise(...)`.
* **`CanAllocateInReadOnlySpace`, `EmptyStringRootIsInitialized`, `AllocationTypeForInPlaceInternalizableString`:**  Internal V8 memory management details.
* **`NewFunctionForTesting`:** Creates test functions. Internal V8 testing.
* **`NewJSSharedStruct`, `NewJSSharedArray`, `NewJSAtomicsMutex`, `NewJSAtomicsCondition`:** Create objects related to shared memory and atomics. JavaScript relevance: SharedArrayBuffer, Atomics API.
* **`NewFunctionTemplateInfo`, `NewObjectTemplateInfo`, `NewDictionaryTemplateInfo`:**  Create template objects, used in V8's embedding API (Node.js, browser extensions). Less direct JavaScript examples.
* **`NewTrustedForeign`:** Creates a wrapper for external (non-V8) data. Often used in V8's embedding API.
* **`JSFunctionBuilder::Build`, `JSFunctionBuilder::BuildRaw`:** Helper class for building `JSFunction` objects. Internal V8 usage.

Now I can proceed with generating the response based on this plan.
```cpp
tringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    // Build the string backwards from the least significant digit.
    int i = buffer.length();
    size_t value_copy = value;
    buffer[--i] = '\0';
    do {
      buffer[--i] = '0' + (value_copy % 10);
      value_copy /= 10;
    } while (value_copy > 0);
    char* string = buffer.begin() + i;
    // No way to cache this; we'd need an {Object} to use as key.
    result = NewStringFromAsciiChecked(string);
  }
  {
    DisallowGarbageCollection no_gc;
    Tagged<String> raw = *result;
    if (value <= JSArray::kMaxArrayIndex &&
        raw->raw_hash_field() == String::kEmptyHashField) {
      uint32_t raw_hash_field = StringHasher::MakeArrayIndexHash(
          static_cast<uint32_t>(value), raw->length());
      raw->set_raw_hash_field(raw_hash_field);
    }
  }
  return result;
}

Handle<DebugInfo> Factory::NewDebugInfo(
    DirectHandle<SharedFunctionInfo> shared) {
  DCHECK(!shared->HasDebugInfo(isolate()));

  auto debug_info =
      NewStructInternal<DebugInfo>(DEBUG_INFO_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw_shared = *shared;
  debug_info->set_flags(DebugInfo::kNone, kRelaxedStore);
  debug_info->set_shared(raw_shared);
  debug_info->set_debugger_hints(0);
  DCHECK_EQ(DebugInfo::kNoDebuggingId, debug_info->debugging_id());
  debug_info->set_break_points(*empty_fixed_array(), SKIP_WRITE_BARRIER);
  debug_info->clear_original_bytecode_array();
  debug_info->clear_debug_bytecode_array();

  return handle(debug_info, isolate());
}

Handle<BreakPointInfo> Factory::NewBreakPointInfo(int source_position) {
  auto new_break_point_info = NewStructInternal<BreakPointInfo>(
      BREAK_POINT_INFO_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  new_break_point_info->set_source_position(source_position);
  new_break_point_info->set_break_points(*undefined_value(),
                                         SKIP_WRITE_BARRIER);
  return handle(new_break_point_info, isolate());
}

Handle<BreakPoint> Factory::NewBreakPoint(int id,
                                          DirectHandle<String> condition) {
  auto new_break_point =
      NewStructInternal<BreakPoint>(BREAK_POINT_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  new_break_point->set_id(id);
  new_break_point->set_condition(*condition);
  return handle(new_break_point, isolate());
}

Handle<CallSiteInfo> Factory::NewCallSiteInfo(
    DirectHandle<JSAny> receiver_or_instance,
    DirectHandle<UnionOf<Smi, JSFunction>> function,
    DirectHandle<HeapObject> code_object, int code_offset_or_source_position,
    int flags, DirectHandle<FixedArray> parameters) {
  auto info = NewStructInternal<CallSiteInfo>(CALL_SITE_INFO_TYPE,
                                              AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_receiver_or_instance(*receiver_or_instance, SKIP_WRITE_BARRIER);
  info->set_function(*function, SKIP_WRITE_BARRIER);
  info->set_code_object(*code_object, SKIP_WRITE_BARRIER);
  info->set_code_offset_or_source_position(code_offset_or_source_position);
  info->set_flags(flags);
  info->set_parameters(*parameters, SKIP_WRITE_BARRIER);
  return handle(info, isolate());
}

Handle<StackFrameInfo> Factory::NewStackFrameInfo(
    DirectHandle<UnionOf<SharedFunctionInfo, Script>> shared_or_script,
    int bytecode_offset_or_source_position, DirectHandle<String> function_name,
    bool is_constructor) {
  DCHECK_GE(bytecode_offset_or_source_position, 0);
  Tagged<StackFrameInfo> info = NewStructInternal<StackFrameInfo>(
      STACK_FRAME_INFO_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_flags(0);
  info->set_shared_or_script(*shared_or_script, SKIP_WRITE_BARRIER);
  info->set_bytecode_offset_or_source_position(
      bytecode_offset_or_source_position);
  info->set_function_name(*function_name, SKIP_WRITE_BARRIER);
  info->set_is_constructor(is_constructor);
  return handle(info, isolate());
}

Handle<StackTraceInfo> Factory::NewStackTraceInfo(
    DirectHandle<FixedArray> frames) {
  Tagged<StackTraceInfo> info = NewStructInternal<StackTraceInfo>(
      STACK_TRACE_INFO_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_id(isolate()->heap()->NextStackTraceId());
  info->set_frames(*frames, SKIP_WRITE_BARRIER);
  return handle(info, isolate());
}

Handle<JSObject> Factory::NewArgumentsObject(Handle<JSFunction> callee,
                                             int length) {
  bool strict_mode_callee = is_strict(callee->shared()->language_mode()) ||
                            !callee->shared()->has_simple_parameters();
  DirectHandle<Map> map = strict_mode_callee
                              ? isolate()->strict_arguments_map()
                              : isolate()->sloppy_arguments_map();
  AllocationSiteUsageContext context(isolate(), Handle<AllocationSite>(),
                                     false);
  DCHECK(!isolate()->has_exception());
  Handle<JSObject> result = NewJSObjectFromMap(map);
  Handle<Smi> value(Smi::FromInt(length), isolate());
  Object::SetProperty(isolate(), result, length_string(), value,
                      StoreOrigin::kMaybeKeyed,
                      Just(ShouldThrow::kThrowOnError))
      .Assert();
  if (!strict_mode_callee) {
    Object::SetProperty(isolate(), result, callee_string(), callee,
                        StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Assert();
  }
  return result;
}

Handle<Map> Factory::ObjectLiteralMapFromCache(
    DirectHandle<NativeContext> context, int number_of_properties) {
  // Use initial slow object proto map for too many properties.
  if (number_of_properties >= JSObject::kMapCacheSize) {
    return handle(context->slow_object_with_object_prototype_map(), isolate());
  }
  // TODO(chromium:1503456): remove once fixed.
  CHECK_LE(0, number_of_properties);

  DirectHandle<WeakFixedArray> cache(Cast<WeakFixedArray>(context->map_cache()),
                                     isolate());

  // Check to see whether there is a matching element in the cache.
  Tagged<MaybeObject> result = cache->get(number_of_properties);
  Tagged<HeapObject> heap_object;
  if (result.GetHeapObjectIfWeak(&heap_object)) {
    Tagged<Map> map = Cast<Map>(heap_object);
    DCHECK(!map->is_dictionary_map());
    return handle(map, isolate());
  }

  // Create a new map and add it to the cache.
  Handle<Map> map = Map::Create(isolate(), number_of_properties);
  DCHECK(!map->is_dictionary_map());
  cache->set(number_of_properties, MakeWeak(*map));
  return map;
}

Handle<MegaDomHandler> Factory::NewMegaDomHandler(MaybeObjectHandle accessor,
                                                  MaybeObjectHandle context) {
  DirectHandle<Map> map = read_only_roots().mega_dom_handler_map_handle();
  Tagged<MegaDomHandler> handler =
      Cast<MegaDomHandler>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  handler->set_accessor(*accessor, kReleaseStore);
  handler->set_context(*context);
  return handle(handler, isolate());
}

Handle<LoadHandler> Factory::NewLoadHandler(int data_count,
                                            AllocationType allocation) {
  DirectHandle<Map> map;
  switch (data_count) {
    case 1:
      map = load_handler1_map();
      break;
    case 2:
      map = load_handler2_map();
      break;
    case 3:
      map = load_handler3_map();
      break;
    default:
      UNREACHABLE();
  }
  return handle(Cast<LoadHandler>(New(map, allocation)), isolate());
}

Handle<StoreHandler> Factory::NewStoreHandler(int data_count) {
  DirectHandle<Map> map;
  switch (data_count) {
    case 0:
      map = store_handler0_map();
      break;
    case 1:
      map = store_handler1_map();
      break;
    case 2:
      map = store_handler2_map();
      break;
    case 3:
      map = store_handler3_map();
      break;
    default:
      UNREACHABLE();
  }
  return handle(Cast<StoreHandler>(New(map, AllocationType::kOld)), isolate());
}

void Factory::SetRegExpAtomData(DirectHandle<JSRegExp> regexp,
                                DirectHandle<String> source,
                                JSRegExp::Flags flags,
                                DirectHandle<String> pattern) {
  DirectHandle<RegExpData> regexp_data =
      NewAtomRegExpData(source, flags, pattern);
  regexp->set_data(*regexp_data);
}

void Factory::SetRegExpIrregexpData(DirectHandle<JSRegExp> regexp,
                                    DirectHandle<String> source,
                                    JSRegExp::Flags flags, int capture_count,
                                    uint32_t backtrack_limit) {
  DirectHandle<RegExpData> regexp_data =
      NewIrRegExpData(source, flags, capture_count, backtrack_limit);
  regexp->set_data(*regexp_data);
}

void Factory::SetRegExpExperimentalData(DirectHandle<JSRegExp> regexp,
                                        DirectHandle<String> source,
                                        JSRegExp::Flags flags,
                                        int capture_count) {
  DirectHandle<RegExpData> regexp_data =
      NewExperimentalRegExpData(source, flags, capture_count);
  regexp->set_data(*regexp_data);
}

Handle<RegExpData> Factory::NewAtomRegExpData(DirectHandle<String> source,
                                              JSRegExp::Flags flags,
                                              DirectHandle<String> pattern) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = AtomRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().atom_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<AtomRegExpData> instance = Cast<AtomRegExpData>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::ATOM);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->set_pattern(*pattern);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<RegExpData> Factory::NewIrRegExpData(DirectHandle<String> source,
                                            JSRegExp::Flags flags,
                                            int capture_count,
                                            uint32_t backtrack_limit) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = IrRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().ir_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<IrRegExpData> instance = Cast<IrRegExpData>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::IRREGEXP);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->clear_latin1_code();
  instance->clear_uc16_code();
  instance->clear_latin1_bytecode();
  instance->clear_uc16_bytecode();
  instance->set_capture_name_map(Smi::FromInt(JSRegExp::kUninitializedValue));
  instance->set_max_register_count(JSRegExp::kUninitializedValue);
  instance->set_capture_count(capture_count);
  int ticks_until_tier_up = v8_flags.regexp_tier_up
                                ? v8_flags.regexp_tier_up_ticks
                                : JSRegExp::kUninitializedValue;
  instance->set_ticks_until_tier_up(ticks_until_tier_up);
  instance->set_backtrack_limit(backtrack_limit);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<RegExpData> Factory::NewExperimentalRegExpData(
    DirectHandle<String> source, JSRegExp::Flags flags, int capture_count) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = IrRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().ir_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<IrRegExpData> instance = Cast<IrRegExpData>(result);
  // TODO(mbid,v8:10765): At the moment the ExperimentalRegExpData is just an
  // alias of IrRegExpData, with most fields set to some default/uninitialized
  // value. This is because EXPERIMENTAL and IRREGEXP regexps take the same code
  // path in `RegExpExecInternal`, which reads off various fields from this
  // struct. `RegExpExecInternal` should probably distinguish between
  // EXPERIMENTAL and IRREGEXP, and then we can get rid of all the IRREGEXP only
  // fields.
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::EXPERIMENTAL);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->clear_latin1_code();
  instance->clear_uc16_code();
  instance->clear_latin1_bytecode();
  instance->clear_uc16_bytecode();
  instance->set_capture_name_map(Smi::FromInt(JSRegExp::kUninitializedValue));
  instance->set_max_register_count(JSRegExp::kUninitializedValue);
  instance->set_capture_count(capture_count);
  instance->set_ticks_until_tier_up(JSRegExp::kUninitializedValue);
  instance->set_backtrack_limit(JSRegExp::kUninitializedValue);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<Object> Factory::GlobalConstantFor(Handle<Name> name) {
  if (Name::Equals(isolate(), name, undefined_string())) {
    return undefined_value();
  }
  if (Name::Equals(isolate(), name, NaN_string())) return nan_value();
  if (Name::Equals(isolate(), name, Infinity_string())) return infinity_value();
  return Handle<Object>::null();
}

Handle<String> Factory::ToPrimitiveHintString(ToPrimitiveHint hint) {
  switch (hint) {
    case ToPrimitiveHint::kDefault:
      return default_string();
    case ToPrimitiveHint::kNumber:
      return number_string();
    case ToPrimitiveHint::kString:
      return string_string();
  }
  UNREACHABLE();
}

Handle<Map> Factory::CreateSloppyFunctionMap(
    FunctionMode function_mode, MaybeHandle<JSFunction> maybe_empty_function) {
  bool has_prototype = IsFunctionModeWithPrototype(function_mode);
  int header_size = has_prototype ? JSFunction::kSizeWithPrototype
                                  : JSFunction::kSizeWithoutPrototype;
  int descriptors_count = has_prototype ? 5 : 4;
  int inobject_properties_count = 0;
  if (IsFunctionModeWithName(function_mode)) ++inobject_properties_count;

  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_FUNCTION_TYPE, header_size + inobject_properties_count * kTaggedSize,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties_count);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(has_prototype);
    raw_map->set_is_constructor(has_prototype);
    raw_map->set_is_callable(true);
  }
  Handle<JSFunction> empty_function;
  if (maybe_empty_function.ToHandle(&empty_function)) {
    // Temporarily set constructor to empty function to calm down map verifier.
    map->SetConstructor(*empty_function);
    Map::SetPrototype(isolate(), map, empty_function);
  } else {
    // |maybe_empty_function| is allowed to be empty only during empty function
    // creation.
    DCHECK(IsUndefined(
        isolate()->raw_native_context()->get(Context::EMPTY_FUNCTION_INDEX)));
  }

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, descriptors_count);

  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes rw_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  int field_index = 0;
  static_assert(
      JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  static_assert(
      JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex == 1);
  if (IsFunctionModeWithName(function_mode)) {
    // Add name field.
    Handle<Name> name = isolate()->factory()->name_string();
    Descriptor d = Descriptor::DataField(isolate(), name, field_index++,
                                         roc_attribs, Representation::Tagged());
    map->AppendDescriptor(isolate(), &d);

  } else {
    // Add name accessor.
    Descriptor d = Descriptor::AccessorConstant(
        name_string(), function_name_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  {  // Add arguments accessor.
    Descriptor d = Descriptor::AccessorConstant(
        arguments_string(), function_arguments_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  {  // Add caller accessor.
    Descriptor d = Descriptor::AccessorConstant(
        caller_string(), function_caller_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  if (IsFunctionModeWithPrototype(function_mode)) {
    // Add prototype accessor.
    PropertyAttributes attribs =
        IsFunctionModeWithWritablePrototype(function_mode) ? rw_attribs
                                                           : ro_attribs;
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  DCHECK_EQ(inobject_properties_count, field_index);
  DCHECK_EQ(
      0, map->instance_descriptors(isolate())->number_of_slack_descriptors());
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<Map> Factory::CreateStrictFunctionMap(
    FunctionMode function_mode, Handle<JSFunction> empty_function) {
  bool has_prototype = IsFunctionModeWithPrototype(function_mode);
  int header_size = has_prototype ? JSFunction::kSizeWithPrototype
                                  : JSFunction::kSizeWithoutPrototype;
  int inobject_properties_count = 0;
  // length and prototype accessors or just length accessor.
  int descriptors_count = IsFunctionModeWithPrototype(function_mode) ? 2 : 1;
  if (IsFunctionModeWithName(function_mode)) {
    ++inobject_properties_count;  // name property.
  } else {
    ++descriptors_count;  // name accessor.
  }
  descriptors_count += inobject_properties_count;

  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_FUNCTION_TYPE, header_size + inobject_properties_count * kTaggedSize,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties_count);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(has_prototype);
    raw_map->set_is_constructor(has_prototype);
    raw_map->set_is_callable(true);
    // Temporarily set constructor to empty function to calm down map verifier.
    raw_map->SetConstructor(*empty_function);
  }
  Map::SetPrototype(isolate(), map, empty_function);

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, descriptors_count);

  PropertyAttributes rw_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);
  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  int field_index = 0;
  static_assert(JSFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  static_assert(JSFunction::kNameDescriptorIndex == 1);
  if (IsFunctionModeWithName(function_mode)) {
    // Add name field.
    Handle<Name> name = isolate()->factory()->name_string();
    Descriptor d = Descriptor::DataField(isolate(), name, field_index++,
                                         roc_attribs, Representation::Tagged());
    map->AppendDescriptor(isolate(), &d);

  } else {
    // Add name accessor.
    Descriptor d = Descriptor::AccessorConstant(
        name_string(), function_name_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  if (IsFunctionModeWithPrototype(function_mode)) {
    // Add prototype accessor.
    PropertyAttributes attribs =
        IsFunctionModeWithWritablePrototype(function_mode) ? rw_attribs
                                                           : ro_attribs;
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  DCHECK_EQ(inobject_properties_count, field_index);
  DCHECK_EQ(
      0, map->instance_descriptors(isolate())->number_of_slack_descriptors());
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<Map> Factory::CreateClassFunctionMap(Handle<JSFunction> empty_function) {
  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_CLASS_CONSTRUCTOR_TYPE, JSFunction::kSizeWithPrototype);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(true);
    raw_map->set_is_constructor(true);
    raw_map->set_is_prototype_map(true);
    raw_map->set_is_callable(true);
    // Temporarily set constructor to empty function to calm down map verifier.
    raw_map->SetConstructor(*empty_function);
  }
  Map::SetPrototype(isolate(), map, empty_function);

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, 2);

  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  static_assert(JSFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  {
    // Add prototype accessor.
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<JSPromise> Factory::NewJSPromiseWithoutHook() {
  Handle<JSPromise> promise =
      Cast<JSPromise>(NewJSObject(isolate()->promise_function()));
  DisallowGarbageCollection no_gc;
  Tagged<JSPromise> raw = *promise;
  raw->set_reactions_or_result(Smi::zero(), SKIP_WRITE_BARRIER);
  raw->set_flags(0);
  // TODO(v8) remove once embedder data slots are always zero-initialized.
  InitEmbedderFields(*promise, Smi::zero());
  DCHECK_EQ(raw->GetEmbedderFieldCount(), v8::Promise::kEmbedderFieldCount);
  return promise;
}

Handle<JSPromise> Factory::NewJSPromise() {
  Handle<JSPromise> promise = NewJSPromiseWithoutHook();
  isolate()->RunAllPromiseHooks(PromiseHookType::kInit, promise,
                                undefined_value());
  return promise;
}

bool Factory::CanAllocateInReadOnlySpace() {
  return allocator()->CanAllocateInReadOnlySpace();
}

bool Factory::EmptyStringRootIsInitialized() {
  return isolate()->roots_table()[RootIndex::kempty_string] != kNullAddress;
}

AllocationType Factory::AllocationTypeForInPlaceInternalizableString() {
  return isolate()
      ->heap()
      ->allocation_type_for_in_place_internalizable_strings();
}

Handle<JSFunction> Factory::NewFunctionForTesting(DirectHandle<String> name) {
  Handle<SharedFunctionInfo> info =
      NewSharedFunctionInfoForBuiltin(name, Builtin::kIllegal, 0, kDontAdapt);
  info->set_language_mode(LanguageMode::kSloppy);
  return JSFunctionBuilder{isolate(), info, isolate()->native_context()}
      .Build();
}

Handle<JSSharedStruct> Factory::NewJSSharedStruct(
    Handle<JSFunction> constructor,
    MaybeHandle<NumberDictionary> maybe_elements_template) {
  SharedObjectSafePublishGuard publish_guard;

  DirectHandle<Map> instance_map(constructor->initial_map(), isolate());
  DirectHandle<PropertyArray> property_array;
  const int num_oob_fields =
      instance_map->NumberOfFields(ConcurrencyMode::kSynchronous) -
      instance_map->GetInObjectProperties();
  if (num_oob_fields > 0) {
    property_array =
        NewPropertyArray(num_oob_fields, AllocationType::kSharedOld);
  }

  Handle<NumberDictionary> elements_dictionary;

### 提示词
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
tringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    // Build the string backwards from the least significant digit.
    int i = buffer.length();
    size_t value_copy = value;
    buffer[--i] = '\0';
    do {
      buffer[--i] = '0' + (value_copy % 10);
      value_copy /= 10;
    } while (value_copy > 0);
    char* string = buffer.begin() + i;
    // No way to cache this; we'd need an {Object} to use as key.
    result = NewStringFromAsciiChecked(string);
  }
  {
    DisallowGarbageCollection no_gc;
    Tagged<String> raw = *result;
    if (value <= JSArray::kMaxArrayIndex &&
        raw->raw_hash_field() == String::kEmptyHashField) {
      uint32_t raw_hash_field = StringHasher::MakeArrayIndexHash(
          static_cast<uint32_t>(value), raw->length());
      raw->set_raw_hash_field(raw_hash_field);
    }
  }
  return result;
}

Handle<DebugInfo> Factory::NewDebugInfo(
    DirectHandle<SharedFunctionInfo> shared) {
  DCHECK(!shared->HasDebugInfo(isolate()));

  auto debug_info =
      NewStructInternal<DebugInfo>(DEBUG_INFO_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw_shared = *shared;
  debug_info->set_flags(DebugInfo::kNone, kRelaxedStore);
  debug_info->set_shared(raw_shared);
  debug_info->set_debugger_hints(0);
  DCHECK_EQ(DebugInfo::kNoDebuggingId, debug_info->debugging_id());
  debug_info->set_break_points(*empty_fixed_array(), SKIP_WRITE_BARRIER);
  debug_info->clear_original_bytecode_array();
  debug_info->clear_debug_bytecode_array();

  return handle(debug_info, isolate());
}

Handle<BreakPointInfo> Factory::NewBreakPointInfo(int source_position) {
  auto new_break_point_info = NewStructInternal<BreakPointInfo>(
      BREAK_POINT_INFO_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  new_break_point_info->set_source_position(source_position);
  new_break_point_info->set_break_points(*undefined_value(),
                                         SKIP_WRITE_BARRIER);
  return handle(new_break_point_info, isolate());
}

Handle<BreakPoint> Factory::NewBreakPoint(int id,
                                          DirectHandle<String> condition) {
  auto new_break_point =
      NewStructInternal<BreakPoint>(BREAK_POINT_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  new_break_point->set_id(id);
  new_break_point->set_condition(*condition);
  return handle(new_break_point, isolate());
}

Handle<CallSiteInfo> Factory::NewCallSiteInfo(
    DirectHandle<JSAny> receiver_or_instance,
    DirectHandle<UnionOf<Smi, JSFunction>> function,
    DirectHandle<HeapObject> code_object, int code_offset_or_source_position,
    int flags, DirectHandle<FixedArray> parameters) {
  auto info = NewStructInternal<CallSiteInfo>(CALL_SITE_INFO_TYPE,
                                              AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_receiver_or_instance(*receiver_or_instance, SKIP_WRITE_BARRIER);
  info->set_function(*function, SKIP_WRITE_BARRIER);
  info->set_code_object(*code_object, SKIP_WRITE_BARRIER);
  info->set_code_offset_or_source_position(code_offset_or_source_position);
  info->set_flags(flags);
  info->set_parameters(*parameters, SKIP_WRITE_BARRIER);
  return handle(info, isolate());
}

Handle<StackFrameInfo> Factory::NewStackFrameInfo(
    DirectHandle<UnionOf<SharedFunctionInfo, Script>> shared_or_script,
    int bytecode_offset_or_source_position, DirectHandle<String> function_name,
    bool is_constructor) {
  DCHECK_GE(bytecode_offset_or_source_position, 0);
  Tagged<StackFrameInfo> info = NewStructInternal<StackFrameInfo>(
      STACK_FRAME_INFO_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_flags(0);
  info->set_shared_or_script(*shared_or_script, SKIP_WRITE_BARRIER);
  info->set_bytecode_offset_or_source_position(
      bytecode_offset_or_source_position);
  info->set_function_name(*function_name, SKIP_WRITE_BARRIER);
  info->set_is_constructor(is_constructor);
  return handle(info, isolate());
}

Handle<StackTraceInfo> Factory::NewStackTraceInfo(
    DirectHandle<FixedArray> frames) {
  Tagged<StackTraceInfo> info = NewStructInternal<StackTraceInfo>(
      STACK_TRACE_INFO_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  info->set_id(isolate()->heap()->NextStackTraceId());
  info->set_frames(*frames, SKIP_WRITE_BARRIER);
  return handle(info, isolate());
}

Handle<JSObject> Factory::NewArgumentsObject(Handle<JSFunction> callee,
                                             int length) {
  bool strict_mode_callee = is_strict(callee->shared()->language_mode()) ||
                            !callee->shared()->has_simple_parameters();
  DirectHandle<Map> map = strict_mode_callee
                              ? isolate()->strict_arguments_map()
                              : isolate()->sloppy_arguments_map();
  AllocationSiteUsageContext context(isolate(), Handle<AllocationSite>(),
                                     false);
  DCHECK(!isolate()->has_exception());
  Handle<JSObject> result = NewJSObjectFromMap(map);
  Handle<Smi> value(Smi::FromInt(length), isolate());
  Object::SetProperty(isolate(), result, length_string(), value,
                      StoreOrigin::kMaybeKeyed,
                      Just(ShouldThrow::kThrowOnError))
      .Assert();
  if (!strict_mode_callee) {
    Object::SetProperty(isolate(), result, callee_string(), callee,
                        StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Assert();
  }
  return result;
}

Handle<Map> Factory::ObjectLiteralMapFromCache(
    DirectHandle<NativeContext> context, int number_of_properties) {
  // Use initial slow object proto map for too many properties.
  if (number_of_properties >= JSObject::kMapCacheSize) {
    return handle(context->slow_object_with_object_prototype_map(), isolate());
  }
  // TODO(chromium:1503456): remove once fixed.
  CHECK_LE(0, number_of_properties);

  DirectHandle<WeakFixedArray> cache(Cast<WeakFixedArray>(context->map_cache()),
                                     isolate());

  // Check to see whether there is a matching element in the cache.
  Tagged<MaybeObject> result = cache->get(number_of_properties);
  Tagged<HeapObject> heap_object;
  if (result.GetHeapObjectIfWeak(&heap_object)) {
    Tagged<Map> map = Cast<Map>(heap_object);
    DCHECK(!map->is_dictionary_map());
    return handle(map, isolate());
  }

  // Create a new map and add it to the cache.
  Handle<Map> map = Map::Create(isolate(), number_of_properties);
  DCHECK(!map->is_dictionary_map());
  cache->set(number_of_properties, MakeWeak(*map));
  return map;
}

Handle<MegaDomHandler> Factory::NewMegaDomHandler(MaybeObjectHandle accessor,
                                                  MaybeObjectHandle context) {
  DirectHandle<Map> map = read_only_roots().mega_dom_handler_map_handle();
  Tagged<MegaDomHandler> handler =
      Cast<MegaDomHandler>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  handler->set_accessor(*accessor, kReleaseStore);
  handler->set_context(*context);
  return handle(handler, isolate());
}

Handle<LoadHandler> Factory::NewLoadHandler(int data_count,
                                            AllocationType allocation) {
  DirectHandle<Map> map;
  switch (data_count) {
    case 1:
      map = load_handler1_map();
      break;
    case 2:
      map = load_handler2_map();
      break;
    case 3:
      map = load_handler3_map();
      break;
    default:
      UNREACHABLE();
  }
  return handle(Cast<LoadHandler>(New(map, allocation)), isolate());
}

Handle<StoreHandler> Factory::NewStoreHandler(int data_count) {
  DirectHandle<Map> map;
  switch (data_count) {
    case 0:
      map = store_handler0_map();
      break;
    case 1:
      map = store_handler1_map();
      break;
    case 2:
      map = store_handler2_map();
      break;
    case 3:
      map = store_handler3_map();
      break;
    default:
      UNREACHABLE();
  }
  return handle(Cast<StoreHandler>(New(map, AllocationType::kOld)), isolate());
}

void Factory::SetRegExpAtomData(DirectHandle<JSRegExp> regexp,
                                DirectHandle<String> source,
                                JSRegExp::Flags flags,
                                DirectHandle<String> pattern) {
  DirectHandle<RegExpData> regexp_data =
      NewAtomRegExpData(source, flags, pattern);
  regexp->set_data(*regexp_data);
}

void Factory::SetRegExpIrregexpData(DirectHandle<JSRegExp> regexp,
                                    DirectHandle<String> source,
                                    JSRegExp::Flags flags, int capture_count,
                                    uint32_t backtrack_limit) {
  DirectHandle<RegExpData> regexp_data =
      NewIrRegExpData(source, flags, capture_count, backtrack_limit);
  regexp->set_data(*regexp_data);
}

void Factory::SetRegExpExperimentalData(DirectHandle<JSRegExp> regexp,
                                        DirectHandle<String> source,
                                        JSRegExp::Flags flags,
                                        int capture_count) {
  DirectHandle<RegExpData> regexp_data =
      NewExperimentalRegExpData(source, flags, capture_count);
  regexp->set_data(*regexp_data);
}

Handle<RegExpData> Factory::NewAtomRegExpData(DirectHandle<String> source,
                                              JSRegExp::Flags flags,
                                              DirectHandle<String> pattern) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = AtomRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().atom_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<AtomRegExpData> instance = Cast<AtomRegExpData>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::ATOM);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->set_pattern(*pattern);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<RegExpData> Factory::NewIrRegExpData(DirectHandle<String> source,
                                            JSRegExp::Flags flags,
                                            int capture_count,
                                            uint32_t backtrack_limit) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = IrRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().ir_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<IrRegExpData> instance = Cast<IrRegExpData>(result);
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::IRREGEXP);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->clear_latin1_code();
  instance->clear_uc16_code();
  instance->clear_latin1_bytecode();
  instance->clear_uc16_bytecode();
  instance->set_capture_name_map(Smi::FromInt(JSRegExp::kUninitializedValue));
  instance->set_max_register_count(JSRegExp::kUninitializedValue);
  instance->set_capture_count(capture_count);
  int ticks_until_tier_up = v8_flags.regexp_tier_up
                                ? v8_flags.regexp_tier_up_ticks
                                : JSRegExp::kUninitializedValue;
  instance->set_ticks_until_tier_up(ticks_until_tier_up);
  instance->set_backtrack_limit(backtrack_limit);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<RegExpData> Factory::NewExperimentalRegExpData(
    DirectHandle<String> source, JSRegExp::Flags flags, int capture_count) {
  DirectHandle<RegExpDataWrapper> wrapper = NewRegExpDataWrapper();
  int size = IrRegExpData::kSize;
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, read_only_roots().ir_regexp_data_map());
  DisallowGarbageCollection no_gc;
  Tagged<IrRegExpData> instance = Cast<IrRegExpData>(result);
  // TODO(mbid,v8:10765): At the moment the ExperimentalRegExpData is just an
  // alias of IrRegExpData, with most fields set to some default/uninitialized
  // value. This is because EXPERIMENTAL and IRREGEXP regexps take the same code
  // path in `RegExpExecInternal`, which reads off various fields from this
  // struct. `RegExpExecInternal` should probably distinguish between
  // EXPERIMENTAL and IRREGEXP, and then we can get rid of all the IRREGEXP only
  // fields.
  instance->init_self_indirect_pointer(isolate());
  instance->set_type_tag(RegExpData::Type::EXPERIMENTAL);
  instance->set_source(*source);
  instance->set_flags(flags);
  instance->clear_latin1_code();
  instance->clear_uc16_code();
  instance->clear_latin1_bytecode();
  instance->clear_uc16_bytecode();
  instance->set_capture_name_map(Smi::FromInt(JSRegExp::kUninitializedValue));
  instance->set_max_register_count(JSRegExp::kUninitializedValue);
  instance->set_capture_count(capture_count);
  instance->set_ticks_until_tier_up(JSRegExp::kUninitializedValue);
  instance->set_backtrack_limit(JSRegExp::kUninitializedValue);
  Tagged<RegExpDataWrapper> raw_wrapper = *wrapper;
  instance->set_wrapper(raw_wrapper);
  raw_wrapper->set_data(instance);
  return handle(instance, isolate());
}

Handle<Object> Factory::GlobalConstantFor(Handle<Name> name) {
  if (Name::Equals(isolate(), name, undefined_string())) {
    return undefined_value();
  }
  if (Name::Equals(isolate(), name, NaN_string())) return nan_value();
  if (Name::Equals(isolate(), name, Infinity_string())) return infinity_value();
  return Handle<Object>::null();
}

Handle<String> Factory::ToPrimitiveHintString(ToPrimitiveHint hint) {
  switch (hint) {
    case ToPrimitiveHint::kDefault:
      return default_string();
    case ToPrimitiveHint::kNumber:
      return number_string();
    case ToPrimitiveHint::kString:
      return string_string();
  }
  UNREACHABLE();
}

Handle<Map> Factory::CreateSloppyFunctionMap(
    FunctionMode function_mode, MaybeHandle<JSFunction> maybe_empty_function) {
  bool has_prototype = IsFunctionModeWithPrototype(function_mode);
  int header_size = has_prototype ? JSFunction::kSizeWithPrototype
                                  : JSFunction::kSizeWithoutPrototype;
  int descriptors_count = has_prototype ? 5 : 4;
  int inobject_properties_count = 0;
  if (IsFunctionModeWithName(function_mode)) ++inobject_properties_count;

  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_FUNCTION_TYPE, header_size + inobject_properties_count * kTaggedSize,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties_count);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(has_prototype);
    raw_map->set_is_constructor(has_prototype);
    raw_map->set_is_callable(true);
  }
  Handle<JSFunction> empty_function;
  if (maybe_empty_function.ToHandle(&empty_function)) {
    // Temporarily set constructor to empty function to calm down map verifier.
    map->SetConstructor(*empty_function);
    Map::SetPrototype(isolate(), map, empty_function);
  } else {
    // |maybe_empty_function| is allowed to be empty only during empty function
    // creation.
    DCHECK(IsUndefined(
        isolate()->raw_native_context()->get(Context::EMPTY_FUNCTION_INDEX)));
  }

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, descriptors_count);

  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes rw_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  int field_index = 0;
  static_assert(
      JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  static_assert(
      JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex == 1);
  if (IsFunctionModeWithName(function_mode)) {
    // Add name field.
    Handle<Name> name = isolate()->factory()->name_string();
    Descriptor d = Descriptor::DataField(isolate(), name, field_index++,
                                         roc_attribs, Representation::Tagged());
    map->AppendDescriptor(isolate(), &d);

  } else {
    // Add name accessor.
    Descriptor d = Descriptor::AccessorConstant(
        name_string(), function_name_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  {  // Add arguments accessor.
    Descriptor d = Descriptor::AccessorConstant(
        arguments_string(), function_arguments_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  {  // Add caller accessor.
    Descriptor d = Descriptor::AccessorConstant(
        caller_string(), function_caller_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  if (IsFunctionModeWithPrototype(function_mode)) {
    // Add prototype accessor.
    PropertyAttributes attribs =
        IsFunctionModeWithWritablePrototype(function_mode) ? rw_attribs
                                                           : ro_attribs;
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  DCHECK_EQ(inobject_properties_count, field_index);
  DCHECK_EQ(
      0, map->instance_descriptors(isolate())->number_of_slack_descriptors());
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<Map> Factory::CreateStrictFunctionMap(
    FunctionMode function_mode, Handle<JSFunction> empty_function) {
  bool has_prototype = IsFunctionModeWithPrototype(function_mode);
  int header_size = has_prototype ? JSFunction::kSizeWithPrototype
                                  : JSFunction::kSizeWithoutPrototype;
  int inobject_properties_count = 0;
  // length and prototype accessors or just length accessor.
  int descriptors_count = IsFunctionModeWithPrototype(function_mode) ? 2 : 1;
  if (IsFunctionModeWithName(function_mode)) {
    ++inobject_properties_count;  // name property.
  } else {
    ++descriptors_count;  // name accessor.
  }
  descriptors_count += inobject_properties_count;

  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_FUNCTION_TYPE, header_size + inobject_properties_count * kTaggedSize,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties_count);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(has_prototype);
    raw_map->set_is_constructor(has_prototype);
    raw_map->set_is_callable(true);
    // Temporarily set constructor to empty function to calm down map verifier.
    raw_map->SetConstructor(*empty_function);
  }
  Map::SetPrototype(isolate(), map, empty_function);

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, descriptors_count);

  PropertyAttributes rw_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);
  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  int field_index = 0;
  static_assert(JSFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  static_assert(JSFunction::kNameDescriptorIndex == 1);
  if (IsFunctionModeWithName(function_mode)) {
    // Add name field.
    Handle<Name> name = isolate()->factory()->name_string();
    Descriptor d = Descriptor::DataField(isolate(), name, field_index++,
                                         roc_attribs, Representation::Tagged());
    map->AppendDescriptor(isolate(), &d);

  } else {
    // Add name accessor.
    Descriptor d = Descriptor::AccessorConstant(
        name_string(), function_name_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  if (IsFunctionModeWithPrototype(function_mode)) {
    // Add prototype accessor.
    PropertyAttributes attribs =
        IsFunctionModeWithWritablePrototype(function_mode) ? rw_attribs
                                                           : ro_attribs;
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  DCHECK_EQ(inobject_properties_count, field_index);
  DCHECK_EQ(
      0, map->instance_descriptors(isolate())->number_of_slack_descriptors());
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<Map> Factory::CreateClassFunctionMap(Handle<JSFunction> empty_function) {
  Handle<Map> map = NewContextfulMapForCurrentContext(
      JS_CLASS_CONSTRUCTOR_TYPE, JSFunction::kSizeWithPrototype);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw_map = *map;
    raw_map->set_has_prototype_slot(true);
    raw_map->set_is_constructor(true);
    raw_map->set_is_prototype_map(true);
    raw_map->set_is_callable(true);
    // Temporarily set constructor to empty function to calm down map verifier.
    raw_map->SetConstructor(*empty_function);
  }
  Map::SetPrototype(isolate(), map, empty_function);

  //
  // Setup descriptors array.
  //
  Map::EnsureDescriptorSlack(isolate(), map, 2);

  PropertyAttributes ro_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);
  PropertyAttributes roc_attribs =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);

  static_assert(JSFunction::kLengthDescriptorIndex == 0);
  {  // Add length accessor.
    Descriptor d = Descriptor::AccessorConstant(
        length_string(), function_length_accessor(), roc_attribs);
    map->AppendDescriptor(isolate(), &d);
  }

  {
    // Add prototype accessor.
    Descriptor d = Descriptor::AccessorConstant(
        prototype_string(), function_prototype_accessor(), ro_attribs);
    map->AppendDescriptor(isolate(), &d);
  }
  LOG(isolate(), MapDetails(*map));
  return map;
}

Handle<JSPromise> Factory::NewJSPromiseWithoutHook() {
  Handle<JSPromise> promise =
      Cast<JSPromise>(NewJSObject(isolate()->promise_function()));
  DisallowGarbageCollection no_gc;
  Tagged<JSPromise> raw = *promise;
  raw->set_reactions_or_result(Smi::zero(), SKIP_WRITE_BARRIER);
  raw->set_flags(0);
  // TODO(v8) remove once embedder data slots are always zero-initialized.
  InitEmbedderFields(*promise, Smi::zero());
  DCHECK_EQ(raw->GetEmbedderFieldCount(), v8::Promise::kEmbedderFieldCount);
  return promise;
}

Handle<JSPromise> Factory::NewJSPromise() {
  Handle<JSPromise> promise = NewJSPromiseWithoutHook();
  isolate()->RunAllPromiseHooks(PromiseHookType::kInit, promise,
                                undefined_value());
  return promise;
}

bool Factory::CanAllocateInReadOnlySpace() {
  return allocator()->CanAllocateInReadOnlySpace();
}

bool Factory::EmptyStringRootIsInitialized() {
  return isolate()->roots_table()[RootIndex::kempty_string] != kNullAddress;
}

AllocationType Factory::AllocationTypeForInPlaceInternalizableString() {
  return isolate()
      ->heap()
      ->allocation_type_for_in_place_internalizable_strings();
}

Handle<JSFunction> Factory::NewFunctionForTesting(DirectHandle<String> name) {
  Handle<SharedFunctionInfo> info =
      NewSharedFunctionInfoForBuiltin(name, Builtin::kIllegal, 0, kDontAdapt);
  info->set_language_mode(LanguageMode::kSloppy);
  return JSFunctionBuilder{isolate(), info, isolate()->native_context()}
      .Build();
}

Handle<JSSharedStruct> Factory::NewJSSharedStruct(
    Handle<JSFunction> constructor,
    MaybeHandle<NumberDictionary> maybe_elements_template) {
  SharedObjectSafePublishGuard publish_guard;

  DirectHandle<Map> instance_map(constructor->initial_map(), isolate());
  DirectHandle<PropertyArray> property_array;
  const int num_oob_fields =
      instance_map->NumberOfFields(ConcurrencyMode::kSynchronous) -
      instance_map->GetInObjectProperties();
  if (num_oob_fields > 0) {
    property_array =
        NewPropertyArray(num_oob_fields, AllocationType::kSharedOld);
  }

  Handle<NumberDictionary> elements_dictionary;
  bool has_elements_dictionary;
  if ((has_elements_dictionary =
           maybe_elements_template.ToHandle(&elements_dictionary))) {
    elements_dictionary = NumberDictionary::ShallowCopy(
        isolate(), elements_dictionary, AllocationType::kSharedOld);
  }

  Handle<JSSharedStruct> instance = Cast<JSSharedStruct>(
      NewJSObject(constructor, AllocationType::kSharedOld));

  // The struct object has not been fully initialized yet. Disallow allocation
  // from this point on.
  DisallowGarbageCollection no_gc;
  if (!property_array.is_null()) instance->SetProperties(*property_array);
  if (has_elements_dictionary) instance->set_elements(*elements_dictionary);

  return instance;
}

Handle<JSSharedArray> Factory::NewJSSharedArray(Handle<JSFunction> constructor,
                                                int length) {
  SharedObjectSafePublishGuard publish_guard;
  DirectHandle<FixedArrayBase> storage =
      NewFixedArray(length, AllocationType::kSharedOld);
  auto instance =
      Cast<JSSharedArray>(NewJSObject(constructor, AllocationType::kSharedOld));
  instance->set_elements(*storage);
  FieldIndex index = FieldIndex::ForDescriptor(
      constructor->initial_map(),
      InternalIndex(JSSharedArray::kLengthFieldIndex));
  instance->FastPropertyAtPut(index, Smi::FromInt(length), SKIP_WRITE_BARRIER);
  return instance;
}

Handle<JSAtomicsMutex> Factory::NewJSAtomicsMutex() {
  SharedObjectSafePublishGuard publish_guard;
  DirectHandle<Map> map = read_only_roots().js_atomics_mutex_map_handle();
  auto mutex =
      Cast<JSAtomicsMutex>(NewJSObjectFromMap(map, AllocationType::kSharedOld));
  mutex->set_state(JSAtomicsMutex::kUnlockedUncontended);
  mutex->set_owner_thread_id(ThreadId::Invalid().ToInteger());
  mutex->SetNullWaiterQueueHead();
  return mutex;
}

Handle<JSAtomicsCondition> Factory::NewJSAtomicsCondition() {
  SharedObjectSafePublishGuard publish_guard;
  DirectHandle<Map> map = read_only_roots().js_atomics_condition_map_handle();
  Handle<JSAtomicsCondition> cond = Cast<JSAtomicsCondition>(
      NewJSObjectFromMap(map, AllocationType::kSharedOld));
  cond->set_state(JSAtomicsCondition::kEmptyState);
  cond->SetNullWaiterQueueHead();
  return cond;
}

namespace {

inline void InitializeTemplate(Tagged<TemplateInfo> that, ReadOnlyRoots roots,
                               bool do_not_cache) {
  that->set_number_of_properties(0);
  int serial_number =
      do_not_cache ? TemplateInfo::kDoNotCache : TemplateInfo::kUncached;
  that->set_serial_number(serial_number);
  that->set_property_list(roots.undefined_value(), SKIP_WRITE_BARRIER);
  that->set_property_accessors(roots.undefined_value(), SKIP_WRITE_BARRIER);
}

}  // namespace

Handle<FunctionTemplateInfo> Factory::NewFunctionTemplateInfo(
    int length, bool do_not_cache) {
  const int size = FunctionTemplateInfo::SizeFor();
  Tagged<FunctionTemplateInfo> obj =
      Cast<FunctionTemplateInfo>(AllocateRawWithImmortalMap(
          size, AllocationType::kOld,
          read_only_roots().function_template_info_map()));
  {
    // Disallow GC until all fields of obj have acceptable types.
    DisallowGarbageCollection no_gc;
    Tagged<FunctionTemplateInfo> raw = *obj;
    ReadOnlyRoots roots(isolate());
    InitializeTemplate(raw, roots, do_not_cache);
    raw->set_class_name(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_interface_name(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_signature(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_rare_data(roots.undefined_value(), kReleaseStore,
                       SKIP_WRITE_BARRIER);
    raw->set_shared_function_info(roots.undefined_value(), SKIP_WRITE_BARRIER);
    raw->set_cached_property_name(roots.the_hole_value(), SKIP_WRITE_BARRIER);

    raw->set_flag(0, kRelaxedStore);
    raw->set_undetectable(false);
    raw->set_needs_access_check(false);
    raw->set_accept_any_receiver(true);
    raw->set_exception_context(
        static_cast<uint32_t>(ExceptionContext::kUnknown));

    raw->set_length(length);
    raw->SetInstanceType(0);
    raw->init_callback(isolate(), kNullAddress);
    raw->set_callback_data(roots.the_hole_value(), kReleaseStore,
                           SKIP_WRITE_BARRIER);
  }
  return handle(obj, isolate());
}

Handle<ObjectTemplateInfo> Factory::NewObjectTemplateInfo(
    DirectHandle<FunctionTemplateInfo> constructor, bool do_not_cache) {
  const int size = ObjectTemplateInfo::SizeFor();
  Tagged<ObjectTemplateInfo> obj = Cast<ObjectTemplateInfo>(
      AllocateRawWithImmortalMap(size, AllocationType::kOld,
                                 read_only_roots().object_template_info_map()));
  {
    // Disallow GC until all fields of obj have acceptable types.
    DisallowGarbageCollection no_gc;
    Tagged<ObjectTemplateInfo> raw = *obj;
    ReadOnlyRoots roots(isolate());
    InitializeTemplate(raw, roots, do_not_cache);
    if (constructor.is_null()) {
      raw->set_constructor(roots.undefined_value(), SKIP_WRITE_BARRIER);
    } else {
      raw->set_constructor(*constructor);
    }
    raw->set_data(0);
  }
  return handle(obj, isolate());
}

Handle<DictionaryTemplateInfo> Factory::NewDictionaryTemplateInfo(
    DirectHandle<FixedArray> property_names) {
  const int size = DictionaryTemplateInfo::SizeFor();
  DirectHandle<Map> map =
      read_only_roots().dictionary_template_info_map_handle();
  Tagged<DictionaryTemplateInfo> obj = Cast<DictionaryTemplateInfo>(
      AllocateRawWithImmortalMap(size, AllocationType::kOld, *map));
  obj->set_property_names(*property_names);
  obj->set_serial_number(TemplateInfo::kUncached);
  return handle(obj, isolate());
}

Handle<TrustedForeign> Factory::NewTrustedForeign(Address addr) {
  // Statically ensure that it is safe to allocate foreigns in paged spaces.
  static_assert(TrustedForeign::kSize <= kMaxRegularHeapObjectSize);
  Tagged<Map> map = *trusted_foreign_map();
  Tagged<TrustedForeign> foreign =
      Cast<TrustedForeign>(AllocateRawWithImmortalMap(
          map->instance_size(), AllocationType::kTrusted, map));
  DisallowGarbageCollection no_gc;
  foreign->set_foreign_address(addr);
  return handle(foreign, isolate());
}

Factory::JSFunctionBuilder::JSFunctionBuilder(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> sfi,
    DirectHandle<Context> context)
    : isolate_(isolate), sfi_(sfi), context_(context) {}

Handle<JSFunction> Factory::JSFunctionBuilder::Build() {
  PrepareMap();
  PrepareFeedbackCell();

  DirectHandle<Code> code(sfi_->GetCode(isolate_), isolate_);
  // Retain the code across the call to BuildRaw, because it allocates and can
  // trigger code to be flushed. Otherwise the SFI's compiled state and the
  // function's compiled state can diverge, and the call to PostInstantiation
  // below can fail to initialize the feedback vector.
  IsCompiledScope is_compiled_scope(sfi_->is_compiled_scope(isolate_));
  Handle<JSFunction> result = BuildRaw(code);

  if (code->kind() == CodeKind::BASELINE) {
    JSFunction::EnsureFeedbackVector(isolate_, result, &is_compiled_scope);
  }

  Compiler::PostInstantiation(isolate_, result, &is_compiled_scope);
  return result;
}

Handle<JSFunction> Factory::JSFunctionBuilder::BuildRaw(
    DirectHandle<Code> code) {
  Isolate* isolate = isolate_;
  Factory* factory = isolate_->factory();

  DirectHandle<Map> map = maybe_map_.ToHandleChecked();
  DirectHandle<FeedbackCell> feedback_cell =
      maybe_feedback_cell_.ToHandleChecked();

  DCHECK(InstanceTypeChecker::IsJSFunction(*map));

  // Allocation.
  Tagged<JSFunction> function =
      Cast<JSFunction>(factory->New(map, allocation_type_));
  DisallowGarbageCollection no_gc;

  WriteBarrierMode mode = allocation_type_ == AllocationType::kYoung
                              ? SKIP_WRITE_BARRIER
                              : UPDATE_WRITE_BARRIER;
  // Header initialization.
  function->initialize_properties(isolate);
  function->initialize_elements();
  function->set_shared(*sfi_, mode);
  function->set_context(*context_, kReleaseStore, mode);
  function->set_raw_feedback_cell(*feedback_cell, mode)
```