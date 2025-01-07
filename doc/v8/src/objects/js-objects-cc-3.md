Response:
The user wants a summary of the provided C++ code snippet from V8's `js-objects.cc` file, specifically focusing on its functionality. The request also includes considerations for .tq files, JavaScript relevance, code logic, common programming errors, and the fact that this is part 4 of 8.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The code primarily deals with determining the header size of various JavaScript object types. This is done through a large `switch` statement based on the `InstanceType`.

2. **Address the .tq Question:** The snippet is clearly C++, not Torque. State this fact directly.

3. **Connect to JavaScript Functionality:**  The different `case` statements in the `switch` directly correspond to JavaScript object types (e.g., `JSGlobalObject`, `JSFunction`, `JSArray`, `JSMap`, `Promise`, `RegExp`, etc.). Provide JavaScript examples for some of the key types to illustrate this connection. Prioritize common and fundamental types.

4. **Code Logic and Assumptions:** The code logic is straightforward: based on the object type, it returns a predefined size. The assumption is that the `type` variable holds a valid `InstanceType`. Illustrate this with a simple example showing the input (`JS_ARRAY_TYPE`) and the expected output (`JSArray::kHeaderSize`).

5. **Common Programming Errors (Relevance):**  While the *provided* code doesn't directly expose opportunities for common *user* programming errors in JavaScript, the underlying concept of object types and their structure is relevant. Explain how incorrect type assumptions in user code can lead to errors, but acknowledge that this specific C++ snippet is more about V8's internal workings.

6. **Part 4 of 8 -  Contextualization:** Since this is part of a larger file, acknowledge that this specific snippet likely deals with a low-level aspect of object representation. Infer that other parts might cover object creation, manipulation, etc.

7. **Summarize the Functionality:** Combine the above points into a concise summary that answers the core request. Highlight the main purpose (determining object header size) and the mechanism (switch statement based on `InstanceType`).

8. **Review and Refine:**  Ensure the language is clear, the examples are accurate, and all parts of the user's request have been addressed. Make sure the JavaScript examples are simple and illustrative. Clarify the distinction between V8's internal mechanisms and user-level JavaScript errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the C++ aspect.
* **Correction:**  Shift focus to the connection with JavaScript object types, as this is more relevant to the user's context (given the prompt).
* **Initial thought:** Provide overly technical C++ explanations.
* **Correction:** Keep the C++ explanations high-level and focus on the purpose of the code.
* **Initial thought:**  Try to find direct user-level errors related to *this specific code*.
* **Correction:**  Broaden the scope to discuss how understanding object types (even though this is internal) is relevant to avoiding errors in JavaScript.

By following these steps, the generated response effectively addresses all aspects of the user's prompt and provides a clear and informative summary of the code snippet's functionality.
```cpp
e JS_GLOBAL_OBJECT_TYPE:
      return JSGlobalObject::kHeaderSize;
    case JS_BOUND_FUNCTION_TYPE:
      return JSBoundFunction::kHeaderSize;
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      return JSFunction::GetHeaderSize(function_has_prototype_slot);
    case JS_PRIMITIVE_WRAPPER_TYPE:
      return JSPrimitiveWrapper::kHeaderSize;
    case JS_DATE_TYPE:
      return JSDate::kHeaderSize;
    case JS_DISPOSABLE_STACK_BASE_TYPE:
      return JSDisposableStackBase::kHeaderSize;
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
      return JSAsyncDisposableStack::kHeaderSize;
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
      return JSSyncDisposableStack::kHeaderSize;
    case JS_ARRAY_TYPE:
      return JSArray::kHeaderSize;
    case JS_ARRAY_BUFFER_TYPE:
      return JSArrayBuffer::kHeaderSize;
    case JS_ARRAY_ITERATOR_TYPE:
      return JSArrayIterator::kHeaderSize;
    case JS_TYPED_ARRAY_TYPE:
      return JSTypedArray::kHeaderSize;
    case JS_DATA_VIEW_TYPE:
      return JSDataView::kHeaderSize;
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return JSRabGsabDataView::kHeaderSize;
    case JS_SET_TYPE:
      return JSSet::kHeaderSize;
    case JS_MAP_TYPE:
      return JSMap::kHeaderSize;
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      return JSSetIterator::kHeaderSize;
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
      return JSMapIterator::kHeaderSize;
    case JS_WEAK_REF_TYPE:
      return JSWeakRef::kHeaderSize;
    case JS_FINALIZATION_REGISTRY_TYPE:
      return JSFinalizationRegistry::kHeaderSize;
    case JS_WEAK_MAP_TYPE:
      return JSWeakMap::kHeaderSize;
    case JS_WEAK_SET_TYPE:
      return JSWeakSet::kHeaderSize;
    case JS_PROMISE_TYPE:
      return JSPromise::kHeaderSize;
    case JS_REG_EXP_TYPE:
      return JSRegExp::kHeaderSize;
    case JS_REG_EXP_STRING_ITERATOR_TYPE:
      return JSRegExpStringIterator::kHeaderSize;
    case JS_MESSAGE_OBJECT_TYPE:
      return JSMessageObject::kHeaderSize;
    case JS_EXTERNAL_OBJECT_TYPE:
      return JSExternalObject::kHeaderSize;
    case JS_SHADOW_REALM_TYPE:
      return JSShadowRealm::kHeaderSize;
    case JS_STRING_ITERATOR_TYPE:
      return JSStringIterator::kHeaderSize;
    case JS_ITERATOR_MAP_HELPER_TYPE:
      return JSIteratorMapHelper::kHeaderSize;
    case JS_ITERATOR_FILTER_HELPER_TYPE:
      return JSIteratorFilterHelper::kHeaderSize;
    case JS_ITERATOR_TAKE_HELPER_TYPE:
      return JSIteratorTakeHelper::kHeaderSize;
    case JS_ITERATOR_DROP_HELPER_TYPE:
      return JSIteratorDropHelper::kHeaderSize;
    case JS_ITERATOR_FLAT_MAP_HELPER_TYPE:
      return JSIteratorFlatMapHelper::kHeaderSize;
    case JS_MODULE_NAMESPACE_TYPE:
      return JSModuleNamespace::kHeaderSize;
    case JS_SHARED_ARRAY_TYPE:
      return JSSharedArray::kHeaderSize;
    case JS_SHARED_STRUCT_TYPE:
      return JSSharedStruct::kHeaderSize;
    case JS_ATOMICS_MUTEX_TYPE:
      return JSAtomicsMutex::kHeaderSize;
    case JS_ATOMICS_CONDITION_TYPE:
      return JSAtomicsCondition::kHeaderSize;
    case JS_TEMPORAL_CALENDAR_TYPE:
      return JSTemporalCalendar::kHeaderSize;
    case JS_TEMPORAL_DURATION_TYPE:
      return JSTemporalDuration::kHeaderSize;
    case JS_TEMPORAL_INSTANT_TYPE:
      return JSTemporalInstant::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
      return JSTemporalPlainDate::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
      return JSTemporalPlainDateTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
      return JSTemporalPlainMonthDay::kHeaderSize;
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
      return JSTemporalPlainTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
      return JSTemporalPlainYearMonth::kHeaderSize;
    case JS_TEMPORAL_TIME_ZONE_TYPE:
      return JSTemporalTimeZone::kHeaderSize;
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
      return JSTemporalZonedDateTime::kHeaderSize;
    case JS_VALID_ITERATOR_WRAPPER_TYPE:
      return JSValidIteratorWrapper::kHeaderSize;
    case JS_WRAPPED_FUNCTION_TYPE:
      return JSWrappedFunction::kHeaderSize;
    case JS_RAW_JSON_TYPE:
      return JSRawJson::kHeaderSize;
#ifdef V8_INTL_SUPPORT
    case JS_V8_BREAK_ITERATOR_TYPE:
      return JSV8BreakIterator::kHeaderSize;
    case JS_COLLATOR_TYPE:
      return JSCollator::kHeaderSize;
    case JS_DATE_TIME_FORMAT_TYPE:
      return JSDateTimeFormat::kHeaderSize;
    case JS_DISPLAY_NAMES_TYPE:
      return JSDisplayNames::kHeaderSize;
    case JS_DURATION_FORMAT_TYPE:
      return JSDurationFormat::kHeaderSize;
    case JS_LIST_FORMAT_TYPE:
      return JSListFormat::kHeaderSize;
    case JS_LOCALE_TYPE:
      return JSLocale::kHeaderSize;
    case JS_NUMBER_FORMAT_TYPE:
      return JSNumberFormat::kHeaderSize;
    case JS_PLURAL_RULES_TYPE:
      return JSPluralRules::kHeaderSize;
    case JS_RELATIVE_TIME_FORMAT_TYPE:
      return JSRelativeTimeFormat::kHeaderSize;
    case JS_SEGMENT_ITERATOR_TYPE:
      return JSSegmentIterator::kHeaderSize;
    case JS_SEGMENTER_TYPE:
      return JSSegmenter::kHeaderSize;
    case JS_SEGMENTS_TYPE:
      return JSSegments::kHeaderSize;
#endif  // V8_INTL_SUPPORT
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
      return WasmGlobalObject::kHeaderSize;
    case WASM_INSTANCE_OBJECT_TYPE:
      return WasmInstanceObject::kHeaderSize;
    case WASM_MEMORY_OBJECT_TYPE:
      return WasmMemoryObject::kHeaderSize;
    case WASM_MODULE_OBJECT_TYPE:
      return WasmModuleObject::kHeaderSize;
    case WASM_TABLE_OBJECT_TYPE:
      return WasmTableObject::kHeaderSize;
    case WASM_VALUE_OBJECT_TYPE:
      return WasmValueObject::kHeaderSize;
    case WASM_TAG_OBJECT_TYPE:
      return WasmTagObject::kHeaderSize;
    case WASM_EXCEPTION_PACKAGE_TYPE:
      return WasmExceptionPackage::kHeaderSize;
    case WASM_SUSPENDING_OBJECT_TYPE:
      return WasmSuspendingObject::kHeaderSize;
#endif  // V8_ENABLE_WEBASSEMBLY
    default: {
      // Special type check for API Objects because they are in a large variable
      // instance type range.
      if (InstanceTypeChecker::IsJSApiObject(type)) {
        return JSAPIObjectWithEmbedderSlots::BodyDescriptor::kHeaderSize;
      }
      FATAL("unexpected instance type: %s\n", NonAPIInstanceTypeToString(type));
    }
  }
}

MaybeHandle<JSAny> JSObject::GetPropertyWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Handle<JSAny> result;
    bool done;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        GetPropertyWithInterceptorInternal(it, interceptor, &done));
    if (done) return result;
  }

  // Cross-Origin [[Get]] of Well-Known Symbols does not throw, and returns
  // undefined.
  DirectHandle<Name> name = it->GetName();
  if (IsSymbol(*name) && Cast<Symbol>(*name)->is_well_known_symbol()) {
    return it->factory()->undefined_value();
  }

  RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(checked));
  UNREACHABLE();
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Maybe<PropertyAttributes> result =
        GetPropertyAttributesWithInterceptorInternal(it, interceptor);
    if (isolate->has_exception()) return Nothing<PropertyAttributes>();
    if (result.FromMaybe(ABSENT) != ABSENT) return result;
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<PropertyAttributes>());
  UNREACHABLE();
}

Maybe<bool> JSObject::SetPropertyWithFailedAccessCheck(
    LookupIterator* it, Handle<Object> value, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    InterceptorResult result;
    if (!SetPropertyWithInterceptorInternal(it, interceptor, should_throw,
                                            value)
             .To(&result)) {
      // An exception was thrown in the interceptor. Propagate.
      return Nothing<bool>();
    }
    switch (result) {
      case InterceptorResult::kFalse:
        return Just(false);
      case InterceptorResult::kTrue:
        return Just(true);
      case InterceptorResult::kNotIntercepted:
        // Fall through to report failed access check.
        break;
    }
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<bool>());
  UNREACHABLE();
}

void JSObject::SetNormalizedProperty(Handle<JSObject> object, Handle<Name> name,
                                     Handle<Object> value,
                                     PropertyDetails details) {
  DCHECK(!object->HasFastProperties());
  DCHECK(IsUniqueName(*name));
  Isolate* isolate = object->GetIsolate();

  uint32_t hash = name->hash();

  if (IsJSGlobalObject(*object)) {
    auto global_obj = Cast<JSGlobalObject>(object);
    Handle<GlobalDictionary> dictionary(
        global_obj->global_dictionary(kAcquireLoad), isolate);
    ReadOnlyRoots roots(isolate);
    InternalIndex entry = dictionary->FindEntry(isolate, roots, name, hash);

    if (entry.is_not_found()) {
      DCHECK_IMPLIES(global_obj->map()->is_prototype_map(),
                     Map::IsPrototypeChainInvalidated(global_obj->map()));
      auto cell_type = IsUndefined(*value, roots) ? PropertyCellType::kUndefined
                                                  : PropertyCellType::kConstant;
      details = details.set_cell_type(cell_type);
      auto cell = isolate->factory()->NewPropertyCell(name, details, value);
      dictionary =
          GlobalDictionary::Add(isolate, dictionary, name, cell, details);
      global_obj->set_global_dictionary(*dictionary, kReleaseStore);
    } else {
      PropertyCell::PrepareForAndSetValue(isolate, dictionary, entry, value,
                                          details);
      DCHECK_EQ(dictionary->CellAt(entry)->value(), *value);
    }
  } else {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          object->property_dictionary_swiss(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, *name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            SwissNameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        dictionary->ValueAtPut(entry, *value);
        dictionary->DetailsAtPut(entry, details);
      }
    } else {
      Handle<NameDictionary> dictionary(object->property_dictionary(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            NameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        PropertyDetails original_details = dictionary->DetailsAt(entry);
        int enumeration_index = original_details.dictionary_index();
        DCHECK_GT(enumeration_index, 0);
        details = details.set_index(enumeration_index);
        dictionary->SetEntry(entry, *name, *value, details);
      }
      // TODO(pthier): Add flags to swiss dictionaries.
      if (name->IsInteresting(isolate)) {
        dictionary->set_may_have_interesting_properties(true);
      }
    }
  }
}

void JSObject::SetNormalizedElement(Handle<JSObject> object, uint32_t index,
                                    Handle<Object> value,
                                    PropertyDetails details) {
  DCHECK_EQ(object->GetElementsKind(), DICTIONARY_ELEMENTS);

  Isolate* isolate = object->GetIsolate();

  Handle<NumberDictionary> dictionary =
      handle(Cast<NumberDictionary>(object->elements()), isolate);
  dictionary =
      NumberDictionary::Set(isolate, dictionary, index, value, object, details);
  object->set_elements(*dictionary);
}

void JSObject::JSObjectShortPrint(StringStream* accumulator) {
  switch (map()->instance_type()) {
    case JS_ARRAY_TYPE: {
      double length = IsUndefined(Cast<JSArray>(*this)->length())
                          ? 0
                          : Object::NumberValue(Cast<JSArray>(*this)->length());
      accumulator->Add("<JSArray[%u]>", static_cast<uint32_t>(length));
      break;
    }
    case JS_BOUND_FUNCTION_TYPE: {
      Tagged<JSBoundFunction> bound_function = Cast<JSBoundFunction>(*this);
      accumulator->Add("<JSBoundFunction");
      accumulator->Add(" (BoundTargetFunction %p)>",
                       reinterpret_cast<void*>(
                           bound_function->bound_target_function().ptr()));
      break;
    }
    case JS_WEAK_MAP_TYPE: {
      accumulator->Add("<JSWeakMap>");
      break;
    }
    case JS_WEAK_SET_TYPE: {
      accumulator->Add("<JSWeakSet>");
      break;
    }
    case JS_REG_EXP_TYPE: {
      accumulator->Add("<JSRegExp");
      Tagged<JSRegExp> regexp = Cast<JSRegExp>(*this);
      if (IsString(regexp->source())) {
        accumulator->Add(" ");
        Cast<String>(regexp->source())->StringShortPrint(accumulator);
      }
      accumulator->Add(">");

      break;
    }
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_FUNCTION_TYPE: {
      Tagged<JSFunction> function = Cast<JSFunction>(*this);
      std::unique_ptr<char[]> fun_name = function->shared()->DebugNameCStr();
      if (fun_name[0] != '\0') {
        accumulator->Add("<JSFunction ");
        accumulator->Add(fun_name.get());
      } else {
        accumulator->Add("<JSFunction");
      }
      if (v8_flags.trace_file_names) {
        Tagged<Object> source_name =
            Cast<Script>(function->shared()->script())->name();
        if (IsString(source_name)) {
          Tagged<String> str = Cast<String>(source_name);
          if (str->length() > 0) {
            accumulator->Add(" <");
            accumulator->Put(str);
            accumulator->Add(">");
          }
        }
      }
      accumulator->Add(" (sfi = %p)",
                       reinterpret_cast<void*>(function->shared().ptr()));
      accumulator->Put('>');
      break;
    }
    case JS_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JSGenerator>");
      break;
    }
    case JS_ASYNC_FUNCTION_OBJECT_TYPE: {
      accumulator->Add("<JSAsyncFunctionObject>");
      break;
    }
    case JS_ASYNC_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JS AsyncGenerator>");
      break;
    }
    case JS_SHARED_ARRAY_TYPE:
      accumulator->Add("<JSSharedArray>");
      break;
    case JS_SHARED_STRUCT_TYPE:
      accumulator->Add("<JSSharedStruct>");
      break;
    case JS_ATOMICS_MUTEX_TYPE:
      accumulator->Add("<JSAtomicsMutex>");
      break;
    case JS_ATOMICS_CONDITION_TYPE:
      accumulator->Add("<JSAtomicsCondition>");
      break;
    case JS_MESSAGE_OBJECT_TYPE:
      accumulator->Add("<JSMessageObject>");
      break;
    case JS_EXTERNAL_OBJECT_TYPE:
      accumulator->Add("<JSExternalObject>");
      break;

    default: {
      Tagged<Map> map_of_this = map();
      Tagged<Object> constructor = map_of_this->GetConstructor();
      bool printed = false;
      bool is_global_proxy = IsJSGlobalProxy(*this);
      if (IsJSFunction(constructor)) {
        Tagged<SharedFunctionInfo> sfi =
            Cast<JSFunction>(constructor)->shared();
        Tagged<String> constructor_name = sfi->Name();
        if (constructor_name->length() > 0) {
          accumulator->Add(is_global_proxy ? "<GlobalObject " : "<");
          accumulator->Put(constructor_name);
          accumulator->Add(" %smap = %p",
                           map_of_this->is_deprecated() ? "deprecated-" : "",
                           map_of_this);
          printed = true;
        }
      } else if (IsFunctionTemplateInfo(constructor)) {
        accumulator->Add("<RemoteObject>");
        printed = true;
      }
      if (!printed) {
        accumulator->Add("<JS");
        if (is_global_proxy) {
          accumulator->Add("GlobalProxy");
        } else if (IsJSGlobalObject(*this)) {
          accumulator->Add("GlobalObject");
        } else {
          accumulator->Add("Object");
        }
      }
      if (IsJSPrimitiveWrapper(*this)) {
        accumulator->Add(" value = ");
        ShortPrint(Cast<JSPrimitiveWrapper>(*this)->value(), accumulator);
      }
      accumulator->Put('>');
      break;
    }
  }
}

void JSObject::PrintElementsTransition(
    FILE* file, DirectHandle<JSObject> object, ElementsKind from_kind,
    DirectHandle<FixedArrayBase> from_elements, ElementsKind to_kind,
    DirectHandle<FixedArrayBase> to_elements) {
  if (from_kind != to_kind) {
    OFStream os(file);
    os << "elements transition [" << ElementsKindToString(from_kind) << " -> "
       << ElementsKindToString(to_kind) << "] in ";
    JavaScriptFrame::PrintTop(object->GetIsolate(), file, false, true);
    PrintF(file, " for ");
    ShortPrint(*object, file);
    PrintF(file, " from ");
    ShortPrint(*from_elements, file);
    PrintF(file, " to ");
    ShortPrint(*to_elements, file);
    PrintF(file, "\n");
  }
}

void JSObject::PrintInstanceMigration(FILE* file, Tagged<Map> original_map,
                                      Tagged<Map> new_map) {
  if (new_map->is_dictionary_map()) {
    PrintF(file, "[migrating to slow]\n");
    return;
  }
  PrintF(file, "[migrating]");
  Isolate* isolate = GetIsolate();
  Tagged<DescriptorArray> o = original_map->instance_descriptors(isolate);
  Tagged<DescriptorArray> n = new_map->instance_descriptors(isolate);
  for (InternalIndex i : original_map->IterateOwnDescriptors()) {
    Representation o_r = o->GetDetails(i).representation();
    Representation n_r = n->GetDetails(i).representation();
    if (!o_r.Equals(n_r)) {
      Cast<String>(o->GetKey(i))->PrintOn(file);
      PrintF(file, ":%s->%s ", o_r.Mnemonic(), n_r.Mnemonic());
    } else if (o->GetDetails(i).location() == PropertyLocation::kDescriptor &&
               n->GetDetails(i).location() == PropertyLocation::kField) {
      Tagged<Name> name = o->GetKey(i);
      if (IsString(name)) {
        Cast<String>(name)->PrintOn(file);
      } else {
        PrintF(file, "{symbol %p}", reinterpret_cast<void*>(name.ptr()));
      }
      PrintF(file, " ");
    }
  }
  if (original_map->elements_kind() != new_map->elements_kind()) {
    PrintF(file, "elements_kind[%i->%i]", original_map->elements_kind(),
           new_map->elements_kind());
  }
  PrintF(file, "\n");
}

// static
bool JSObject::IsUnmodifiedApiObject(FullObjectSlot o) {
  Tagged<Object> object = *o;
  if (IsSmi(object)) return false;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
  Tagged<Map> map = heap_object->map();
  if (!InstanceTypeChecker::IsJSObject(map)) return false;
  if (!JSObject::IsDroppableApiObject(map)) return false;
  Tagged<Object> maybe_constructor = map->GetConstructor();
  if (!IsJSFunction(maybe_constructor)) return false;
  Tagged<JSObject> js_object = Cast<JSObject>(object);
  if (js_object->elements()->length() != 0) return false;
  // Check that the object is not a key in a WeakMap (over-approximation).
  if (!IsUndefined(js_object->GetIdentityHash())) return false;

  Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
  return constructor->initial_map() == map;
}

// static
void JSObject::UpdatePrototypeUserRegistration(DirectHandle<Map> old_map,
                                               DirectHandle<Map> new_map,
                                               Isolate* isolate) {
  DCHECK(old_map->is_prototype_map());
  DCHECK(new_map->is_prototype_map());
  bool was_registered = JSObject::UnregisterPrototypeUser(old_map, isolate);
  new_map->set_prototype_info(old_map->prototype_info(), kReleaseStore);
  old_map->set_prototype_info(Smi::zero(), kReleaseStore);
  if (v8_flags.trace_prototype_users) {
    PrintF("Moving prototype_info %p from map %p to map %p.\n",
           reinterpret_cast<void*>(new_map->prototype_info().ptr()),
           reinterpret_cast<void*>(old_map->ptr()),
           reinterpret_cast<void*>(new_map->ptr()));
  }
  if (was_registered) {
    if (new_map->has_prototype_info()) {
      // The new map isn't registered with its prototype yet; reflect this fact
      // in the PrototypeInfo it just inherited from the old map.
      Cast<PrototypeInfo>(new_map->prototype_info())
          ->set_registry_slot(MemoryChunk::UNREGISTERED);
    }
    JSObject::LazyRegisterPrototypeUser(new_map, isolate);
  }
}

// static
void JSObject::NotifyMapChange(DirectHandle<Map> old_map,
                               DirectHandle<Map> new_map, Isolate* isolate) {
  if (!old_map->is_prototype_map()) return;

  InvalidatePrototypeChains(*old_map);

  // If the map was registered with its prototype before, ensure that it
  // registers with its new prototype now. This preserves the invariant that
  // when a map on a prototype chain is registered with its prototype, then
  // all prototypes further up the chain are also registered with their
  // respective prototypes.
  UpdatePrototypeUserRegistration(old_map, new_map, isolate);
}

namespace {

// To migrate a fast instance to a fast map:
// - First check whether the instance needs to be rewritten. If not, simply
//   change the map.
// - Otherwise, allocate a fixed array large enough to hold all fields, in
//   addition to unused space.
// - Copy all existing properties in, in the following order: backing store
//   properties, unused fields, inobject properties.
// - If all allocation succeeded, commit the state atomically:
//   * Copy inobject properties from the backing store back into the object.
//   * Trim the difference in instance size of the object. This also cleanly
//     frees inobject properties that moved to the backing store.
//   * If there are properties left in the backing store, trim of the space used
//     to temporarily store the inobject properties.
//   * If there are properties left in the backing store, install the backing
//     store.
void MigrateFastToFast(Isolate* isolate, DirectHandle<JSObject> object,
                       DirectHandle<Map> new_map) {
  DirectHandle<Map> old_map(object->map(), isolate);
  // In case of a regular transition.
  if (new_map->GetBackPointer(isolate) == *old_map) {
    // If the map does not add named properties, simply set the map.
    if (old_map->NumberOfOwnDescriptors() ==
        new_map->NumberOfOwnDescriptors()) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // If the map adds a new kDescriptor property, simply set the map.
    PropertyDetails details = new_map->GetLastDescriptorDetails(isolate);
    if (details.location() == PropertyLocation::kDescriptor) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // Check if we still have space in the {object}, in which case we
    // can also simply set the map (modulo a special case for mutable
    // double boxes).
    FieldIndex index = FieldIndex::ForDetails(*new_map, details);
    if (index.is_inobject() || index.outobject_array_index() <
                                   object->property_array(isolate)->length()) {
      // Allocate HeapNumbers for double fields.
      if (index.is_double()) {
        auto value = isolate->factory()->NewHeapNumberWithHoleNaN();
        object->FastPropertyAtPut(index, *value);
      }
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // This migration is a transition from a map that has run out of property
    // space. Extend the backing store.
    int grow_by = new_map->UnusedPropertyFields() + 1;
    DirectHandle<PropertyArray> old_storage(object->property_array(isolate),
                                            isolate);
    DirectHandle<PropertyArray> new_storage =
        isolate->factory()->CopyPropertyArrayAndGrow(old_storage, grow_by);

    // Properly initialize newly added property.
    DirectHandle<Object> value;
    if (details.representation().IsDouble()) {
      value = isolate->factory()->NewHeapNumberWithHoleNaN();
    } else {
      value = isolate->factory()->uninitialized_value();
    }
    DCHECK_EQ(PropertyLocation::kField, details.location());
    DCHECK_EQ(PropertyKind::kData, details.kind());
    DCHECK(!index.is_inobject());  // Must be a backing store index.
    new_storage->set(index.outobject_array_index(), *value);

    // From here on we cannot fail and we shouldn't GC anymore.
    DisallowGarbageCollection no_gc;

    // Set the new property value and do the map transition.
    object->SetProperties(*new_storage);
    object->set_map(isolate, *new_map, kReleaseStore);
    return;
  }

  int
Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
e JS_GLOBAL_OBJECT_TYPE:
      return JSGlobalObject::kHeaderSize;
    case JS_BOUND_FUNCTION_TYPE:
      return JSBoundFunction::kHeaderSize;
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      return JSFunction::GetHeaderSize(function_has_prototype_slot);
    case JS_PRIMITIVE_WRAPPER_TYPE:
      return JSPrimitiveWrapper::kHeaderSize;
    case JS_DATE_TYPE:
      return JSDate::kHeaderSize;
    case JS_DISPOSABLE_STACK_BASE_TYPE:
      return JSDisposableStackBase::kHeaderSize;
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
      return JSAsyncDisposableStack::kHeaderSize;
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
      return JSSyncDisposableStack::kHeaderSize;
    case JS_ARRAY_TYPE:
      return JSArray::kHeaderSize;
    case JS_ARRAY_BUFFER_TYPE:
      return JSArrayBuffer::kHeaderSize;
    case JS_ARRAY_ITERATOR_TYPE:
      return JSArrayIterator::kHeaderSize;
    case JS_TYPED_ARRAY_TYPE:
      return JSTypedArray::kHeaderSize;
    case JS_DATA_VIEW_TYPE:
      return JSDataView::kHeaderSize;
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return JSRabGsabDataView::kHeaderSize;
    case JS_SET_TYPE:
      return JSSet::kHeaderSize;
    case JS_MAP_TYPE:
      return JSMap::kHeaderSize;
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      return JSSetIterator::kHeaderSize;
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
      return JSMapIterator::kHeaderSize;
    case JS_WEAK_REF_TYPE:
      return JSWeakRef::kHeaderSize;
    case JS_FINALIZATION_REGISTRY_TYPE:
      return JSFinalizationRegistry::kHeaderSize;
    case JS_WEAK_MAP_TYPE:
      return JSWeakMap::kHeaderSize;
    case JS_WEAK_SET_TYPE:
      return JSWeakSet::kHeaderSize;
    case JS_PROMISE_TYPE:
      return JSPromise::kHeaderSize;
    case JS_REG_EXP_TYPE:
      return JSRegExp::kHeaderSize;
    case JS_REG_EXP_STRING_ITERATOR_TYPE:
      return JSRegExpStringIterator::kHeaderSize;
    case JS_MESSAGE_OBJECT_TYPE:
      return JSMessageObject::kHeaderSize;
    case JS_EXTERNAL_OBJECT_TYPE:
      return JSExternalObject::kHeaderSize;
    case JS_SHADOW_REALM_TYPE:
      return JSShadowRealm::kHeaderSize;
    case JS_STRING_ITERATOR_TYPE:
      return JSStringIterator::kHeaderSize;
    case JS_ITERATOR_MAP_HELPER_TYPE:
      return JSIteratorMapHelper::kHeaderSize;
    case JS_ITERATOR_FILTER_HELPER_TYPE:
      return JSIteratorFilterHelper::kHeaderSize;
    case JS_ITERATOR_TAKE_HELPER_TYPE:
      return JSIteratorTakeHelper::kHeaderSize;
    case JS_ITERATOR_DROP_HELPER_TYPE:
      return JSIteratorDropHelper::kHeaderSize;
    case JS_ITERATOR_FLAT_MAP_HELPER_TYPE:
      return JSIteratorFlatMapHelper::kHeaderSize;
    case JS_MODULE_NAMESPACE_TYPE:
      return JSModuleNamespace::kHeaderSize;
    case JS_SHARED_ARRAY_TYPE:
      return JSSharedArray::kHeaderSize;
    case JS_SHARED_STRUCT_TYPE:
      return JSSharedStruct::kHeaderSize;
    case JS_ATOMICS_MUTEX_TYPE:
      return JSAtomicsMutex::kHeaderSize;
    case JS_ATOMICS_CONDITION_TYPE:
      return JSAtomicsCondition::kHeaderSize;
    case JS_TEMPORAL_CALENDAR_TYPE:
      return JSTemporalCalendar::kHeaderSize;
    case JS_TEMPORAL_DURATION_TYPE:
      return JSTemporalDuration::kHeaderSize;
    case JS_TEMPORAL_INSTANT_TYPE:
      return JSTemporalInstant::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
      return JSTemporalPlainDate::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
      return JSTemporalPlainDateTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
      return JSTemporalPlainMonthDay::kHeaderSize;
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
      return JSTemporalPlainTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
      return JSTemporalPlainYearMonth::kHeaderSize;
    case JS_TEMPORAL_TIME_ZONE_TYPE:
      return JSTemporalTimeZone::kHeaderSize;
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
      return JSTemporalZonedDateTime::kHeaderSize;
    case JS_VALID_ITERATOR_WRAPPER_TYPE:
      return JSValidIteratorWrapper::kHeaderSize;
    case JS_WRAPPED_FUNCTION_TYPE:
      return JSWrappedFunction::kHeaderSize;
    case JS_RAW_JSON_TYPE:
      return JSRawJson::kHeaderSize;
#ifdef V8_INTL_SUPPORT
    case JS_V8_BREAK_ITERATOR_TYPE:
      return JSV8BreakIterator::kHeaderSize;
    case JS_COLLATOR_TYPE:
      return JSCollator::kHeaderSize;
    case JS_DATE_TIME_FORMAT_TYPE:
      return JSDateTimeFormat::kHeaderSize;
    case JS_DISPLAY_NAMES_TYPE:
      return JSDisplayNames::kHeaderSize;
    case JS_DURATION_FORMAT_TYPE:
      return JSDurationFormat::kHeaderSize;
    case JS_LIST_FORMAT_TYPE:
      return JSListFormat::kHeaderSize;
    case JS_LOCALE_TYPE:
      return JSLocale::kHeaderSize;
    case JS_NUMBER_FORMAT_TYPE:
      return JSNumberFormat::kHeaderSize;
    case JS_PLURAL_RULES_TYPE:
      return JSPluralRules::kHeaderSize;
    case JS_RELATIVE_TIME_FORMAT_TYPE:
      return JSRelativeTimeFormat::kHeaderSize;
    case JS_SEGMENT_ITERATOR_TYPE:
      return JSSegmentIterator::kHeaderSize;
    case JS_SEGMENTER_TYPE:
      return JSSegmenter::kHeaderSize;
    case JS_SEGMENTS_TYPE:
      return JSSegments::kHeaderSize;
#endif  // V8_INTL_SUPPORT
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
      return WasmGlobalObject::kHeaderSize;
    case WASM_INSTANCE_OBJECT_TYPE:
      return WasmInstanceObject::kHeaderSize;
    case WASM_MEMORY_OBJECT_TYPE:
      return WasmMemoryObject::kHeaderSize;
    case WASM_MODULE_OBJECT_TYPE:
      return WasmModuleObject::kHeaderSize;
    case WASM_TABLE_OBJECT_TYPE:
      return WasmTableObject::kHeaderSize;
    case WASM_VALUE_OBJECT_TYPE:
      return WasmValueObject::kHeaderSize;
    case WASM_TAG_OBJECT_TYPE:
      return WasmTagObject::kHeaderSize;
    case WASM_EXCEPTION_PACKAGE_TYPE:
      return WasmExceptionPackage::kHeaderSize;
    case WASM_SUSPENDING_OBJECT_TYPE:
      return WasmSuspendingObject::kHeaderSize;
#endif  // V8_ENABLE_WEBASSEMBLY
    default: {
      // Special type check for API Objects because they are in a large variable
      // instance type range.
      if (InstanceTypeChecker::IsJSApiObject(type)) {
        return JSAPIObjectWithEmbedderSlots::BodyDescriptor::kHeaderSize;
      }
      FATAL("unexpected instance type: %s\n", NonAPIInstanceTypeToString(type));
    }
  }
}

MaybeHandle<JSAny> JSObject::GetPropertyWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Handle<JSAny> result;
    bool done;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        GetPropertyWithInterceptorInternal(it, interceptor, &done));
    if (done) return result;
  }

  // Cross-Origin [[Get]] of Well-Known Symbols does not throw, and returns
  // undefined.
  DirectHandle<Name> name = it->GetName();
  if (IsSymbol(*name) && Cast<Symbol>(*name)->is_well_known_symbol()) {
    return it->factory()->undefined_value();
  }

  RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(checked));
  UNREACHABLE();
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Maybe<PropertyAttributes> result =
        GetPropertyAttributesWithInterceptorInternal(it, interceptor);
    if (isolate->has_exception()) return Nothing<PropertyAttributes>();
    if (result.FromMaybe(ABSENT) != ABSENT) return result;
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<PropertyAttributes>());
  UNREACHABLE();
}

Maybe<bool> JSObject::SetPropertyWithFailedAccessCheck(
    LookupIterator* it, Handle<Object> value, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    InterceptorResult result;
    if (!SetPropertyWithInterceptorInternal(it, interceptor, should_throw,
                                            value)
             .To(&result)) {
      // An exception was thrown in the interceptor. Propagate.
      return Nothing<bool>();
    }
    switch (result) {
      case InterceptorResult::kFalse:
        return Just(false);
      case InterceptorResult::kTrue:
        return Just(true);
      case InterceptorResult::kNotIntercepted:
        // Fall through to report failed access check.
        break;
    }
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<bool>());
  UNREACHABLE();
}

void JSObject::SetNormalizedProperty(Handle<JSObject> object, Handle<Name> name,
                                     Handle<Object> value,
                                     PropertyDetails details) {
  DCHECK(!object->HasFastProperties());
  DCHECK(IsUniqueName(*name));
  Isolate* isolate = object->GetIsolate();

  uint32_t hash = name->hash();

  if (IsJSGlobalObject(*object)) {
    auto global_obj = Cast<JSGlobalObject>(object);
    Handle<GlobalDictionary> dictionary(
        global_obj->global_dictionary(kAcquireLoad), isolate);
    ReadOnlyRoots roots(isolate);
    InternalIndex entry = dictionary->FindEntry(isolate, roots, name, hash);

    if (entry.is_not_found()) {
      DCHECK_IMPLIES(global_obj->map()->is_prototype_map(),
                     Map::IsPrototypeChainInvalidated(global_obj->map()));
      auto cell_type = IsUndefined(*value, roots) ? PropertyCellType::kUndefined
                                                  : PropertyCellType::kConstant;
      details = details.set_cell_type(cell_type);
      auto cell = isolate->factory()->NewPropertyCell(name, details, value);
      dictionary =
          GlobalDictionary::Add(isolate, dictionary, name, cell, details);
      global_obj->set_global_dictionary(*dictionary, kReleaseStore);
    } else {
      PropertyCell::PrepareForAndSetValue(isolate, dictionary, entry, value,
                                          details);
      DCHECK_EQ(dictionary->CellAt(entry)->value(), *value);
    }
  } else {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          object->property_dictionary_swiss(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, *name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            SwissNameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        dictionary->ValueAtPut(entry, *value);
        dictionary->DetailsAtPut(entry, details);
      }
    } else {
      Handle<NameDictionary> dictionary(object->property_dictionary(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            NameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        PropertyDetails original_details = dictionary->DetailsAt(entry);
        int enumeration_index = original_details.dictionary_index();
        DCHECK_GT(enumeration_index, 0);
        details = details.set_index(enumeration_index);
        dictionary->SetEntry(entry, *name, *value, details);
      }
      // TODO(pthier): Add flags to swiss dictionaries.
      if (name->IsInteresting(isolate)) {
        dictionary->set_may_have_interesting_properties(true);
      }
    }
  }
}

void JSObject::SetNormalizedElement(Handle<JSObject> object, uint32_t index,
                                    Handle<Object> value,
                                    PropertyDetails details) {
  DCHECK_EQ(object->GetElementsKind(), DICTIONARY_ELEMENTS);

  Isolate* isolate = object->GetIsolate();

  Handle<NumberDictionary> dictionary =
      handle(Cast<NumberDictionary>(object->elements()), isolate);
  dictionary =
      NumberDictionary::Set(isolate, dictionary, index, value, object, details);
  object->set_elements(*dictionary);
}

void JSObject::JSObjectShortPrint(StringStream* accumulator) {
  switch (map()->instance_type()) {
    case JS_ARRAY_TYPE: {
      double length = IsUndefined(Cast<JSArray>(*this)->length())
                          ? 0
                          : Object::NumberValue(Cast<JSArray>(*this)->length());
      accumulator->Add("<JSArray[%u]>", static_cast<uint32_t>(length));
      break;
    }
    case JS_BOUND_FUNCTION_TYPE: {
      Tagged<JSBoundFunction> bound_function = Cast<JSBoundFunction>(*this);
      accumulator->Add("<JSBoundFunction");
      accumulator->Add(" (BoundTargetFunction %p)>",
                       reinterpret_cast<void*>(
                           bound_function->bound_target_function().ptr()));
      break;
    }
    case JS_WEAK_MAP_TYPE: {
      accumulator->Add("<JSWeakMap>");
      break;
    }
    case JS_WEAK_SET_TYPE: {
      accumulator->Add("<JSWeakSet>");
      break;
    }
    case JS_REG_EXP_TYPE: {
      accumulator->Add("<JSRegExp");
      Tagged<JSRegExp> regexp = Cast<JSRegExp>(*this);
      if (IsString(regexp->source())) {
        accumulator->Add(" ");
        Cast<String>(regexp->source())->StringShortPrint(accumulator);
      }
      accumulator->Add(">");

      break;
    }
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_FUNCTION_TYPE: {
      Tagged<JSFunction> function = Cast<JSFunction>(*this);
      std::unique_ptr<char[]> fun_name = function->shared()->DebugNameCStr();
      if (fun_name[0] != '\0') {
        accumulator->Add("<JSFunction ");
        accumulator->Add(fun_name.get());
      } else {
        accumulator->Add("<JSFunction");
      }
      if (v8_flags.trace_file_names) {
        Tagged<Object> source_name =
            Cast<Script>(function->shared()->script())->name();
        if (IsString(source_name)) {
          Tagged<String> str = Cast<String>(source_name);
          if (str->length() > 0) {
            accumulator->Add(" <");
            accumulator->Put(str);
            accumulator->Add(">");
          }
        }
      }
      accumulator->Add(" (sfi = %p)",
                       reinterpret_cast<void*>(function->shared().ptr()));
      accumulator->Put('>');
      break;
    }
    case JS_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JSGenerator>");
      break;
    }
    case JS_ASYNC_FUNCTION_OBJECT_TYPE: {
      accumulator->Add("<JSAsyncFunctionObject>");
      break;
    }
    case JS_ASYNC_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JS AsyncGenerator>");
      break;
    }
    case JS_SHARED_ARRAY_TYPE:
      accumulator->Add("<JSSharedArray>");
      break;
    case JS_SHARED_STRUCT_TYPE:
      accumulator->Add("<JSSharedStruct>");
      break;
    case JS_ATOMICS_MUTEX_TYPE:
      accumulator->Add("<JSAtomicsMutex>");
      break;
    case JS_ATOMICS_CONDITION_TYPE:
      accumulator->Add("<JSAtomicsCondition>");
      break;
    case JS_MESSAGE_OBJECT_TYPE:
      accumulator->Add("<JSMessageObject>");
      break;
    case JS_EXTERNAL_OBJECT_TYPE:
      accumulator->Add("<JSExternalObject>");
      break;

    default: {
      Tagged<Map> map_of_this = map();
      Tagged<Object> constructor = map_of_this->GetConstructor();
      bool printed = false;
      bool is_global_proxy = IsJSGlobalProxy(*this);
      if (IsJSFunction(constructor)) {
        Tagged<SharedFunctionInfo> sfi =
            Cast<JSFunction>(constructor)->shared();
        Tagged<String> constructor_name = sfi->Name();
        if (constructor_name->length() > 0) {
          accumulator->Add(is_global_proxy ? "<GlobalObject " : "<");
          accumulator->Put(constructor_name);
          accumulator->Add(" %smap = %p",
                           map_of_this->is_deprecated() ? "deprecated-" : "",
                           map_of_this);
          printed = true;
        }
      } else if (IsFunctionTemplateInfo(constructor)) {
        accumulator->Add("<RemoteObject>");
        printed = true;
      }
      if (!printed) {
        accumulator->Add("<JS");
        if (is_global_proxy) {
          accumulator->Add("GlobalProxy");
        } else if (IsJSGlobalObject(*this)) {
          accumulator->Add("GlobalObject");
        } else {
          accumulator->Add("Object");
        }
      }
      if (IsJSPrimitiveWrapper(*this)) {
        accumulator->Add(" value = ");
        ShortPrint(Cast<JSPrimitiveWrapper>(*this)->value(), accumulator);
      }
      accumulator->Put('>');
      break;
    }
  }
}

void JSObject::PrintElementsTransition(
    FILE* file, DirectHandle<JSObject> object, ElementsKind from_kind,
    DirectHandle<FixedArrayBase> from_elements, ElementsKind to_kind,
    DirectHandle<FixedArrayBase> to_elements) {
  if (from_kind != to_kind) {
    OFStream os(file);
    os << "elements transition [" << ElementsKindToString(from_kind) << " -> "
       << ElementsKindToString(to_kind) << "] in ";
    JavaScriptFrame::PrintTop(object->GetIsolate(), file, false, true);
    PrintF(file, " for ");
    ShortPrint(*object, file);
    PrintF(file, " from ");
    ShortPrint(*from_elements, file);
    PrintF(file, " to ");
    ShortPrint(*to_elements, file);
    PrintF(file, "\n");
  }
}

void JSObject::PrintInstanceMigration(FILE* file, Tagged<Map> original_map,
                                      Tagged<Map> new_map) {
  if (new_map->is_dictionary_map()) {
    PrintF(file, "[migrating to slow]\n");
    return;
  }
  PrintF(file, "[migrating]");
  Isolate* isolate = GetIsolate();
  Tagged<DescriptorArray> o = original_map->instance_descriptors(isolate);
  Tagged<DescriptorArray> n = new_map->instance_descriptors(isolate);
  for (InternalIndex i : original_map->IterateOwnDescriptors()) {
    Representation o_r = o->GetDetails(i).representation();
    Representation n_r = n->GetDetails(i).representation();
    if (!o_r.Equals(n_r)) {
      Cast<String>(o->GetKey(i))->PrintOn(file);
      PrintF(file, ":%s->%s ", o_r.Mnemonic(), n_r.Mnemonic());
    } else if (o->GetDetails(i).location() == PropertyLocation::kDescriptor &&
               n->GetDetails(i).location() == PropertyLocation::kField) {
      Tagged<Name> name = o->GetKey(i);
      if (IsString(name)) {
        Cast<String>(name)->PrintOn(file);
      } else {
        PrintF(file, "{symbol %p}", reinterpret_cast<void*>(name.ptr()));
      }
      PrintF(file, " ");
    }
  }
  if (original_map->elements_kind() != new_map->elements_kind()) {
    PrintF(file, "elements_kind[%i->%i]", original_map->elements_kind(),
           new_map->elements_kind());
  }
  PrintF(file, "\n");
}

// static
bool JSObject::IsUnmodifiedApiObject(FullObjectSlot o) {
  Tagged<Object> object = *o;
  if (IsSmi(object)) return false;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
  Tagged<Map> map = heap_object->map();
  if (!InstanceTypeChecker::IsJSObject(map)) return false;
  if (!JSObject::IsDroppableApiObject(map)) return false;
  Tagged<Object> maybe_constructor = map->GetConstructor();
  if (!IsJSFunction(maybe_constructor)) return false;
  Tagged<JSObject> js_object = Cast<JSObject>(object);
  if (js_object->elements()->length() != 0) return false;
  // Check that the object is not a key in a WeakMap (over-approximation).
  if (!IsUndefined(js_object->GetIdentityHash())) return false;

  Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
  return constructor->initial_map() == map;
}

// static
void JSObject::UpdatePrototypeUserRegistration(DirectHandle<Map> old_map,
                                               DirectHandle<Map> new_map,
                                               Isolate* isolate) {
  DCHECK(old_map->is_prototype_map());
  DCHECK(new_map->is_prototype_map());
  bool was_registered = JSObject::UnregisterPrototypeUser(old_map, isolate);
  new_map->set_prototype_info(old_map->prototype_info(), kReleaseStore);
  old_map->set_prototype_info(Smi::zero(), kReleaseStore);
  if (v8_flags.trace_prototype_users) {
    PrintF("Moving prototype_info %p from map %p to map %p.\n",
           reinterpret_cast<void*>(new_map->prototype_info().ptr()),
           reinterpret_cast<void*>(old_map->ptr()),
           reinterpret_cast<void*>(new_map->ptr()));
  }
  if (was_registered) {
    if (new_map->has_prototype_info()) {
      // The new map isn't registered with its prototype yet; reflect this fact
      // in the PrototypeInfo it just inherited from the old map.
      Cast<PrototypeInfo>(new_map->prototype_info())
          ->set_registry_slot(MemoryChunk::UNREGISTERED);
    }
    JSObject::LazyRegisterPrototypeUser(new_map, isolate);
  }
}

// static
void JSObject::NotifyMapChange(DirectHandle<Map> old_map,
                               DirectHandle<Map> new_map, Isolate* isolate) {
  if (!old_map->is_prototype_map()) return;

  InvalidatePrototypeChains(*old_map);

  // If the map was registered with its prototype before, ensure that it
  // registers with its new prototype now. This preserves the invariant that
  // when a map on a prototype chain is registered with its prototype, then
  // all prototypes further up the chain are also registered with their
  // respective prototypes.
  UpdatePrototypeUserRegistration(old_map, new_map, isolate);
}

namespace {

// To migrate a fast instance to a fast map:
// - First check whether the instance needs to be rewritten. If not, simply
//   change the map.
// - Otherwise, allocate a fixed array large enough to hold all fields, in
//   addition to unused space.
// - Copy all existing properties in, in the following order: backing store
//   properties, unused fields, inobject properties.
// - If all allocation succeeded, commit the state atomically:
//   * Copy inobject properties from the backing store back into the object.
//   * Trim the difference in instance size of the object. This also cleanly
//     frees inobject properties that moved to the backing store.
//   * If there are properties left in the backing store, trim of the space used
//     to temporarily store the inobject properties.
//   * If there are properties left in the backing store, install the backing
//     store.
void MigrateFastToFast(Isolate* isolate, DirectHandle<JSObject> object,
                       DirectHandle<Map> new_map) {
  DirectHandle<Map> old_map(object->map(), isolate);
  // In case of a regular transition.
  if (new_map->GetBackPointer(isolate) == *old_map) {
    // If the map does not add named properties, simply set the map.
    if (old_map->NumberOfOwnDescriptors() ==
        new_map->NumberOfOwnDescriptors()) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // If the map adds a new kDescriptor property, simply set the map.
    PropertyDetails details = new_map->GetLastDescriptorDetails(isolate);
    if (details.location() == PropertyLocation::kDescriptor) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // Check if we still have space in the {object}, in which case we
    // can also simply set the map (modulo a special case for mutable
    // double boxes).
    FieldIndex index = FieldIndex::ForDetails(*new_map, details);
    if (index.is_inobject() || index.outobject_array_index() <
                                   object->property_array(isolate)->length()) {
      // Allocate HeapNumbers for double fields.
      if (index.is_double()) {
        auto value = isolate->factory()->NewHeapNumberWithHoleNaN();
        object->FastPropertyAtPut(index, *value);
      }
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // This migration is a transition from a map that has run out of property
    // space. Extend the backing store.
    int grow_by = new_map->UnusedPropertyFields() + 1;
    DirectHandle<PropertyArray> old_storage(object->property_array(isolate),
                                            isolate);
    DirectHandle<PropertyArray> new_storage =
        isolate->factory()->CopyPropertyArrayAndGrow(old_storage, grow_by);

    // Properly initialize newly added property.
    DirectHandle<Object> value;
    if (details.representation().IsDouble()) {
      value = isolate->factory()->NewHeapNumberWithHoleNaN();
    } else {
      value = isolate->factory()->uninitialized_value();
    }
    DCHECK_EQ(PropertyLocation::kField, details.location());
    DCHECK_EQ(PropertyKind::kData, details.kind());
    DCHECK(!index.is_inobject());  // Must be a backing store index.
    new_storage->set(index.outobject_array_index(), *value);

    // From here on we cannot fail and we shouldn't GC anymore.
    DisallowGarbageCollection no_gc;

    // Set the new property value and do the map transition.
    object->SetProperties(*new_storage);
    object->set_map(isolate, *new_map, kReleaseStore);
    return;
  }

  int old_number_of_fields;
  int number_of_fields = new_map->NumberOfFields(ConcurrencyMode::kSynchronous);
  int inobject = new_map->GetInObjectProperties();
  int unused = new_map->UnusedPropertyFields();

  // Nothing to do if no functions were converted to fields and no smis were
  // converted to doubles.
  if (!old_map->InstancesNeedRewriting(*new_map, number_of_fields, inobject,
                                       unused, &old_number_of_fields,
                                       ConcurrencyMode::kSynchronous)) {
    object->set_map(isolate, *new_map, kReleaseStore);
    return;
  }

  int total_size = number_of_fields + unused;
  int external = total_size - inobject;
  DirectHandle<PropertyArray> array =
      isolate->factory()->NewPropertyArray(external);

  // We use this array to temporarily store the inobject properties.
  DirectHandle<FixedArray> inobject_props =
      isolate->factory()->NewFixedArray(inobject);

  DirectHandle<DescriptorArray> old_descriptors(
      old_map->instance_descriptors(isolate), isolate);
  DirectHandle<DescriptorArray> new_descriptors(
      new_map->instance_descriptors(isolate), isolate);
  int old_nof = old_map->NumberOfOwnDescriptors();
  int new_nof = new_map->NumberOfOwnDescriptors();

  // This method only supports generalizing instances to at least the same
  // number of properties.
  DCHECK(old_nof <= new_nof);

  for (InternalIndex i : InternalIndex::Range(old_nof)) {
    PropertyDetails details = new_descriptors->GetDetails(i);
    if (details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, details.kind());
    PropertyDetails old_details = old_descriptors->GetDetails(i);
    Representation old_representation = old_details.representation();
    Representation representation = details.representation();
    Handle<UnionOf<JSAny, Hole>> value;
    if (old_details.location() == PropertyLocation::kDescriptor) {
      if (old_details.kind() == PropertyKind::kAccessor) {
        // In case of kAccessor -> kData property reconfiguration, the property
        // must already be prepared for data of certain type.
        DCHECK(!details.representation().IsNone());
        if (details.representation().IsDouble()) {
          value = isolate->factory()->NewHeapNumberWithHoleNaN();
        } else {
          value = isolate->factory()->uninitialized_value();
        }
      } else {
        DCHECK_EQ(PropertyKind::kData, old_details.kind());
        value = handle(Cast<JSAny>(old_descriptors->GetStrongValue(isolate, i)),
                       isolate);
        DCHECK(!old_representation.IsDouble() && !representation.IsDouble());
      }
    } else {
      DCHECK_EQ(PropertyLocation::kField, old_details.location());
      FieldIndex index = FieldIndex::ForDetails(*old_map, old_details);
      value = handle(object->RawFastPropertyAt(isolate, index), isolate);
      if (!old_representation.IsDouble() && representation.IsDouble()) {
        DCHECK_IMPLIES(old_representation.IsNone(),
                       IsUninitialized(*value, isolate));
        value = Object::NewStorageFor(isolate, value, representation);
      } else if (old_representation.IsDouble() && !representation.IsDouble()) {
        value = Object::WrapForRead(isolate, Cast<JSAny>(value),
                                    old_representation);
      }
    }
    DCHECK(!(representation.IsDouble() && IsSmi(*value)));
    int target_index = new_descriptors->GetFieldIndex(i);
    if (target_index < inobject) {
      inobject_props->set(target_index, *value);
    } else {
      array->set(target_index - inobject, *value);
    }
  }

  for (InternalIndex i : InternalIndex::Range(old_nof, new_nof)) {
    PropertyDetails details = new_descriptors->GetDetails(i);
    if (details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, details.kind());
    DirectHandle<Object> value;
    if (details.representation().IsDouble()) {
      value = isolate->factory()->NewHeapNumberWithHoleNaN();
    } else {
      value = isolate->factory()->uninitialized_value();
    }
    int target_index = new_descriptors->GetFieldIndex(i);
    if (target_index < inobject) {
      inobject_props->set(target_index, *value);
    } else {
      array->set(target_index - inobject, *value);
    }
  }

  // From here on we cannot fail and we shouldn't GC anymore.
  DisallowGarbageCollection no_gc;

  Heap* heap = isolate->heap();

  // Copy (real) inobject properties. If necessary, stop at number_of_fields to
  // avoid overwriting |one_pointer_filler_map|.
  int limit = std::min(inobject, number_of_fields);
  for (int i = 0; i < limit; i++) {
    FieldIndex index = FieldIndex::ForPropertyIndex(*new_map, i);
    Tagged<Object> value = inobject_props->get(i);
    object->FastPropertyAtPut(index, value);
  }

  object->SetProperties(*array);

  // Create filler object past the new instance size.
  int old_instance_size = old_map->instance_size();
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
}

void MigrateFastToSlow(Isolate* isolate, DirectHandle<JSObject> object,
                       DirectHandle<Map> new_map,
                       int expected_additional_properties) {
  // The global object is always normalized.
  DCHECK(!IsJSGlobalObject(*object, isolate));
  // JSGlobalProxy must never be normalized
  DCHECK(!IsJSGlobalProxy(*object, isolate));

  DCHECK_IMPLIES(new_map->is_prototype_map(),
                 Map::IsPrototypeChainInvalidated(*new_map));

  HandleScope scope(isolate);
  DirectHandle<Map> map(object->map(isolate), isolate);

  // Allocate new content.
  int real_size = map->NumberOfOwnDescriptors();
  int property_count = real_size;
  if (expected_additional_properties > 0) {
    property_count += expected_additional_properties;
  } else {
    // Make space for two more properties.
    constexpr int initial_capacity = PropertyDictionary::kInitialCapacity;
    property_count += initial_capacity;
  }

  Handle<NameDictionary> dictionary;
  Handle<SwissNameDictionary> ord_dictionary;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    ord_dictionary = isolate->factory()->NewSwissNameDictionary(property_count);
  } else {
    dictionary = isolate->factory()->NewNameDictionary(
"""


```