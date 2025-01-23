Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `factory.cc` file in the V8 JavaScript engine. The focus should be on its role and any connection to JavaScript features, illustrated with JavaScript examples if applicable.

**Plan:**

1. **Identify the core responsibility:** The file seems to be responsible for creating and initializing various objects used within the V8 engine's heap. The "Factory" class strongly suggests this.
2. **Categorize the object creation functions:**  Look for patterns in the function names (e.g., `NewJSObject`, `NewJSArray`, `NewJSMap`) to understand the types of objects being created.
3. **Analyze the initialization steps:**  Observe how the factory functions set up the internal state of these objects (e.g., setting maps, elements, properties).
4. **Identify connections to JavaScript concepts:**  Relate the created object types to corresponding JavaScript language features (e.g., `JSArray` to JavaScript arrays, `JSMap` to JavaScript `Map` objects).
5. **Provide JavaScript examples:**  Illustrate how these factory-created objects are represented and used in JavaScript code.
6. **Consider the "Part 3 of 4" aspect:**  Acknowledge that this is only a portion of the file and the summary reflects that.

**High-level categorization of functions observed:**

* **Basic Objects:** `NewJSObjectFromMap`, `NewSlowJSObjectFromMap`, `NewSlowJSObjectWithPropertiesAndElements`
* **Arrays:** `NewJSArray`, `NewJSArrayWithElements`, `NewJSArrayStorage`
* **Collections:** `NewJSWeakMap`, `NewJSMap`, `NewJSSet`
* **Modules:** `NewJSModuleNamespace`, `NewSourceTextModule`, `NewSyntheticModule`
* **Buffers:** `NewJSArrayBuffer`, `NewJSSharedArrayBuffer`
* **Iterators:** `NewJSIteratorResult`, `NewJSAsyncFromSyncIterator`
* **Functions and Proxies:** `NewJSWrappedFunction`, `NewJSGeneratorObject`, `NewJSBoundFunction`, `NewJSProxy`
* **Globals:** `NewUninitializedJSGlobalProxy`, `ReinitializeJSGlobalProxy`
* **Error Handling:** `NewJSMessageObject`
* **Function Information:** `NewSharedFunctionInfoForApiFunction`, `NewSharedFunctionInfoForBuiltin`, `NewInterpreterData`
* **Debugging:** `NewDebugInfo`, `NewBreakPointInfo`, `NewBreakPoint`, `NewCallSiteInfo`, `NewStackFrameInfo`, `NewStackTraceInfo`
* **Arguments Object:** `NewArgumentsObject`
* **Templates:** `NewFunctionTemplateInfo`, `NewObjectTemplateInfo`, `NewDictionaryTemplateInfo`
* **Typed Arrays and Data Views:** `NewJSArrayBufferView`, `NewJSTypedArray`, `NewJSDataViewOrRabGsabDataView`
* **Promises:** `NewJSPromise`, `NewJSPromiseWithoutHook`
* **Shared Objects:** `NewJSSharedStruct`, `NewJSSharedArray`, `NewJSAtomicsMutex`, `NewJSAtomicsCondition`
* **Internal Utilities:** `SizeToString`, `GlobalConstantFor`, `ToPrimitiveHintString`, helper functions for map creation, etc.
* **Regular Expressions:** `SetRegExpAtomData`, `SetRegExpIrregexpData`, `SetRegExpExperimentalData`, `NewAtomRegExpData`, `NewIrRegExpData`, `NewExperimentalRegExpData`

This categorization helps to structure the summary.
这是 `v8/src/heap/factory.cc` 文件的一部分，主要负责创建和初始化 V8 堆中各种 JavaScript 对象和其他内部对象。可以将其视为 V8 引擎的“对象工厂”，提供了一系列静态方法来实例化不同类型的对象。

**主要功能归纳：**

* **对象创建:**  提供了大量 `New...` 开头的方法，用于创建不同类型的 JavaScript 对象，例如：
    * 基础对象 (`JSObject`)
    * 数组 (`JSArray`)
    * Map 和 WeakMap (`JSMap`, `JSWeakMap`)
    * Set (`JSSet`)
    * 模块相关的对象 (`JSModuleNamespace`, `SourceTextModule`, `SyntheticModule`)
    * 缓冲区 (`JSArrayBuffer`, `JSSharedArrayBuffer`)
    * 迭代器结果 (`JSIteratorResult`)
    * 函数相关对象 (`JSWrappedFunction`, `JSGeneratorObject`, `JSBoundFunction`)
    * Proxy 对象 (`JSProxy`)
    * 全局对象代理 (`JSGlobalProxy`)
    * 错误消息对象 (`JSMessageObject`)
    * 类型化数组和 DataView (`JSTypedArray`, `JSDataViewOrRabGsabDataView`)
    * Promise (`JSPromise`)
    * 共享对象 (`JSSharedStruct`, `JSSharedArray`, `JSAtomicsMutex`, `JSAtomicsCondition`)
    * 模板对象 (`FunctionTemplateInfo`, `ObjectTemplateInfo`, `DictionaryTemplateInfo`)
    * 正则表达式相关对象 (`JSRegExp`, `RegExpData`)
    * 以及其他内部使用的对象，如 `DebugInfo`, `BreakPointInfo`, `CallSiteInfo`, `StackFrameInfo`, `InterpreterData` 等。

* **对象初始化:** 在创建对象的同时，这些工厂方法还会负责对象的初始化工作，例如设置对象的 `Map` (描述对象结构和类型的元数据), 初始化属性和元素, 设置内部槽位的值等。

* **优化对象创建:** 某些工厂方法会尝试优化对象的创建过程，例如 `NewSlowJSObjectFromMap` 用于创建属性存储在字典中的“慢对象”，`ObjectLiteralMapFromCache` 用于缓存对象字面量的 Map，从而加速相同结构对象的创建。

* **与垃圾回收的交互:**  在对象创建过程中，会使用 `AllocationType` 来指定对象应该分配在新生代还是老生代，并使用 `DisallowGarbageCollection` 来防止在关键的初始化阶段发生垃圾回收。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`Factory` 类创建的对象是 V8 引擎内部表示 JavaScript 值的核心。我们通常在 JavaScript 代码中使用的各种对象，最终都由 `Factory` 类的方法创建出来。

**示例 1: 创建一个普通对象**

```javascript
// JavaScript 代码
const obj = {};
```

在 V8 内部，当执行 `const obj = {};` 时，`Factory::NewJSObjectFromMap` (或者类似的函数) 会被调用来创建一个 `JSObject` 实例。这个函数会根据当前的上下文和对象的属性数量，选择合适的 `Map` 来初始化这个对象。

**示例 2: 创建一个数组**

```javascript
// JavaScript 代码
const arr = [1, 2, 3];
```

当执行这段代码时，`Factory::NewJSArray` 或 `Factory::NewJSArrayWithElements` 会被调用。这些函数会创建 `JSArray` 对象，并分配存储数组元素的内存 (`FixedArray`)，并将 JavaScript 的值 (1, 2, 3) 写入到这个内存中。

**示例 3: 创建一个 Map 对象**

```javascript
// JavaScript 代码
const map = new Map();
map.set('key', 'value');
```

执行 `new Map()` 时，`Factory::NewJSMap` 会被调用，创建一个 `JSMap` 对象。这个对象内部会维护一个哈希表或者类似的结构来存储键值对。

**示例 4: 创建一个 Promise 对象**

```javascript
// JavaScript 代码
const promise = new Promise((resolve, reject) => {
  // ...
});
```

执行 `new Promise()` 时，`Factory::NewJSPromise` 会被调用，创建一个 `JSPromise` 对象。这个对象会保存 Promise 的状态和结果。

**总结 (针对第 3 部分):**

作为 `v8/src/heap/factory.cc` 的一部分，这段代码集中展示了 `Factory` 类创建各种 JavaScript 对象和相关内部对象的能力。它涵盖了创建普通对象、数组、集合类型、模块、缓冲区、函数、Proxy、全局对象代理、错误对象、类型化数组、Promise 和共享对象等功能。这些都是构成 JavaScript 语言基础的核心组成部分，这段代码是 V8 引擎实现这些功能的重要基础。 考虑到这是第 3 部分，可以推断前后的部分可能涉及更基础的对象创建机制 (例如，分配内存和创建 `Map` 对象) 以及一些更高级的对象创建或优化策略。

### 提示词
```
这是目录为v8/src/heap/factory.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
HasDictionaryElements() || js_obj->HasSharedArrayElements());
  return handle(js_obj, isolate());
}

Handle<JSObject> Factory::NewSlowJSObjectFromMap(
    DirectHandle<Map> map, int capacity, AllocationType allocation,
    DirectHandle<AllocationSite> allocation_site,
    NewJSObjectType new_js_object_type) {
  DCHECK(map->is_dictionary_map());
  DirectHandle<HeapObject> object_properties;
  if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    object_properties = NewSwissNameDictionary(capacity, allocation);
  } else {
    object_properties = NameDictionary::New(isolate(), capacity);
  }
  Handle<JSObject> js_object =
      NewJSObjectFromMap(map, allocation, allocation_site, new_js_object_type);
  js_object->set_raw_properties_or_hash(*object_properties, kRelaxedStore);
  return js_object;
}

Handle<JSObject> Factory::NewSlowJSObjectFromMap(DirectHandle<Map> map) {
  return NewSlowJSObjectFromMap(map, PropertyDictionary::kInitialCapacity);
}

Handle<JSObject> Factory::NewSlowJSObjectWithPropertiesAndElements(
    Handle<JSPrototype> prototype, DirectHandle<HeapObject> properties,
    DirectHandle<FixedArrayBase> elements) {
  DCHECK(IsPropertyDictionary(*properties));

  Handle<Map> object_map = isolate()->slow_object_with_object_prototype_map();
  if (object_map->prototype() != *prototype) {
    object_map = Map::TransitionRootMapToPrototypeForNewObject(
        isolate(), object_map, prototype);
  }
  DCHECK(object_map->is_dictionary_map());
  Handle<JSObject> object =
      NewJSObjectFromMap(object_map, AllocationType::kYoung);
  object->set_raw_properties_or_hash(*properties);
  if (*elements != read_only_roots().empty_fixed_array()) {
    DCHECK(IsNumberDictionary(*elements));
    object_map =
        JSObject::GetElementsTransitionMap(object, DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate(), object, object_map);
    object->set_elements(*elements);
  }
  return object;
}

Handle<JSArray> Factory::NewJSArray(ElementsKind elements_kind, int length,
                                    int capacity,
                                    ArrayStorageAllocationMode mode,
                                    AllocationType allocation) {
  DCHECK(capacity >= length);
  if (capacity == 0) {
    return NewJSArrayWithElements(empty_fixed_array(), elements_kind, length,
                                  allocation);
  }

  HandleScope inner_scope(isolate());
  DirectHandle<FixedArrayBase> elms =
      NewJSArrayStorage(elements_kind, capacity, mode);
  return inner_scope.CloseAndEscape(NewJSArrayWithUnverifiedElements(
      elms, elements_kind, length, allocation));
}

Handle<JSArray> Factory::NewJSArrayWithElements(
    DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
    int length, AllocationType allocation) {
  Handle<JSArray> array = NewJSArrayWithUnverifiedElements(
      elements, elements_kind, length, allocation);
#ifdef ENABLE_SLOW_DCHECKS
  JSObject::ValidateElements(*array);
#endif
  return array;
}

Handle<JSArray> Factory::NewJSArrayWithUnverifiedElements(
    DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
    int length, AllocationType allocation) {
  DCHECK(length <= elements->length());
  Tagged<NativeContext> native_context = isolate()->raw_native_context();
  Tagged<Map> map = native_context->GetInitialJSArrayMap(elements_kind);
  if (map.is_null()) {
    Tagged<JSFunction> array_function = native_context->array_function();
    map = array_function->initial_map();
  }
  return NewJSArrayWithUnverifiedElements(handle(map, isolate()), elements,
                                          length, allocation);
}

Handle<JSArray> Factory::NewJSArrayWithUnverifiedElements(
    DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements, int length,
    AllocationType allocation) {
  auto array = Cast<JSArray>(NewJSObjectFromMap(map, allocation));
  DisallowGarbageCollection no_gc;
  Tagged<JSArray> raw = *array;
  raw->set_elements(*elements);
  raw->set_length(Smi::FromInt(length));
  return array;
}

Handle<JSArray> Factory::NewJSArrayForTemplateLiteralArray(
    DirectHandle<FixedArray> cooked_strings,
    DirectHandle<FixedArray> raw_strings, int function_literal_id,
    int slot_id) {
  Handle<JSArray> raw_object =
      NewJSArrayWithElements(raw_strings, PACKED_ELEMENTS,
                             raw_strings->length(), AllocationType::kOld);
  JSObject::SetIntegrityLevel(isolate(), raw_object, FROZEN, kThrowOnError)
      .ToChecked();

  DirectHandle<NativeContext> native_context = isolate()->native_context();
  auto template_object =
      Cast<TemplateLiteralObject>(NewJSArrayWithUnverifiedElements(
          handle(native_context->js_array_template_literal_object_map(),
                 isolate()),
          cooked_strings, cooked_strings->length(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  Tagged<TemplateLiteralObject> raw_template_object = *template_object;
  DCHECK_EQ(raw_template_object->map(),
            native_context->js_array_template_literal_object_map());
  raw_template_object->set_raw(*raw_object);
  raw_template_object->set_function_literal_id(function_literal_id);
  raw_template_object->set_slot_id(slot_id);
  return template_object;
}

void Factory::NewJSArrayStorage(DirectHandle<JSArray> array, int length,
                                int capacity, ArrayStorageAllocationMode mode) {
  DCHECK(capacity >= length);

  if (capacity == 0) {
    Tagged<JSArray> raw = *array;
    DisallowGarbageCollection no_gc;
    raw->set_length(Smi::zero());
    raw->set_elements(*empty_fixed_array());
    return;
  }

  HandleScope inner_scope(isolate());
  DirectHandle<FixedArrayBase> elms =
      NewJSArrayStorage(array->GetElementsKind(), capacity, mode);
  DisallowGarbageCollection no_gc;
  Tagged<JSArray> raw = *array;
  raw->set_elements(*elms);
  raw->set_length(Smi::FromInt(length));
}

Handle<FixedArrayBase> Factory::NewJSArrayStorage(
    ElementsKind elements_kind, int capacity, ArrayStorageAllocationMode mode) {
  DCHECK_GT(capacity, 0);
  Handle<FixedArrayBase> elms;
  if (IsDoubleElementsKind(elements_kind)) {
    if (mode == ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS) {
      elms = NewFixedDoubleArray(capacity);
    } else {
      DCHECK_EQ(
          mode,
          ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
      elms = NewFixedDoubleArrayWithHoles(capacity);
    }
  } else {
    DCHECK(IsSmiOrObjectElementsKind(elements_kind));
    if (mode == ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS) {
      elms = NewFixedArray(capacity);
    } else {
      DCHECK_EQ(
          mode,
          ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
      elms = NewFixedArrayWithHoles(capacity);
    }
  }
  return elms;
}

Handle<JSWeakMap> Factory::NewJSWeakMap() {
  Tagged<NativeContext> native_context = isolate()->raw_native_context();
  DirectHandle<Map> map(native_context->js_weak_map_fun()->initial_map(),
                        isolate());
  Handle<JSWeakMap> weakmap(Cast<JSWeakMap>(*NewJSObjectFromMap(map)),
                            isolate());
  {
    // Do not leak handles for the hash table, it would make entries strong.
    HandleScope scope(isolate());
    JSWeakCollection::Initialize(weakmap, isolate());
  }
  return weakmap;
}

Handle<JSModuleNamespace> Factory::NewJSModuleNamespace() {
  DirectHandle<Map> map = isolate()->js_module_namespace_map();
  Handle<JSModuleNamespace> module_namespace(
      Cast<JSModuleNamespace>(NewJSObjectFromMap(
          map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
          NewJSObjectType::kAPIWrapper)));
  FieldIndex index = FieldIndex::ForDescriptor(
      *map, InternalIndex(JSModuleNamespace::kToStringTagFieldIndex));
  module_namespace->FastPropertyAtPut(index, read_only_roots().Module_string(),
                                      SKIP_WRITE_BARRIER);
  return module_namespace;
}

Handle<JSWrappedFunction> Factory::NewJSWrappedFunction(
    DirectHandle<NativeContext> creation_context, DirectHandle<Object> target) {
  DCHECK(IsCallable(*target));
  DirectHandle<Map> map(
      Cast<Map>(creation_context->get(Context::WRAPPED_FUNCTION_MAP_INDEX)),
      isolate());
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function->prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  Handle<JSWrappedFunction> wrapped =
      Cast<JSWrappedFunction>(isolate()->factory()->NewJSObjectFromMap(map));
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  wrapped->set_wrapped_target_function(Cast<JSCallable>(*target));
  // 6. Set wrapped.[[Realm]] to callerRealm.
  wrapped->set_context(*creation_context);
  // TODO(v8:11989): https://github.com/tc39/proposal-shadowrealm/pull/348

  return wrapped;
}

Handle<JSGeneratorObject> Factory::NewJSGeneratorObject(
    Handle<JSFunction> function) {
  DCHECK(IsResumableFunction(function->shared()->kind()));
  JSFunction::EnsureHasInitialMap(function);
  DirectHandle<Map> map(function->initial_map(), isolate());

  DCHECK(map->instance_type() == JS_GENERATOR_OBJECT_TYPE ||
         map->instance_type() == JS_ASYNC_GENERATOR_OBJECT_TYPE);

  return Cast<JSGeneratorObject>(NewJSObjectFromMap(map));
}

Handle<JSDisposableStackBase> Factory::NewJSDisposableStackBase() {
  DirectHandle<NativeContext> native_context = isolate()->native_context();
  DirectHandle<Map> map(native_context->js_disposable_stack_map(), isolate());
  Handle<JSDisposableStackBase> disposable_stack(
      Cast<JSDisposableStackBase>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<JSSyncDisposableStack> Factory::NewJSSyncDisposableStack(
    DirectHandle<Map> map) {
  Handle<JSSyncDisposableStack> disposable_stack(
      Cast<JSSyncDisposableStack>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<JSAsyncDisposableStack> Factory::NewJSAsyncDisposableStack(
    DirectHandle<Map> map) {
  Handle<JSAsyncDisposableStack> disposable_stack(
      Cast<JSAsyncDisposableStack>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<SourceTextModule> Factory::NewSourceTextModule(
    DirectHandle<SharedFunctionInfo> sfi) {
  DirectHandle<SourceTextModuleInfo> module_info(
      sfi->scope_info()->ModuleDescriptorInfo(), isolate());
  DirectHandle<ObjectHashTable> exports =
      ObjectHashTable::New(isolate(), module_info->RegularExportCount());
  DirectHandle<FixedArray> regular_exports =
      NewFixedArray(module_info->RegularExportCount());
  DirectHandle<FixedArray> regular_imports =
      NewFixedArray(module_info->regular_imports()->length());
  int requested_modules_length = module_info->module_requests()->length();
  DirectHandle<FixedArray> requested_modules =
      requested_modules_length > 0 ? NewFixedArray(requested_modules_length)
                                   : empty_fixed_array();

  ReadOnlyRoots roots(isolate());
  Tagged<SourceTextModule> module = Cast<SourceTextModule>(
      New(source_text_module_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  module->set_code(*sfi);
  module->set_exports(*exports);
  module->set_regular_exports(*regular_exports);
  module->set_regular_imports(*regular_imports);
  module->set_hash(isolate()->GenerateIdentityHash(Smi::kMaxValue));
  module->set_module_namespace(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_requested_modules(*requested_modules);
  module->set_status(Module::kUnlinked);
  module->set_exception(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_top_level_capability(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_import_meta(roots.the_hole_value(), kReleaseStore,
                          SKIP_WRITE_BARRIER);
  module->set_dfs_index(-1);
  module->set_dfs_ancestor_index(-1);
  module->set_flags(0);
  module->set_has_toplevel_await(IsModuleWithTopLevelAwait(sfi->kind()));
  module->set_async_evaluation_ordinal(SourceTextModule::kNotAsyncEvaluated);
  module->set_cycle_root(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_async_parent_modules(roots.empty_array_list());
  module->set_pending_async_dependencies(0);
  return handle(module, isolate());
}

Handle<SyntheticModule> Factory::NewSyntheticModule(
    DirectHandle<String> module_name, DirectHandle<FixedArray> export_names,
    v8::Module::SyntheticModuleEvaluationSteps evaluation_steps) {
  ReadOnlyRoots roots(isolate());

  DirectHandle<ObjectHashTable> exports =
      ObjectHashTable::New(isolate(), static_cast<int>(export_names->length()));
  DirectHandle<Foreign> evaluation_steps_foreign =
      NewForeign<kSyntheticModuleTag>(
          reinterpret_cast<Address>(evaluation_steps));

  Tagged<SyntheticModule> module =
      Cast<SyntheticModule>(New(synthetic_module_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  module->set_hash(isolate()->GenerateIdentityHash(Smi::kMaxValue));
  module->set_module_namespace(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_status(Module::kUnlinked);
  module->set_exception(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_top_level_capability(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_name(*module_name);
  module->set_export_names(*export_names);
  module->set_exports(*exports);
  module->set_evaluation_steps(*evaluation_steps_foreign);
  return handle(module, isolate());
}

Handle<JSArrayBuffer> Factory::NewJSArrayBuffer(
    std::shared_ptr<BackingStore> backing_store, AllocationType allocation) {
  DirectHandle<Map> map(
      isolate()->native_context()->array_buffer_fun()->initial_map(),
      isolate());
  ResizableFlag resizable_by_js = ResizableFlag::kNotResizable;
  if (backing_store->is_resizable_by_js()) {
    resizable_by_js = ResizableFlag::kResizable;
  }
  auto result = Cast<JSArrayBuffer>(
      NewJSObjectFromMap(map, allocation, DirectHandle<AllocationSite>::null(),
                         NewJSObjectType::kAPIWrapper));
  result->Setup(SharedFlag::kNotShared, resizable_by_js,
                std::move(backing_store), isolate());
  return result;
}

MaybeHandle<JSArrayBuffer> Factory::NewJSArrayBufferAndBackingStore(
    size_t byte_length, InitializedFlag initialized,
    AllocationType allocation) {
  return NewJSArrayBufferAndBackingStore(byte_length, byte_length, initialized,
                                         ResizableFlag::kNotResizable,
                                         allocation);
}

MaybeHandle<JSArrayBuffer> Factory::NewJSArrayBufferAndBackingStore(
    size_t byte_length, size_t max_byte_length, InitializedFlag initialized,
    ResizableFlag resizable, AllocationType allocation) {
  DCHECK_LE(byte_length, max_byte_length);
  std::unique_ptr<BackingStore> backing_store = nullptr;

  if (resizable == ResizableFlag::kResizable) {
    size_t page_size, initial_pages, max_pages;
    if (JSArrayBuffer::GetResizableBackingStorePageConfiguration(
            isolate(), byte_length, max_byte_length, kDontThrow, &page_size,
            &initial_pages, &max_pages)
            .IsNothing()) {
      return MaybeHandle<JSArrayBuffer>();
    }

    backing_store = BackingStore::TryAllocateAndPartiallyCommitMemory(
        isolate(), byte_length, max_byte_length, page_size, initial_pages,
        max_pages, WasmMemoryFlag::kNotWasm, SharedFlag::kNotShared);
    if (!backing_store) return MaybeHandle<JSArrayBuffer>();
  } else {
    if (byte_length > 0) {
      backing_store = BackingStore::Allocate(
          isolate(), byte_length, SharedFlag::kNotShared, initialized);
      if (!backing_store) return MaybeHandle<JSArrayBuffer>();
    }
  }
  DirectHandle<Map> map(
      isolate()->native_context()->array_buffer_fun()->initial_map(),
      isolate());
  auto array_buffer = Cast<JSArrayBuffer>(
      NewJSObjectFromMap(map, allocation, DirectHandle<AllocationSite>::null(),
                         NewJSObjectType::kAPIWrapper));
  array_buffer->Setup(SharedFlag::kNotShared, resizable,
                      std::move(backing_store), isolate());
  return array_buffer;
}

Handle<JSArrayBuffer> Factory::NewJSSharedArrayBuffer(
    std::shared_ptr<BackingStore> backing_store) {
  DirectHandle<Map> map(
      isolate()->native_context()->shared_array_buffer_fun()->initial_map(),
      isolate());
  auto result = Cast<JSArrayBuffer>(NewJSObjectFromMap(
      map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
      NewJSObjectType::kAPIWrapper));
  ResizableFlag resizable = backing_store->is_resizable_by_js()
                                ? ResizableFlag::kResizable
                                : ResizableFlag::kNotResizable;
  result->Setup(SharedFlag::kShared, resizable, std::move(backing_store),
                isolate());
  return result;
}

Handle<JSIteratorResult> Factory::NewJSIteratorResult(
    DirectHandle<Object> value, bool done) {
  DirectHandle<Map> map(isolate()->native_context()->iterator_result_map(),
                        isolate());
  Handle<JSIteratorResult> js_iter_result =
      Cast<JSIteratorResult>(NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSIteratorResult> raw = *js_iter_result;
  raw->set_value(*value, SKIP_WRITE_BARRIER);
  raw->set_done(*ToBoolean(done), SKIP_WRITE_BARRIER);
  return js_iter_result;
}

Handle<JSAsyncFromSyncIterator> Factory::NewJSAsyncFromSyncIterator(
    DirectHandle<JSReceiver> sync_iterator, DirectHandle<Object> next) {
  DirectHandle<Map> map(
      isolate()->native_context()->async_from_sync_iterator_map(), isolate());
  Handle<JSAsyncFromSyncIterator> iterator = Cast<JSAsyncFromSyncIterator>(
      NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSAsyncFromSyncIterator> raw = *iterator;
  raw->set_sync_iterator(*sync_iterator, SKIP_WRITE_BARRIER);
  raw->set_next(*next, SKIP_WRITE_BARRIER);
  return iterator;
}

Handle<JSMap> Factory::NewJSMap() {
  DirectHandle<Map> map(isolate()->native_context()->js_map_map(), isolate());
  Handle<JSMap> js_map = Cast<JSMap>(NewJSObjectFromMap(map));
  JSMap::Initialize(js_map, isolate());
  return js_map;
}

Handle<JSSet> Factory::NewJSSet() {
  DirectHandle<Map> map(isolate()->native_context()->js_set_map(), isolate());
  Handle<JSSet> js_set = Cast<JSSet>(NewJSObjectFromMap(map));
  JSSet::Initialize(js_set, isolate());
  return js_set;
}

void Factory::TypeAndSizeForElementsKind(ElementsKind kind,
                                         ExternalArrayType* array_type,
                                         size_t* element_size) {
  switch (kind) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                           \
    *array_type = kExternal##Type##Array;         \
    *element_size = sizeof(ctype);                \
    break;
    TYPED_ARRAYS(TYPED_ARRAY_CASE)
    RAB_GSAB_TYPED_ARRAYS_WITH_TYPED_ARRAY_TYPE(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

    default:
      UNREACHABLE();
  }
}

Handle<JSArrayBufferView> Factory::NewJSArrayBufferView(
    DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements,
    DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
    size_t byte_length) {
  if (!IsRabGsabTypedArrayElementsKind(map->elements_kind())) {
    CHECK_LE(byte_length, buffer->GetByteLength());
    CHECK_LE(byte_offset, buffer->GetByteLength());
    CHECK_LE(byte_offset + byte_length, buffer->GetByteLength());
  }

  Handle<JSArrayBufferView> array_buffer_view =
      Cast<JSArrayBufferView>(NewJSObjectFromMap(
          map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
          NewJSObjectType::kAPIWrapper));
  DisallowGarbageCollection no_gc;
  Tagged<JSArrayBufferView> raw = *array_buffer_view;
  raw->set_elements(*elements, SKIP_WRITE_BARRIER);
  raw->set_buffer(*buffer, SKIP_WRITE_BARRIER);
  raw->set_byte_offset(byte_offset);
  raw->set_byte_length(byte_length);
  raw->set_bit_field(0);
  // TODO(v8) remove once embedder data slots are always zero-initialized.
  InitEmbedderFields(raw, Smi::zero());
  DCHECK_EQ(raw->GetEmbedderFieldCount(),
            v8::ArrayBufferView::kEmbedderFieldCount);
  return array_buffer_view;
}

Handle<JSTypedArray> Factory::NewJSTypedArray(
    ExternalArrayType type, DirectHandle<JSArrayBuffer> buffer,
    size_t byte_offset, size_t length, bool is_length_tracking) {
  size_t element_size;
  ElementsKind elements_kind;
  JSTypedArray::ForFixedTypedArray(type, &element_size, &elements_kind);

  const bool is_backed_by_rab =
      buffer->is_resizable_by_js() && !buffer->is_shared();

  DirectHandle<Map> map;
  if (is_backed_by_rab || is_length_tracking) {
    map = direct_handle(
        isolate()->raw_native_context()->TypedArrayElementsKindToRabGsabCtorMap(
            elements_kind),
        isolate());
  } else {
    map = direct_handle(
        isolate()->raw_native_context()->TypedArrayElementsKindToCtorMap(
            elements_kind),
        isolate());
  }

  if (is_length_tracking) {
    // Security: enforce the invariant that length-tracking TypedArrays have
    // their length and byte_length set to 0.
    length = 0;
  }

  CHECK_LE(length, JSTypedArray::kMaxByteLength / element_size);
  CHECK_EQ(0, byte_offset % element_size);
  size_t byte_length = length * element_size;

  Handle<JSTypedArray> typed_array = Cast<JSTypedArray>(NewJSArrayBufferView(
      map, empty_byte_array(), buffer, byte_offset, byte_length));
  Tagged<JSTypedArray> raw = *typed_array;
  DisallowGarbageCollection no_gc;
  raw->set_length(length);
  raw->SetOffHeapDataPtr(isolate(), buffer->backing_store(), byte_offset);
  raw->set_is_length_tracking(is_length_tracking);
  raw->set_is_backed_by_rab(is_backed_by_rab);
  return typed_array;
}

Handle<JSDataViewOrRabGsabDataView> Factory::NewJSDataViewOrRabGsabDataView(
    DirectHandle<JSArrayBuffer> buffer, size_t byte_offset, size_t byte_length,
    bool is_length_tracking) {
  if (is_length_tracking) {
    // Security: enforce the invariant that length-tracking DataViews have their
    // byte_length set to 0.
    byte_length = 0;
  }
  bool is_backed_by_rab = !buffer->is_shared() && buffer->is_resizable_by_js();
  DirectHandle<Map> map;
  if (is_backed_by_rab || is_length_tracking) {
    map = direct_handle(
        isolate()->native_context()->js_rab_gsab_data_view_map(), isolate());
  } else {
    map = direct_handle(
        isolate()->native_context()->data_view_fun()->initial_map(), isolate());
  }
  Handle<JSDataViewOrRabGsabDataView> obj =
      Cast<JSDataViewOrRabGsabDataView>(NewJSArrayBufferView(
          map, empty_fixed_array(), buffer, byte_offset, byte_length));
  obj->set_data_pointer(
      isolate(), static_cast<uint8_t*>(buffer->backing_store()) + byte_offset);
  obj->set_is_length_tracking(is_length_tracking);
  obj->set_is_backed_by_rab(is_backed_by_rab);
  return obj;
}

MaybeHandle<JSBoundFunction> Factory::NewJSBoundFunction(
    DirectHandle<JSReceiver> target_function, DirectHandle<JSAny> bound_this,
    base::Vector<DirectHandle<Object>> bound_args,
    Handle<JSPrototype> prototype) {
  DCHECK(IsCallable(*target_function));
  static_assert(Code::kMaxArguments <= FixedArray::kMaxLength);
  if (bound_args.length() >= Code::kMaxArguments) {
    THROW_NEW_ERROR(isolate(),
                    NewRangeError(MessageTemplate::kTooManyArguments));
  }

  SaveAndSwitchContext save(isolate(),
                            target_function->GetCreationContext().value());

  // Create the [[BoundArguments]] for the result.
  DirectHandle<FixedArray> bound_arguments;
  if (bound_args.empty()) {
    bound_arguments = empty_fixed_array();
  } else {
    bound_arguments = NewFixedArray(bound_args.length());
    for (int i = 0; i < bound_args.length(); ++i) {
      bound_arguments->set(i, *bound_args[i]);
    }
  }

  // Setup the map for the JSBoundFunction instance.
  Handle<Map> map = IsConstructor(*target_function)
                        ? isolate()->bound_function_with_constructor_map()
                        : isolate()->bound_function_without_constructor_map();
  if (map->prototype() != *prototype) {
    map = Map::TransitionRootMapToPrototypeForNewObject(isolate(), map,
                                                        prototype);
  }
  DCHECK_EQ(IsConstructor(*target_function), map->is_constructor());

  // Setup the JSBoundFunction instance.
  Handle<JSBoundFunction> result =
      Cast<JSBoundFunction>(NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSBoundFunction> raw = *result;
  raw->set_bound_target_function(Cast<JSCallable>(*target_function),
                                 SKIP_WRITE_BARRIER);
  raw->set_bound_this(*bound_this, SKIP_WRITE_BARRIER);
  raw->set_bound_arguments(*bound_arguments, SKIP_WRITE_BARRIER);
  return result;
}

// ES6 section 9.5.15 ProxyCreate (target, handler)
Handle<JSProxy> Factory::NewJSProxy(DirectHandle<JSReceiver> target,
                                    DirectHandle<JSReceiver> handler) {
  // Allocate the proxy object.
  DirectHandle<Map> map = IsCallable(*target)
                              ? IsConstructor(*target)
                                    ? isolate()->proxy_constructor_map()
                                    : isolate()->proxy_callable_map()
                              : isolate()->proxy_map();
  DCHECK(IsNull(map->prototype(), isolate()));
  Tagged<JSProxy> result = Cast<JSProxy>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  result->initialize_properties(isolate());
  result->set_target(*target, SKIP_WRITE_BARRIER);
  result->set_handler(*handler, SKIP_WRITE_BARRIER);
  return handle(result, isolate());
}

Handle<JSGlobalProxy> Factory::NewUninitializedJSGlobalProxy(int size) {
  // Create an empty shell of a JSGlobalProxy that needs to be reinitialized
  // via ReinitializeJSGlobalProxy later.
  DirectHandle<Map> map = NewContextlessMap(JS_GLOBAL_PROXY_TYPE, size);
  // Maintain invariant expected from any JSGlobalProxy.
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw = *map;
    raw->set_is_access_check_needed(true);
    raw->set_may_have_interesting_properties(true);
    LOG(isolate(), MapDetails(raw));
  }
  Handle<JSGlobalProxy> proxy = Cast<JSGlobalProxy>(NewJSObjectFromMap(
      map, AllocationType::kOld, DirectHandle<AllocationSite>::null(),
      NewJSObjectType::kAPIWrapper));
  // Create identity hash early in case there is any JS collection containing
  // a global proxy key and needs to be rehashed after deserialization.
  proxy->GetOrCreateIdentityHash(isolate());
  return proxy;
}

void Factory::ReinitializeJSGlobalProxy(DirectHandle<JSGlobalProxy> object,
                                        DirectHandle<JSFunction> constructor) {
  DCHECK(constructor->has_initial_map());
  Handle<Map> map(constructor->initial_map(), isolate());
  DirectHandle<Map> old_map(object->map(), isolate());

  // The proxy's hash should be retained across reinitialization.
  DirectHandle<Object> raw_properties_or_hash(object->raw_properties_or_hash(),
                                              isolate());

  if (old_map->is_prototype_map()) {
    map = Map::Copy(isolate(), map, "CopyAsPrototypeForJSGlobalProxy");
    map->set_is_prototype_map(true);
  }
  JSObject::NotifyMapChange(old_map, map, isolate());
  old_map->NotifyLeafMapLayoutChange(isolate());

  // Check that the already allocated object has the same size and type as
  // objects allocated using the constructor.
  DCHECK(map->instance_size() == old_map->instance_size());
  DCHECK(map->instance_type() == old_map->instance_type());

  // In order to keep heap in consistent state there must be no allocations
  // before object re-initialization is finished.
  DisallowGarbageCollection no_gc;

  // Reset the map for the object.
  Tagged<JSGlobalProxy> raw = *object;
  raw->set_map(isolate(), *map, kReleaseStore);

  // Reinitialize the object from the constructor map.
  InitializeJSObjectFromMap(raw, *raw_properties_or_hash, *map,
                            NewJSObjectType::kAPIWrapper);
  // Ensure that the object and constructor belongs to the same native context.
  DCHECK_EQ(object->map()->map(), constructor->map()->map());
}

Handle<JSMessageObject> Factory::NewJSMessageObject(
    MessageTemplate message, DirectHandle<Object> argument, int start_position,
    int end_position, DirectHandle<SharedFunctionInfo> shared_info,
    int bytecode_offset, DirectHandle<Script> script,
    DirectHandle<StackTraceInfo> stack_trace) {
  DirectHandle<Map> map = message_object_map();
  Tagged<JSMessageObject> message_obj =
      Cast<JSMessageObject>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  message_obj->set_raw_properties_or_hash(*empty_fixed_array(),
                                          SKIP_WRITE_BARRIER);
  message_obj->initialize_elements();
  message_obj->set_elements(*empty_fixed_array(), SKIP_WRITE_BARRIER);
  message_obj->set_type(message);
  message_obj->set_argument(*argument, SKIP_WRITE_BARRIER);
  message_obj->set_start_position(start_position);
  message_obj->set_end_position(end_position);
  message_obj->set_script(*script, SKIP_WRITE_BARRIER);
  if (start_position >= 0) {
    // If there's a start_position, then there's no need to store the
    // SharedFunctionInfo as it will never be necessary to regenerate the
    // position.
    message_obj->set_shared_info(Smi::FromInt(-1));
    message_obj->set_bytecode_offset(Smi::FromInt(0));
  } else {
    message_obj->set_bytecode_offset(Smi::FromInt(bytecode_offset));
    if (shared_info.is_null()) {
      message_obj->set_shared_info(Smi::FromInt(-1));
      DCHECK_EQ(bytecode_offset, -1);
    } else {
      message_obj->set_shared_info(*shared_info, SKIP_WRITE_BARRIER);
      DCHECK_GE(bytecode_offset, kFunctionEntryBytecodeOffset);
    }
  }

  if (stack_trace.is_null()) {
    message_obj->set_stack_trace(*the_hole_value(), SKIP_WRITE_BARRIER);
  } else {
    message_obj->set_stack_trace(*stack_trace, SKIP_WRITE_BARRIER);
  }
  message_obj->set_error_level(v8::Isolate::kMessageError);
  return handle(message_obj, isolate());
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForApiFunction(
    MaybeDirectHandle<String> maybe_name,
    DirectHandle<FunctionTemplateInfo> function_template_info,
    FunctionKind kind) {
  return NewSharedFunctionInfo(
      maybe_name, function_template_info, Builtin::kNoBuiltinId,
      function_template_info->length(), kDontAdapt, kind);
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForBuiltin(
    MaybeDirectHandle<String> maybe_name, Builtin builtin, int len,
    AdaptArguments adapt, FunctionKind kind) {
  return NewSharedFunctionInfo(maybe_name, MaybeHandle<HeapObject>(), builtin,
                               len, adapt, kind);
}

Handle<InterpreterData> Factory::NewInterpreterData(
    DirectHandle<BytecodeArray> bytecode_array, DirectHandle<Code> code) {
  Tagged<Map> map = *interpreter_data_map();
  Tagged<InterpreterData> interpreter_data = Cast<InterpreterData>(
      AllocateRawWithImmortalMap(map->instance_size(), AllocationType::kTrusted,
                                 *interpreter_data_map()));
  DisallowGarbageCollection no_gc;
  interpreter_data->init_self_indirect_pointer(isolate());
  interpreter_data->set_bytecode_array(*bytecode_array);
  interpreter_data->set_interpreter_trampoline(*code);
  return handle(interpreter_data, isolate());
}

int Factory::NumberToStringCacheHash(Tagged<Smi> number) {
  int mask = (number_string_cache()->length() >> 1) - 1;
  return number.value() & mask;
}

int Factory::NumberToStringCacheHash(double number) {
  int mask = (number_string_cache()->length() >> 1) - 1;
  int64_t bits = base::bit_cast<int64_t>(number);
  return (static_cast<int>(bits) ^ static_cast<int>(bits >> 32)) & mask;
}

Handle<String> Factory::SizeToString(size_t value, bool check_cache) {
  Handle<String> result;
  NumberCacheMode cache_mode =
      check_cache ? NumberCacheMode::kBoth : NumberCacheMode::kIgnore;
  if (value <= Smi::kMaxValue) {
    int32_t int32v = static_cast<int32_t>(static_cast<uint32_t>(value));
    // SmiToString sets the hash when needed, we can return immediately.
    return SmiToString(Smi::FromInt(int32v), cache_mode);
  } else if (value <= kMaxSafeInteger) {
    // TODO(jkummerow): Refactor the cache to not require Objects as keys.
    double double_value = static_cast<double>(value);
    result = HeapNumberToString(NewHeapNumber(double_value), value, cache_mode);
  } else {
    char arr[kNumberToStringBufferSize];
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