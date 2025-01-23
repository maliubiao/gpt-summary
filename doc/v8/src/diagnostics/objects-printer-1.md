Response: The user wants me to summarize the functionality of the provided C++ code snippet. This is the second part of a three-part file.

The code defines `Print` methods for various V8 internal object types. These methods are used for debugging and inspection purposes, allowing developers to get a detailed view of the state and structure of these objects.

The methods generally follow a pattern:
1. Print a header indicating the object type.
2. Print specific fields of the object, often using a `Brief()` function to provide a concise representation of other V8 objects.
3. Some methods include additional logic to iterate through related structures (e.g., `JSFinalizationRegistry`).
4. For `Code` objects, disassembly is included if enabled.

The code heavily interacts with V8's internal object representation and data structures.

If there's a connection to JavaScript, it's that these internal objects are the underlying implementation of JavaScript features. For instance, `JSFunction` represents a JavaScript function, `JSArray` represents a JavaScript array, and so on.

To illustrate the connection with JavaScript, I can show how some of these internal objects relate to corresponding JavaScript constructs when examined during debugging.
这是v8引擎的源代码文件 `objects-printer.cc` 的一部分，主要功能是为各种 V8 内部对象类型提供详细的打印输出方法，用于调试和诊断。

**功能归纳:**

这段代码定义了一系列的 `Print` 方法，专门用于以人类可读的格式输出 V8 引擎内部各种对象的状态和信息。 这些方法通常遵循以下模式：

1. **打印对象头信息:**  使用 `JSObjectPrintHeader` 或 `PrintHeader` 打印对象的类型名称和内存地址。
2. **打印关键字段:**  输出对象的重要成员变量的值，例如：
    * 对于迭代器 (`JSSetIterator`, `JSMapIterator` 等)，打印它们关联的集合对象。
    * 对于 `JSWeakRef`，打印其引用的目标对象。
    * 对于 `JSFunction`，打印其原型、共享信息 (SharedFunctionInfo)、代码等。
    * 对于 `JSArrayBuffer` 和 `JSTypedArray`，打印其底层存储、长度等信息.
3. **处理特殊情况:**  对于一些复杂对象，会进行额外的处理，例如：
    * 对于 `JSFinalizationRegistry`，会遍历其 `active_cells` 和 `cleared_cells` 链表。
    * 对于 `Code` 对象，如果启用了反汇编功能，还会打印其汇编代码。
4. **使用 `Brief()` 函数:**  许多输出都使用了 `Brief()` 函数，该函数旨在提供 V8 对象的简洁表示，避免循环引用或输出过多细节。

**与 JavaScript 的关系以及 JavaScript 举例:**

这些 C++ 结构和打印方法直接对应于 JavaScript 中的各种对象和概念。  当你在 V8 引擎的调试模式下检查 JavaScript 代码运行时，这些 `Print` 方法会被调用，以展示 JavaScript 对象在引擎内部的表示。

**JavaScript 例子:**

假设你在 JavaScript 中创建了一个 `Set` 对象和一个 `Map` 对象，并在调试器中检查它们：

```javascript
const mySet = new Set([1, 2, 3]);
const myMap = new Map([['a', 1], ['b', 2]]);
```

如果你在 V8 的调试环境下查看 `mySet` 和 `myMap`，  `objects-printer.cc` 中相应的 `JSSetPrint` 和 `JSMapPrint` 方法会被调用，输出类似下面的信息 (简化版，实际输出会更详细)：

**`mySet` 的输出 (可能触发 `JSSetPrint`)**:

```
JSSet: 0x<memory_address>
 - map: 0x<memory_address>
 - table: 0x<memory_address>
   - <HashTable contents...>
JSObject body size: 3
```

**`myMap` 的输出 (可能触发 `JSMapPrint`)**:

```
JSMap: 0x<memory_address>
 - map: 0x<memory_address>
 - table: 0x<memory_address>
   - <OrderedHashMap contents...>
 - ordered_hash_map_field_count: 2
JSObject body size: 4
```

**其他 JavaScript 例子和对应的 C++ 结构:**

* **JavaScript 函数:**
   ```javascript
   function myFunction(x) { return x * 2; }
   ```
   对应 C++ 中的 `JSFunction` 和 `SharedFunctionInfo`。 `JSFunctionPrint` 和 `SharedFunctionInfoPrint` 会输出函数的代码、作用域信息、参数等。

* **JavaScript 数组:**
   ```javascript
   const myArray = [10, 20, 30];
   ```
   对应 C++ 中的 `JSArray`。 虽然这里没有直接展示 `JSArrayPrint` 的代码，但在同一文件的前面部分应该有定义，它会输出数组的元素、长度等。

* **JavaScript WeakMap/WeakSet:**
   ```javascript
   const wm = new WeakMap();
   const ws = new WeakSet();
   ```
   对应 C++ 中的 `JSWeakMap` 和 `JSWeakSet`， `JSWeakMapPrint` 和 `JSWeakSetPrint` 会输出它们内部的哈希表结构。

* **JavaScript Promise (在 `WasmSuspenderObjectPrint` 中间接提及):** 虽然这段代码没有直接的 `JSPromisePrint`，但 `WasmSuspenderObjectPrint` 中提到了 `promise()`，这说明了 V8 内部也需要表示 Promise 相关的对象。

总而言之，`objects-printer.cc` 中的这段代码是 V8 引擎内部调试工具的关键组成部分，它提供了将 V8 内部对象状态转化为可读文本的能力，帮助开发者理解 JavaScript 代码在引擎底层的运行方式和对象结构。

### 提示词
```
这是目录为v8/src/diagnostics/objects-printer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
SetIteratorPrint(std::ostream& os) {
  JSCollectionIteratorPrint(os, "JSSetIterator");
}

void JSMapIterator::JSMapIteratorPrint(std::ostream& os) {
  JSCollectionIteratorPrint(os, "JSMapIterator");
}

void JSWeakRef::JSWeakRefPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSWeakRef");
  os << "\n - target: " << Brief(target());
  JSObjectPrintBody(os, *this);
}

void JSShadowRealm::JSShadowRealmPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSShadowRealm");
  os << "\n - native_context: " << Brief(native_context());
  JSObjectPrintBody(os, *this);
}

void JSWrappedFunction::JSWrappedFunctionPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSWrappedFunction");
  os << "\n - wrapped_target_function: " << Brief(wrapped_target_function());
  JSObjectPrintBody(os, *this);
}

void JSFinalizationRegistry::JSFinalizationRegistryPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSFinalizationRegistry");
  os << "\n - native_context: " << Brief(native_context());
  os << "\n - cleanup: " << Brief(cleanup());
  os << "\n - active_cells: " << Brief(active_cells());
  Tagged<Object> active_cell = active_cells();
  while (IsWeakCell(active_cell)) {
    os << "\n   - " << Brief(active_cell);
    active_cell = Cast<WeakCell>(active_cell)->next();
  }
  os << "\n - cleared_cells: " << Brief(cleared_cells());
  Tagged<Object> cleared_cell = cleared_cells();
  while (IsWeakCell(cleared_cell)) {
    os << "\n   - " << Brief(cleared_cell);
    cleared_cell = Cast<WeakCell>(cleared_cell)->next();
  }
  os << "\n - key_map: " << Brief(key_map());
  JSObjectPrintBody(os, *this);
}

void JSSharedArray::JSSharedArrayPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSharedArray");
  Isolate* isolate = GetIsolateFromWritableObject(*this);
  os << "\n - isolate: " << isolate;
  if (HeapLayout::InWritableSharedSpace(*this)) os << " (shared)";
  JSObjectPrintBody(os, *this);
}

void JSSharedStruct::JSSharedStructPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSharedStruct");
  Isolate* isolate = GetIsolateFromWritableObject(*this);
  os << "\n - isolate: " << isolate;
  if (HeapLayout::InWritableSharedSpace(*this)) os << " (shared)";
  JSObjectPrintBody(os, *this);
}

void JSAtomicsMutex::JSAtomicsMutexPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSAtomicsMutex");
  Isolate* isolate = GetIsolateFromWritableObject(*this);
  os << "\n - isolate: " << isolate;
  if (HeapLayout::InWritableSharedSpace(*this)) os << " (shared)";
  os << "\n - state: " << this->state();
  os << "\n - owner_thread_id: " << this->owner_thread_id();
  JSObjectPrintBody(os, *this);
}

void JSAtomicsCondition::JSAtomicsConditionPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSAtomicsCondition");
  Isolate* isolate = GetIsolateFromWritableObject(*this);
  os << "\n - isolate: " << isolate;
  if (HeapLayout::InWritableSharedSpace(*this)) os << " (shared)";
  os << "\n - state: " << this->state();
  JSObjectPrintBody(os, *this);
}

std::ostream& operator<<(std::ostream& os, DisposableStackState state) {
  switch (state) {
    case DisposableStackState::kPending:
      return os << "Pending";
    case DisposableStackState::kDisposed:
      return os << "Disposed";
  }
  UNREACHABLE();
}

void JSDisposableStackBase::JSDisposableStackBasePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDisposableStack");
  os << "\n - stack: " << Brief(stack());
  os << "\n - length: " << length();
  os << "\n - state: " << state();
  os << "\n - needs_await: " << needs_await();
  os << "\n - has_awaited: " << has_awaited();
  os << "\n - suppressed_error_created: " << suppressed_error_created();
  os << "\n - error: " << error();
  os << "\n - error_message: " << error_message();
  JSObjectPrintBody(os, *this);
}

void JSAsyncDisposableStack::JSAsyncDisposableStackPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSAsyncDisposableStack");
  os << "\n - stack: " << Brief(stack());
  os << "\n - length: " << length();
  os << "\n - state: " << state();
  os << "\n - needs_await: " << needs_await();
  os << "\n - has_awaited: " << has_awaited();
  os << "\n - suppressed_error_created: " << suppressed_error_created();
  os << "\n - error: " << error();
  os << "\n - error_message: " << error_message();
  JSObjectPrintBody(os, *this);
}

void JSIteratorHelper::JSIteratorHelperPrintHeader(std::ostream& os,
                                                   const char* helper_name) {
  JSObjectPrintHeader(os, *this, helper_name);
  os << "\n - underlying.object: " << Brief(underlying_object());
  os << "\n - underlying.next: " << Brief(underlying_next());
}

void JSIteratorMapHelper::JSIteratorMapHelperPrint(std::ostream& os) {
  JSIteratorHelperPrintHeader(os, "JSIteratorMapHelper");
  os << "\n - mapper: " << Brief(mapper());
  os << "\n - counter: " << counter();
  JSObjectPrintBody(os, *this);
}

void JSIteratorFilterHelper::JSIteratorFilterHelperPrint(std::ostream& os) {
  JSIteratorHelperPrintHeader(os, "JSIteratorFilterHelper");
  os << "\n - predicate: " << Brief(predicate());
  os << "\n - counter: " << counter();
  JSObjectPrintBody(os, *this);
}

void JSIteratorTakeHelper::JSIteratorTakeHelperPrint(std::ostream& os) {
  JSIteratorHelperPrintHeader(os, "JSIteratorTakeHelper");
  os << "\n - remaining: " << remaining();
  JSObjectPrintBody(os, *this);
}

void JSIteratorDropHelper::JSIteratorDropHelperPrint(std::ostream& os) {
  JSIteratorHelperPrintHeader(os, "JSIteratorDropHelper");
  os << "\n - remaining: " << remaining();
  JSObjectPrintBody(os, *this);
}

void JSIteratorFlatMapHelper::JSIteratorFlatMapHelperPrint(std::ostream& os) {
  JSIteratorHelperPrintHeader(os, "JSIteratorFlatMapHelper");
  os << "\n - mapper: " << Brief(mapper());
  os << "\n - counter: " << counter();
  os << "\n - innerIterator.object" << Brief(innerIterator_object());
  os << "\n - innerIterator.next" << Brief(innerIterator_next());
  os << "\n - innerAlive" << innerAlive();
  JSObjectPrintBody(os, *this);
}

void JSWeakMap::JSWeakMapPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSWeakMap");
  os << "\n - table: " << Brief(table());
  JSObjectPrintBody(os, *this);
}

void JSWeakSet::JSWeakSetPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSWeakSet");
  os << "\n - table: " << Brief(table());
  JSObjectPrintBody(os, *this);
}

void JSArrayBuffer::JSArrayBufferPrint(std::ostream& os) {
  JSAPIObjectWithEmbedderSlotsPrintHeader(os, *this, "JSArrayBuffer");
  os << "\n - backing_store: " << backing_store();
  os << "\n - byte_length: " << byte_length();
  os << "\n - max_byte_length: " << max_byte_length();
  os << "\n - detach key: " << detach_key();
  if (is_external()) os << "\n - external";
  if (is_detachable()) os << "\n - detachable";
  if (was_detached()) os << "\n - detached";
  if (is_shared()) os << "\n - shared";
  if (is_resizable_by_js()) os << "\n - resizable_by_js";
  JSObjectPrintBody(os, *this, !was_detached());
}

void JSTypedArray::JSTypedArrayPrint(std::ostream& os) {
  JSAPIObjectWithEmbedderSlotsPrintHeader(os, *this, "JSTypedArray");
  os << "\n - buffer: " << Brief(buffer());
  os << "\n - byte_offset: " << byte_offset();
  os << "\n - byte_length: " << byte_length();
  os << "\n - length: " << GetLength();
  os << "\n - data_ptr: " << DataPtr();
  Tagged_t base_ptr = static_cast<Tagged_t>(base_pointer().ptr());
  os << "\n   - base_pointer: "
     << reinterpret_cast<void*>(static_cast<Address>(base_ptr));
  os << "\n   - external_pointer: "
     << reinterpret_cast<void*>(external_pointer());
  if (!IsJSArrayBuffer(buffer())) {
    os << "\n <invalid buffer>\n";
    return;
  }
  if (WasDetached()) os << "\n - detached";
  if (is_length_tracking()) os << "\n - length-tracking";
  if (is_backed_by_rab()) os << "\n - backed-by-rab";
  JSObjectPrintBody(os, *this, !WasDetached());
}

void JSArrayIterator::JSArrayIteratorPrint(std::ostream& os) {  // NOLING
  JSObjectPrintHeader(os, *this, "JSArrayIterator");
  os << "\n - iterated_object: " << Brief(iterated_object());
  os << "\n - next_index: " << Brief(next_index());
  os << "\n - kind: " << kind();
  JSObjectPrintBody(os, *this);
}

void JSDataView::JSDataViewPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDataView");
  os << "\n - buffer =" << Brief(buffer());
  os << "\n - byte_offset: " << byte_offset();
  os << "\n - byte_length: " << byte_length();
  if (!IsJSArrayBuffer(buffer())) {
    os << "\n <invalid buffer>";
    return;
  }
  if (WasDetached()) os << "\n - detached";
  JSObjectPrintBody(os, *this, !WasDetached());
}

void JSRabGsabDataView::JSRabGsabDataViewPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSRabGsabDataView");
  os << "\n - buffer =" << Brief(buffer());
  os << "\n - byte_offset: " << byte_offset();
  os << "\n - byte_length: " << byte_length();
  if (is_length_tracking()) os << "\n - length-tracking";
  if (is_backed_by_rab()) os << "\n - backed-by-rab";
  if (!IsJSArrayBuffer(buffer())) {
    os << "\n <invalid buffer>";
    return;
  }
  if (WasDetached()) os << "\n - detached";
  JSObjectPrintBody(os, *this, !WasDetached());
}

void JSBoundFunction::JSBoundFunctionPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSBoundFunction");
  os << "\n - bound_target_function: " << Brief(bound_target_function());
  os << "\n - bound_this: " << Brief(bound_this());
  os << "\n - bound_arguments: " << Brief(bound_arguments());
  JSObjectPrintBody(os, *this);
}

void JSFunction::JSFunctionPrint(std::ostream& os) {
  Isolate* isolate = GetIsolate();
  JSObjectPrintHeader(os, *this, "Function");
  os << "\n - function prototype: ";
  if (has_prototype_slot()) {
    if (has_prototype()) {
      os << Brief(prototype());
      if (map()->has_non_instance_prototype()) {
        os << " (non-instance prototype)";
      }
    }
    os << "\n - initial_map: ";
    if (has_initial_map()) os << Brief(initial_map());
  } else {
    os << "<no-prototype-slot>";
  }
  os << "\n - shared_info: " << Brief(shared());
  os << "\n - name: " << Brief(shared()->Name());

  // Print Builtin name for builtin functions
  Builtin builtin = code(isolate)->builtin_id();
  if (Builtins::IsBuiltinId(builtin)) {
    os << "\n - builtin: " << isolate->builtins()->name(builtin);
  }

  os << "\n - formal_parameter_count: ";
  int formal_parameter_count =
      shared()->internal_formal_parameter_count_with_receiver();
  if (formal_parameter_count == kDontAdaptArgumentsSentinel) {
    os << "kDontAdaptArgumentsSentinel";
  } else {
    os << formal_parameter_count;
  }
  os << "\n - kind: " << shared()->kind();
  os << "\n - context: " << Brief(context());
  os << "\n - code: " << Brief(code(isolate));
#ifdef V8_ENABLE_LEAPTIERING
  os << "\n - dispatch_handle: 0x" << std::hex << dispatch_handle() << std::dec;
  if (has_feedback_vector() &&
      raw_feedback_cell()->dispatch_handle() != dispatch_handle()) {
    os << "\n - canonical feedback cell dispatch_handle: 0x" << std::hex
       << raw_feedback_cell()->dispatch_handle() << std::dec;
  }
  if (IsTieringRequestedOrInProgress(GetIsolate())) {
    os << "\n - tiering request ";
    if (tiering_in_progress()) {
      os << "in_progress ";
    }
    GetProcessWideJSDispatchTable()->PrintCurrentTieringRequest(
        dispatch_handle(), GetIsolate(), os);
  }

#endif  // V8_ENABLE_LEAPTIERING
  if (code(isolate)->kind() == CodeKind::FOR_TESTING) {
    os << "\n - FOR_TESTING";
  } else if (ActiveTierIsIgnition(isolate)) {
    os << "\n - interpreted";
    if (shared()->HasBytecodeArray()) {
      os << "\n - bytecode: " << shared()->GetBytecodeArray(isolate);
    }
  }
#if V8_ENABLE_WEBASSEMBLY
  if (WasmExportedFunction::IsWasmExportedFunction(*this)) {
    Tagged<WasmExportedFunction> function = Cast<WasmExportedFunction>(*this);
    Tagged<WasmExportedFunctionData> data =
        function->shared()->wasm_exported_function_data();
    os << "\n - Wasm instance data: " << Brief(data->instance_data());
    os << "\n - Wasm function index: " << data->function_index();
  }
  if (WasmJSFunction::IsWasmJSFunction(*this)) {
    Tagged<WasmJSFunction> function = Cast<WasmJSFunction>(*this);
    os << "\n - Wasm wrapper around: "
       << Brief(function->shared()->wasm_js_function_data()->GetCallable());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  shared()->PrintSourceCode(os);
  JSObjectPrintBody(os, *this);
  os << " - feedback vector: ";
  if (!shared()->HasFeedbackMetadata()) {
    os << "feedback metadata is not available in SFI\n";
  } else if (has_feedback_vector()) {
    feedback_vector()->FeedbackVectorPrint(os);
  } else if (has_closure_feedback_cell_array()) {
    os << "No feedback vector, but we have a closure feedback cell array\n";
    closure_feedback_cell_array()->ClosureFeedbackCellArrayPrint(os);
  } else {
    os << "not available\n";
  }
}

void SharedFunctionInfo::PrintSourceCode(std::ostream& os) {
  if (HasSourceCode()) {
    os << "\n - source code: ";
    Tagged<String> source = Cast<String>(Cast<Script>(script())->source());
    int start = StartPosition();
    int length = EndPosition() - start;
    std::unique_ptr<char[]> source_string = source->ToCString(start, length);
    os << source_string.get();
  }
}

void SharedFunctionInfo::SharedFunctionInfoPrint(std::ostream& os) {
  PrintHeader(os, "SharedFunctionInfo");
  os << "\n - name: ";
  if (HasSharedName()) {
    os << Brief(Name());
  } else {
    os << "<no-shared-name>";
  }
  if (HasInferredName()) {
    os << "\n - inferred name: " << Brief(inferred_name());
  }
  if (class_scope_has_private_brand()) {
    os << "\n - class_scope_has_private_brand";
  }
  if (has_static_private_methods_or_accessors()) {
    os << "\n - has_static_private_methods_or_accessors";
  }
  if (private_name_lookup_skips_outer_class()) {
    os << "\n - private_name_lookup_skips_outer_class";
  }
  os << "\n - kind: " << kind();
  os << "\n - syntax kind: " << syntax_kind();
  os << "\n - function_map_index: " << function_map_index();
  os << "\n - formal_parameter_count: ";
  int formal_parameter_count = internal_formal_parameter_count_with_receiver();
  if (formal_parameter_count == kDontAdaptArgumentsSentinel) {
    os << "kDontAdaptArgumentsSentinel";
  } else {
    os << formal_parameter_count;
  }
  os << "\n - expected_nof_properties: "
     << static_cast<int>(expected_nof_properties());
  os << "\n - language_mode: " << language_mode();
  if (HasTrustedData()) {
    os << "\n - trusted_function_data: "
       << Brief(GetTrustedData(GetIsolateForSandbox(*this)));
  } else {
    os << "\n - trusted_function_data: <empty>";
  }
  os << "\n - untrusted_function_data: " << Brief(GetUntrustedData());
  os << "\n - code (from function_data): ";
  Isolate* isolate;
  if (GetIsolateFromHeapObject(*this, &isolate)) {
    os << Brief(GetCode(isolate));
  } else {
    os << kUnavailableString;
  }
  PrintSourceCode(os);
  // Script files are often large, thus only print their {Brief} representation.
  os << "\n - script: " << Brief(script());
  os << "\n - function token position: " << function_token_position();
  os << "\n - start position: " << StartPosition();
  os << "\n - end position: " << EndPosition();
  os << "\n - scope info: " << Brief(scope_info());
  if (HasOuterScopeInfo()) {
    os << "\n - outer scope info: " << Brief(GetOuterScopeInfo());
  }
  os << "\n - length: " << length();
  os << "\n - feedback_metadata: ";
  if (HasFeedbackMetadata()) {
    feedback_metadata()->FeedbackMetadataPrint(os);
  } else {
    os << "<none>";
  }
  os << "\n - function_literal_id: " << function_literal_id();
  os << "\n - unique_id: " << unique_id();
  os << "\n - age: " << age();
  os << "\n";
}

void SharedFunctionInfoWrapper::SharedFunctionInfoWrapperPrint(
    std::ostream& os) {
  PrintHeader(os, "SharedFunctionInfoWrapper");
  os << "\n    sfi: " << Brief(shared_info());
}

void JSGlobalProxy::JSGlobalProxyPrint(std::ostream& os) {
  JSAPIObjectWithEmbedderSlotsPrintHeader(os, *this, "JSGlobalProxy");
  JSObjectPrintBody(os, *this);
}

void JSGlobalObject::JSGlobalObjectPrint(std::ostream& os) {
  JSAPIObjectWithEmbedderSlotsPrintHeader(os, *this, "JSGlobalObject");
  os << "\n - global proxy: " << Brief(global_proxy());
  JSObjectPrintBody(os, *this);
}

void PropertyCell::PropertyCellPrint(std::ostream& os) {
  PrintHeader(os, "PropertyCell");
  os << "\n - name: ";
  name()->NamePrint(os);
  os << "\n - value: " << Brief(value(kAcquireLoad));
  os << "\n - details: ";
  PropertyDetails details = property_details(kAcquireLoad);
  details.PrintAsSlowTo(os, true);
  os << "\n - cell_type: " << details.cell_type();
  os << "\n - dependent code: " << dependent_code();
  os << "\n";
}

void ContextSidePropertyCell::ContextSidePropertyCellPrint(std::ostream& os) {
  PrintHeader(os, "ContextSidePropertyCell");
  os << "\n - dependent code: " << dependent_code();
  os << "\n - cell_type: " << context_side_property_raw(kAcquireLoad);
  os << "\n";
}

void InstructionStream::InstructionStreamPrint(std::ostream& os) {
  code(kAcquireLoad)->CodePrint(os);
}

void Code::CodePrint(std::ostream& os, const char* name, Address current_pc) {
  // This prints the entire {Code,InstructionStream} composite object.
  //
  // First, Code:
  PrintHeader(os, "Code");
  os << "\n - kind: " << CodeKindToString(kind());
  if (is_builtin()) {
    os << "\n - builtin_id: " << Builtins::name(builtin_id());
  }
  os << "\n - deoptimization_data_or_interpreter_data: "
     << Brief(raw_deoptimization_data_or_interpreter_data());
  os << "\n - position_table: " << Brief(raw_position_table());
  os << "\n - parameter_count: " << parameter_count();
  os << "\n - instruction_stream: " << Brief(raw_instruction_stream());
  os << "\n - instruction_start: "
     << reinterpret_cast<void*>(instruction_start());
  os << "\n - is_turbofanned: " << is_turbofanned();
  os << "\n - stack_slots: " << stack_slots();
  os << "\n - marked_for_deoptimization: " << marked_for_deoptimization();
  os << "\n - embedded_objects_cleared: " << embedded_objects_cleared();
  os << "\n - can_have_weak_objects: " << can_have_weak_objects();
  os << "\n - instruction_size: " << instruction_size();
  os << "\n - metadata_size: " << metadata_size();

  if (kind() != CodeKind::WASM_TO_JS_FUNCTION) {
    os << "\n - inlined_bytecode_size: " << inlined_bytecode_size();
  } else {
    os << "\n - wasm_js_tagged_parameter_count: "
       << wasm_js_tagged_parameter_count();
    os << "\n - wasm_js_first_tagged_parameter: "
       << wasm_js_first_tagged_parameter();
  }
  os << "\n - osr_offset: " << osr_offset();
  os << "\n - handler_table_offset: " << handler_table_offset();
  os << "\n - unwinding_info_offset: " << unwinding_info_offset();
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    os << "\n - constant_pool_offset: " << constant_pool_offset();
  }
  os << "\n - code_comments_offset: " << code_comments_offset();

  // Then, InstructionStream:
  if (has_instruction_stream()) {
    Tagged<InstructionStream> istream = instruction_stream();
    os << "\n - instruction_stream.relocation_info: "
       << Brief(istream->relocation_info());
    os << "\n - instruction_stream.body_size: " << istream->body_size();
  }
  os << "\n";

  // Finally, the disassembly:
#ifdef ENABLE_DISASSEMBLER
  os << "\n--- Disassembly: ---\n";
  Disassemble(name, os, Isolate::Current(), current_pc);
#endif
}

void CodeWrapper::CodeWrapperPrint(std::ostream& os) {
  PrintHeader(os, "CodeWrapper");
  os << "\n - code: " << Brief(code(Isolate::Current()));
  os << "\n";
}

void Foreign::ForeignPrint(std::ostream& os) {
  PrintHeader(os, "Foreign");
  os << "\n - foreign address: "
     << reinterpret_cast<void*>(foreign_address_unchecked());
  os << "\n";
}

void TrustedForeign::TrustedForeignPrint(std::ostream& os) {
  PrintHeader(os, "TrustedForeign");
  os << "\n - foreign address: " << reinterpret_cast<void*>(foreign_address());
  os << "\n";
}

void AsyncGeneratorRequest::AsyncGeneratorRequestPrint(std::ostream& os) {
  PrintHeader(os, "AsyncGeneratorRequest");
  const char* mode = "Invalid!";
  switch (resume_mode()) {
    case JSGeneratorObject::kNext:
      mode = ".next()";
      break;
    case JSGeneratorObject::kReturn:
      mode = ".return()";
      break;
    case JSGeneratorObject::kThrow:
      mode = ".throw()";
      break;
  }
  os << "\n - resume mode: " << mode;
  os << "\n - value: " << Brief(value());
  os << "\n - next: " << Brief(next());
  os << "\n";
}

static void PrintModuleFields(Tagged<Module> module, std::ostream& os) {
  os << "\n - exports: " << Brief(module->exports());
  os << "\n - status: " << module->status();
  os << "\n - exception: " << Brief(module->exception());
}

void Module::ModulePrint(std::ostream& os) {
  if (IsSourceTextModule(*this)) {
    Cast<SourceTextModule>(*this)->SourceTextModulePrint(os);
  } else if (IsSyntheticModule(*this)) {
    Cast<SyntheticModule>(*this)->SyntheticModulePrint(os);
  } else {
    UNREACHABLE();
  }
}

void SourceTextModule::SourceTextModulePrint(std::ostream& os) {
  PrintHeader(os, "SourceTextModule");
  PrintModuleFields(*this, os);
  os << "\n - sfi/code/info: " << Brief(code());
  Tagged<Script> script = GetScript();
  os << "\n - script: " << Brief(script);
  os << "\n - origin: " << Brief(script->GetNameOrSourceURL());
  os << "\n - requested_modules: " << Brief(requested_modules());
  os << "\n - import_meta: " << Brief(import_meta(kAcquireLoad));
  os << "\n - cycle_root: " << Brief(cycle_root());
  os << "\n - has_toplevel_await: " << has_toplevel_await();
  os << "\n - async_evaluation_ordinal: " << async_evaluation_ordinal();
  os << "\n";
}

void JSModuleNamespace::JSModuleNamespacePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSModuleNamespace");
  os << "\n - module: " << Brief(module());
  JSObjectPrintBody(os, *this);
}

void PrototypeInfo::PrototypeInfoPrint(std::ostream& os) {
  PrintHeader(os, "PrototypeInfo");
  os << "\n - module namespace: " << Brief(module_namespace());
  os << "\n - prototype users: " << Brief(prototype_users());
  os << "\n - registry slot: " << registry_slot();
  os << "\n - derived maps: " << Brief(derived_maps());
  os << "\n - should_be_fast_map: " << should_be_fast_map();
  os << "\n";
}

void ArrayBoilerplateDescription::ArrayBoilerplateDescriptionPrint(
    std::ostream& os) {
  PrintHeader(os, "ArrayBoilerplateDescription");
  os << "\n - elements kind: " << ElementsKindToString(elements_kind());
  os << "\n - constant elements: " << Brief(constant_elements());
  os << "\n";
}

#if V8_ENABLE_WEBASSEMBLY
void AsmWasmData::AsmWasmDataPrint(std::ostream& os) {
  PrintHeader(os, "AsmWasmData");
  os << "\n - native module: " << Brief(managed_native_module());
  os << "\n - uses bitset: " << uses_bitset()->value();
  os << "\n";
}

void WasmTypeInfo::WasmTypeInfoPrint(std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  PrintHeader(os, "WasmTypeInfo");
  os << "\n - type address: " << reinterpret_cast<void*>(native_type());
  os << "\n - supertypes: ";
  for (int i = 0; i < supertypes_length(); i++) {
    os << "\n  - " << Brief(supertypes(i));
  }
  os << "\n - trusted_data: " << Brief(trusted_data(isolate));
  os << "\n";
}

void WasmStruct::WasmStructPrint(std::ostream& os) {
  PrintHeader(os, "WasmStruct");
  wasm::StructType* struct_type = type();
  os << "\n - fields (" << struct_type->field_count() << "):";
  for (uint32_t i = 0; i < struct_type->field_count(); i++) {
    wasm::ValueType field = struct_type->field(i);
    os << "\n   - " << field.short_name() << ": ";
    uint32_t field_offset = struct_type->field_offset(i);
    Address field_address = RawFieldAddress(field_offset);
    switch (field.kind()) {
      case wasm::kI32:
        os << base::ReadUnalignedValue<int32_t>(field_address);
        break;
      case wasm::kI64:
        os << base::ReadUnalignedValue<int64_t>(field_address);
        break;
      case wasm::kF16:
        os << fp16_ieee_to_fp32_value(
            base::ReadUnalignedValue<uint16_t>(field_address));
        break;
      case wasm::kF32:
        os << base::ReadUnalignedValue<float>(field_address);
        break;
      case wasm::kF64:
        os << base::ReadUnalignedValue<double>(field_address);
        break;
      case wasm::kI8:
        os << base::ReadUnalignedValue<int8_t>(field_address);
        break;
      case wasm::kI16:
        os << base::ReadUnalignedValue<int16_t>(field_address);
        break;
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt: {
        Tagged_t raw = base::ReadUnalignedValue<Tagged_t>(field_address);
#if V8_COMPRESS_POINTERS
        Address obj = V8HeapCompressionScheme::DecompressTagged(address(), raw);
#else
        Address obj = raw;
#endif
        os << Brief(Tagged<Object>(obj));
        break;
      }
      case wasm::kS128:
        os << "0x" << std::hex << std::setfill('0');
#ifdef V8_TARGET_BIG_ENDIAN
        for (int j = 0; j < kSimd128Size; j++) {
#else
        for (int j = kSimd128Size - 1; j >= 0; j--) {
#endif
          os << std::setw(2)
             << static_cast<int>(reinterpret_cast<uint8_t*>(field_address)[j]);
        }
        os << std::dec << std::setfill(' ');
        break;
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        UNREACHABLE();
    }
  }
  os << "\n";
}

void WasmArray::WasmArrayPrint(std::ostream& os) {
  PrintHeader(os, "WasmArray");
  wasm::ArrayType* array_type = type();
  uint32_t len = length();
  os << "\n - element type: " << array_type->element_type().name();
  os << "\n - length: " << len;
  Address data_ptr = ptr() + WasmArray::kHeaderSize - kHeapObjectTag;
  switch (array_type->element_type().kind()) {
    case wasm::kI32:
      PrintTypedArrayElements(os, reinterpret_cast<int32_t*>(data_ptr), len,
                              true);
      break;
    case wasm::kI64:
      PrintTypedArrayElements(os, reinterpret_cast<int64_t*>(data_ptr), len,
                              true);
      break;
    case wasm::kF16:
      PrintTypedArrayElements(os, reinterpret_cast<Fp16Printer*>(data_ptr), len,
                              true);
      break;
    case wasm::kF32:
      PrintTypedArrayElements(os, reinterpret_cast<float*>(data_ptr), len,
                              true);
      break;
    case wasm::kF64:
      PrintTypedArrayElements(os, reinterpret_cast<double*>(data_ptr), len,
                              true);
      break;
    case wasm::kI8:
      PrintTypedArrayElements(os, reinterpret_cast<int8_t*>(data_ptr), len,
                              true);
      break;
    case wasm::kI16:
      PrintTypedArrayElements(os, reinterpret_cast<int16_t*>(data_ptr), len,
                              true);
      break;
    case wasm::kRef:
    case wasm::kRefNull: {
      os << "\n - elements:";
      constexpr uint32_t kWasmArrayMaximumPrintedElements = 5;
      for (uint32_t i = 0;
           i < std::min(this->length(), kWasmArrayMaximumPrintedElements);
           i++) {
        os << "\n   " << static_cast<int>(i) << " - "
           << Brief(TaggedField<Object>::load(*this, this->element_offset(i)));
      }
      if (this->length() > kWasmArrayMaximumPrintedElements) os << "\n   ...";
      break;
    }
    case wasm::kS128: {
      os << "\n - elements:";
      constexpr uint32_t kWasmArrayMaximumPrintedElements = 5;
      for (uint32_t i = 0;
           i < std::min(this->length(), kWasmArrayMaximumPrintedElements);
           i++) {
        os << "\n   " << static_cast<int>(i) << " - 0x" << std::hex
           << std::setfill('0');
#ifdef V8_TARGET_BIG_ENDIAN
        for (int j = 0; j < kSimd128Size; j++) {
#else
        for (int j = kSimd128Size - 1; j >= 0; j--) {
#endif
          os << std::setw(2)
             << static_cast<int>(
                    reinterpret_cast<uint8_t*>(this->ElementAddress(i))[j]);
        }
        os << std::dec << std::setfill(' ');
      }
      if (this->length() > kWasmArrayMaximumPrintedElements) os << "\n   ...";
      break;
    }
    case wasm::kRtt:
    case wasm::kTop:
    case wasm::kBottom:
    case wasm::kVoid:
      UNREACHABLE();
  }
  os << "\n";
}

void WasmContinuationObject::WasmContinuationObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmContinuationObject");
  os << "\n - parent: " << parent();
  os << "\n - jmpbuf: " << jmpbuf();
  os << "\n - stack: " << stack();
  os << "\n";
}

void WasmSuspenderObject::WasmSuspenderObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmSuspenderObject");
  os << "\n - continuation: " << continuation();
  os << "\n - parent: " << parent();
  os << "\n - promise: " << promise();
  os << "\n - resume: " << resume();
  os << "\n - reject: " << reject();
  os << "\n - state: " << state();
  os << "\n";
}

void WasmSuspendingObject::WasmSuspendingObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmSuspendingObject");
  os << "\n - callable: " << callable();
  os << "\n";
}

void WasmInstanceObject::WasmInstanceObjectPrint(std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  JSObjectPrintHeader(os, *this, "WasmInstanceObject");
  os << "\n - trusted_data: " << Brief(trusted_data(isolate));
  os << "\n - module_object: " << Brief(module_object());
  os << "\n - exports_object: " << Brief(exports_object());
  JSObjectPrintBody(os, *this);
  os << "\n";
}

void WasmTrustedInstanceData::WasmTrustedInstanceDataPrint(std::ostream& os) {
#define PRINT_WASM_INSTANCE_FIELD(name, convert) \
  os << "\n - " #name ": " << convert(name());
#define PRINT_OPTIONAL_WASM_INSTANCE_FIELD(name, convert) \
  if (has_##name()) os << "\n - " #name ": " << convert(name());

  auto to_void_ptr = [](auto value) {
    static_assert(sizeof(value) == kSystemPointerSize);
    return reinterpret_cast<void*>(value);
  };

  PrintHeader(os, "WasmTrustedInstanceData");
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(instance_object, Brief);
  PRINT_WASM_INSTANCE_FIELD(native_context, Brief);
  PRINT_WASM_INSTANCE_FIELD(shared_part, Brief);
  PRINT_WASM_INSTANCE_FIELD(memory_objects, Brief);
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(untagged_globals_buffer, Brief);
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(tagged_globals_buffer, Brief);
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(imported_mutable_globals_buffers, Brief);
#if V8_ENABLE_DRUMBRAKE
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(interpreter_object, Brief);
#endif  // V8_ENABLE_DRUMBRAKE
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(tables, Brief);
  PRINT_WASM_INSTANCE_FIELD(dispatch_table0, Brief);
  PRINT_WASM_INSTANCE_FIELD(dispatch_tables, Brief);
  PRINT_WASM_INSTANCE_FIELD(dispatch_table_for_imports, Brief);
  PRINT_OPTIONAL_WASM_INSTANCE_FIELD(tags_table, Brief);
  PRINT_WASM_INSTANCE_FIELD(func_refs, Brief);
  PRINT_WASM_INSTANCE_FIELD(managed_object_maps, Brief);
  PRINT_WASM_INSTANCE_FIELD(feedback_vectors, Brief);
  PRINT_WASM_INSTANCE_FIELD(well_known_imports, Brief);
  PRINT_WASM_INSTANCE_FIELD(memory0_start, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(memory0_size, +);
  PRINT_WASM_INSTANCE_FIELD(new_allocation_limit_address, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(new_allocation_top_address, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(old_allocation_limit_address, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(old_allocation_top_address, to_void_ptr);
#if V8_ENABLE_DRUMBRAKE
  PRINT_WASM_INSTANCE_FIELD(imported_function_indices, Brief);
#endif  // V8_ENABLE_DRUMBRAKE
  PRINT_WASM_INSTANCE_FIELD(globals_start, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(imported_mutable_globals, Brief);
  PRINT_WASM_INSTANCE_FIELD(jump_table_start, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(data_segment_starts, Brief);
  PRINT_WASM_INSTANCE_FIELD(data_segment_sizes, Brief);
  PRINT_WASM_INSTANCE_FIELD(element_segments, Brief);
  PRINT_WASM_INSTANCE_FIELD(hook_on_function_call_address, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(tiering_budget_array, to_void_ptr);
  PRINT_WASM_INSTANCE_FIELD(memory_bases_and_sizes, Brief);
  PRINT_WASM_INSTANCE_FIELD(break_on_entry, static_cast<int>);
  os << "\n";

#undef PRINT_OPTIONAL_WASM_INSTANCE_FIELD
#undef PRINT_WASM_INSTANCE_FIELD
}

void WasmDispatchTable::WasmDispatchTablePrint(std::ostream& os) {
  PrintHeader(os, "WasmDispatchTable");
  int len = length();
  os << "\n - length: " << len;
  os << "\n - capacity: " << capacity();
  // Only print up to 55 elements; otherwise print the first 50 and "[...]".
  int printed = len > 55 ? 50 : len;
  for (int i = 0; i < printed; ++i) {
    os << "\n " << std::setw(8) << i << ": sig: " << sig(i)
       << "; target: " << AsHex::Address(target(i))
       << "; implicit_arg: " << Brief(implicit_arg(i));
  }
  if (printed != len) os << "\n  [...]";
  os << "\n";
}

// Never called directly, as WasmFunctionData is an "abstract" class.
void WasmFunctionData::WasmFunctionDataPrint(std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << "\n - func_ref: " << Brief(func_ref());
  os << "\n - internal: " << Brief(internal());
  os << "\n - wrapper_code: " << Brief(wrapper_code(isolate));
  os << "\n - js_promise_flags: " << js_promise_flags();
  // No newline here; the caller prints it after printing additional fields.
}

void WasmExportedFunctionData::WasmExportedFunctionDataPrint(std::ostream& os) {
  PrintHeader(os, "WasmExportedFunctionData");
  WasmFunctionDataPrint(os);
  os << "\n - instance_data: " << Brief(instance_data());
  os << "\n - function_index: " << function_index();
  os << "\n - signature: " << reinterpret_cast<const void*>(sig());
  os << "\n - wrapper_budget: " << wrapper_budget()->value();
  os << "\n";
}

void WasmJSFunctionData::WasmJSFunctionDataPrint(std::ostream& os) {
  PrintHeader(os, "WasmJSFunctionData");
  WasmFunctionDataPrint(os);
  os << "\n - canonical_sig_index: " << canonical_sig_index();
  os << "\n";
}

void WasmResumeData::WasmResumeDataPrint(std::ostream& os) {
  PrintHeader(os, "WasmResumeData");
  os << "\n - suspender: " << Brief(suspender());
  os << '\n';
}

void WasmImportData::WasmImportDataPrint(std::ostream& os) {
  PrintHeader(os, "WasmImportData");
  os << "\n - native_context: " << Brief(native_context());
  os << "\n - callable: " << Brief(callable());
  os << "\n - instance_data: ";
  if (has_instance_data()) {
    os << Brief(instance_data());
  } else {
    os << "<empty>";
  }
  os << "\n - suspend: " << suspend();
  os << "\n - wrapper_budget: " << wrapper_budget();
  os << "\n - call_origin: " << Brief(call_origin());
  os << "\n - sig: " << sig() << " (" << sig()->parameter_count() << " params, "
     << sig()->return_count() << " returns)";
  os << "\n";
}

void WasmInternalFunction::WasmInternalFunctionPrint(std::ostream& os) {
  PrintHeader(os, "WasmInternalFunction");
  os << "\n - call target: " << reinterpret_cast<void*>(call_target());
  os << "\n - implicit arg: " << Brief(implicit_arg());
  os << "\n - external: " << Brief(external());
  os << "\n";
}

void WasmFuncRef::WasmFuncRefPrint(std::ostream& os) {
  PrintHeader(os, "WasmFuncRef");
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << "\n - internal: " << Brief(internal(isolate));
  os << "\n";
}

void WasmCapiFunctionData::WasmCapiFunctionDataPrint(std::ostream& os) {
  PrintHeader(os, "WasmCapiFunctionData");
  WasmFunctionDataPrint(os);
  os << "\n - canonical_sig_index: " << canonical_sig_index();
  os << "\n - embedder_data: " << Brief(embedder_data());
  os << "\n - sig: " << sig();
  os << "\n";
}

void WasmExceptionPackage::WasmExceptionPackagePrint(std::ostream& os) {
  PrintHeader(os, "WasmExceptionPackage");
  os << "\n";
}

void WasmModuleObject::WasmModuleObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmModuleObject");
  os << "\n - module: " << module();
  os << "\n - native module: " << native_module();
  os << "\n - script: " << Brief(script());
  os << "\n";
}

void WasmGlobalObject::WasmGlobalObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmGlobalObject");
  if (type().is_reference()) {
    os << "\n - tagged_buffer: " << Brief(tagged_buffer());
  } else {
    os << "\n - untagged_buffer: " << Brief(untagged_buffer());
  }
  os << "\n - offset: " << offset();
  os << "\n - raw_type: " << raw_type();
  os << "\n - is_mutable: " << is_mutable();
  os << "\n - type: " << type();
  os << "\n - is_mutable: " << is_mutable();
  os << "\n";
}

void WasmValueObject::WasmValueObjectPrint(std::ostream& os) {
  PrintHeader(os, "WasmValueObject");
  os << "\n - value: " << Brief(value());
  os << "\n";
}
#endif  // V8_ENABLE_WEBASSEMBLY

void LoadHandler::LoadHandlerPrint(std::ostream& os) {
  PrintHeader(os, "LoadHandler");
  // TODO(ishell): implement printing based on handler kind
  os << "\n - handler: " << Brief(smi_handler());
  os << "\n - validity_cell: " << Brief(validity_cell());
  int data_count = data_field_count();
  if (data_count >= 1) {
    os << "\n - data1: " << Brief(data1());
  }
  if (data_count >= 2) {
    os << "\n - data2: " << Brief(data2());
  }
  if (data_count >= 3) {
    os << "\n - data3: " << Brief(data3());
  }
  os << "\n";
}

void StoreHandler::StoreHandlerPrint(std::ostream& os) {
  PrintHeader(os, "StoreHandler");
  // TODO(ishell): implement printing based on handler kind
  os << "\n - handler: " << Brief(smi_handler());
  os << "\n - validity_cell: " << Brief(validity_cell());
  int data_count = data_field_count();
  if (data_count >= 1) {
    os << "\n - data1: " << Brief(data1());
  }
  if (data_count >= 2) {
    os << "\n - data2: " << Brief(data2());
  }
  if (data_count >= 3) {
    os << "\n - data3: " << Brief(data3());
  }
  os << "\n";
}

void AllocationSite::AllocationSitePrint(std::ostream& os) {
  PrintHeader(os, "AllocationSite");
  if (this->HasWeakNext()) os << "\n - weak_next: " << Brief(weak_next());
  os << "\n - dependent code: " << Brief(dependent_code());
  os << "\n - nested site: " << Brief(nested_site());
  os << "\n - memento found count: "
     << Brief(Smi::FromInt(memento_found_count()));
  os << "\n - memento create count: "
     << Brief(Smi::FromInt(memento_create_count()));
  os << "\n - pretenure decision: "
     << Brief(Smi::FromInt(pretenure_decision()));
  os << "\n - transition_info: ";
  if (!PointsToLiteral()) {
    ElementsKind kind = GetElementsKind();
    os << "Array allocation with ElementsKind " << ElementsKindToString(kind);
  } else if (IsJSArray(boilerplate())) {
    os << "Array literal with boilerplate " << Brief(boilerplate());
  } else {
    os << "Object literal with boilerplate " << Brief(boilerplate());
  }
  os << "\n";
}

void AllocationMemento::AllocationMementoPrint(std::ostream& os) {
  PrintHeader(os, "AllocationMemento");
  os << "\n - allocation site: ";
  if (IsValid()) {
    GetAllocationSite()->AllocationSitePrint(os);
  } else {
    os << "<invalid>\n";
  }
}

void ScriptOrModule::ScriptOrModulePrint(std::ostream& os) {
  PrintHeader(os, "ScriptOrModule");
  os << "\n - host_defined_options: " << Brief(host_defined_options());
  os << "\n - resource_name: " << Brief(resource_name());
}

void Script::ScriptPrint(std::ostream& os) {
  PrintHeader(os, "Script");
  os << "\n - source: " << Brief(source());
  os << "\n - name: " << Brief(name());
  os << "\n - line_offset: " << line_offset();
  os << "\n - column_offset: " << column_offset();
  os << "\n - context data: " << Brief(context_data());
  os << "\n - type: " << static_cast<int>(type());
  os << "\n - line ends: " << Brief(line_ends());
  if (!has_line_ends()) os << " (not set)";
  os << "\n - id: " << id();
  os << "\n - source_url: " << Brief(source_url());
  os << "\n - source_mapping_url: " << Brief(source_mapping_url());
  os << "\n - host_defined_options: " << Brief(host_defined_options());
  os << "\n - compilation type: " << static_cast<int>(compilation_type());
  os << "\n - compiled lazy function positions: "
     << compiled_lazy_function_positions();
  bool is_wasm = false;
#if V8_ENABLE_WEBASSEMBLY
  if ((is_wasm = (type() == Type::kWasm))) {
    if (has_wasm_breakpoint_infos()) {
      os << "\n - wasm_breakpoint_infos: " << Brief(wasm_breakpoint_infos());
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  if (!is_wasm) {
    if (has_eval_from_shared()) {
      os << "\n - eval from shared: " << Brief(eval_from_shared());
    } else if (is_wrapped()) {
      os << "\n - wrapped arguments: " << Brief(wrapped_arguments());
    }
    os << "\n - eval from position: " << eval_from_position();
  }
  os << "\n - infos: " << Brief(infos());
  os << "\n";
}

void JSTemporalPlainDate::JSTemporalPlainDatePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalPlainDate");
  JSObjectPrintBody(os, *this);
}

void JSTemporalPlainTime::JSTemporalPlainTimePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalPlainTime");
  JSObjectPrintBody(os, *this);
}

void JSTemporalPlainDateTime::JSTemporalPlainDateTimePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalPlainDateTime");
  JSObjectPrintBody(os, *this);
}

void JSTemporalZonedDateTime::JSTemporalZonedDateTimePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalZonedDateTime");
  JSObjectPrintBody(os, *this);
}

void JSTemporalDuration::JSTemporalDurationPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalDuration");
  JSObjectPrintBody(os, *this);
}

void JSTemporalInstant::JSTemporalInstantPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalInstant");
  JSObjectPrintBody(os, *this);
}

void JSTemporalPlainYearMonth::JSTemporalPlainYearMonthPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalPlainYearMonth");
  JSObjectPrintBody(os, *this);
}

void JSTemporalPlainMonthDay::JSTemporalPlainMonthDayPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalPlainMonthDay");
  JSObjectPrintBody(os, *this);
}

void JSTemporalTimeZone::JSTemporalTimeZonePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalTimeZone");
  JSObjectPrintBody(os, *this);
}

void JSTemporalCalendar::JSTemporalCalendarPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSTemporalCalendar");
  JSObjectPrintBody(os, *this);
}

void JSRawJson::JSRawJsonPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSRawJson");
  JSObjectPrintBody(os, *this);
}

#ifdef V8_INTL_SUPPORT
void JSV8BreakIterator::JSV8BreakIteratorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSV8BreakIterator");
  os << "\n - locale: " << Brief(locale());
  os << "\n - break iterator: " << Brief(break_iterator());
  os << "\n - unicode string: " << Brief(unicode_string());
  os << "\n - bound adopt text: " << Brief(bound_adopt_text());
  os << "\n - bound first: " << Brief(bound_first());
  os << "\n - bound next: " << Brief(bound_next());
  os << "\n - bound current: " << Brief(bound_current());
  os << "\n - bound break type: " << Brief(bound_break_type());
  os << "\n";
}

void JSCollator::JSCollatorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSCollator");
  os << "\n - icu collator: " << Brief(icu_collator());
  os << "\n - bound compare: " << Brief(bound_compare());
  JSObjectPrintBody(os, *this);
}

void JSDateTimeFormat::JSDateTimeFormatPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDateTimeFormat");
  os << "\n - locale: " << Brief(locale());
  os << "\n - icu locale: " << Brief(icu_locale());
  os << "\n - icu simple date format: " << Brief(icu_simple_date_format());
  os << "\n - icu date interval format: " << Brief(icu_date_interval_format());
  os << "\n - bound format: " << Brief(bound_format());
  os << "\n - hour cycle: " << HourCycleAsString();
  JSObjectPrintBody(os, *this);
}

void JSDisplayNames::JSDisplayNamesPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDisplayNames");
  os << "\n - internal: " << Brief(internal());
  os << "\n - style: " << StyleAsString();
  os << "\n - fallback: " << FallbackAsString();
  JSObjectPrintBody(os, *this);
}

void JSDurationFormat::JSDurationFormatPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDurationFormat");
  os << "\n - style_flags: " << style_flags();
  os << "\n - display_flags: " << display_flags();
  os << "\n - icu locale: " << Brief(icu_locale());
  os << "\n - icu number formatter: " << Brief(icu_number_formatter());
  JSObjectPrintBody(os, *this);
}

void JSListFormat::JSListFormatPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSListFormat");
  os << "\n - locale: " << Brief(locale());
  os << "\n - style: " << StyleAsString();
  os << "\n - type: " << TypeAsString();
  os << "\n - icu formatter: " << Brief(icu_formatter());
  JSObjectPrintBody(os, *this);
}

void JSLocale::JSLocalePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSLocale");
  os << "\n - icu locale: " << Brief(icu_locale());
  JSObjectPrintBody(os, *this);
}

void JSNumberFormat::JSNumberFormatPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSNumberFormat");
  os << "\n - locale: " << Brief(locale());
  os << "\n - icu_number_formatter: " << Brief(icu_number_formatter());
  os << "\n - bound_format: " << Brief(bound_format());
  JSObjectPrintBody(os, *this);
}

void JSPluralRules::JSPluralRulesPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSPluralRules");
  os << "\n - locale: " << Brief(locale());
  os << "\n - type: " << TypeAsString();
  os << "\n - icu plural rules: " << Brief(icu_plural_rules());
  os << "\n - icu_number_formatter: " << Brief(icu_number_formatter());
  JSObjectPrintBody(os, *this);
}

void JSRelativeTimeFormat::JSRelativeTimeFormatPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSRelativeTimeFormat");
  os << "\n - locale: " << Brief(locale());
  os << "\n - numberingSystem: " << Brief(numberingSystem());
  os << "\n - numeric: " << NumericAsString();
  os << "\n - icu formatter: " << Brief(icu_formatter());
  os << "\n";
}

void JSSegmentIterator::JSSegmentIteratorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSegmentIterator");
  os << "\n - icu break iterator: " << Brief(icu_break_iterator());
  os << "\n - granularity: " << GranularityAsString(GetIsolate());
  os << "\n";
}

void JSSegmenter::JSSegmenterPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSegmenter");
  os << "\n - locale: " << Brief(locale());
  os << "\n - granularity: " << GranularityAsString(GetIsolate());
  os << "\n - icu break iterator: " << Brief(icu_break_iterator());
  JSObjectPrintBody(os, *this);
}

void JSSegments::JSSegmentsPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSegments");
  os << "\n - icu break iterator: " << Brief(icu_break_iterator());
  os << "\n - unicode string: " << Brief(unicode_string());
  os << "\n - granularity: " << GranularityAsString(GetIsolate());
  JSObjectPrintBody(os, *this);
}
#endif  // V8_INTL_SUPPORT

namespace {
void PrintScopeInfoList(Tagged<ScopeInfo> scope_info, std::ostream& os,
                        const char* list_name, int length) {
  DisallowGarbageCollection no_gc;
  if (length <= 0) return;
  os << "\n - " << list_name;
  os << " {\n";
  for (auto it : ScopeInfo::IterateLocalNames(scope_info, no_gc)) {
    os << "    - " << it->index() << ": " << it->name() << "\n";
  }
  os << "  }";
}
}  // namespace

void ScopeInfo::ScopeInfoPrint(std::ostream& os) {
  PrintHeader(os, "ScopeInfo");
  if (this->IsEmpty()) {
    os << "\n - empty\n";
    return;
  }
  int flags = Flags();

  os << "\n - parameters: " << ParameterCount();
  os << "\n - context locals : " << ContextLocalCount();
  if (HasInlinedLocalNames()) {
    os << "\n - inlined local names";
  } else {
    os << "\n - local names in a hashtable: "
       << Brief(context_local_names_hashtable());
  }

  os << "\n - scope type: " << scope_type();
  if (SloppyEvalCanExtendVars()) {
    os << "\n - sloppy eval";
    os << "\n - dependent code: " << Brief(dependent_code());
  }
  os << "\n - language mode: " << language_mode();
  if (is_declaration_scope()) os << "\n - declaration scope";
  if (HasReceiver()) {
    os << "\n - receiver: " << ReceiverVariableBits::decode(flags);
  }
  if (ClassScopeHasPrivateBrand()) os << "\n - class scope has private brand";
  if (HasSavedClassVariable()) os << "\n - has saved class variable";
  if (HasNewTarget()) os << "\n - needs new target";
  if (HasFunctionName()) {
    os << "\n - function name(" << FunctionVariableBits::decode(flags) << "): ";
    ShortPrint(FunctionName(), os);
  }
  if (IsAsmModule()) os << "\n - asm module";
  if (HasSimpleParameters()) os << "\n - simple parameters";
  if (PrivateNameLookupSkipsOuterClass())
    os << "\n - private name lookup skips outer class";
  os << "\n - function kind: " << function_kind();
  if (HasOuterScopeInfo()) {
    os << "\n - outer scope info: " << Brief(OuterScopeInfo());
  }
  if (HasFunctionName()) {
    os << "\n - function name: " << Brief(FunctionName());
  }
  if (HasInferredFunctionName()) {
    os << "\n - inferred function name: " << Brief(InferredFunctionName());
  }
  if (HasContextExtensionSlot()) {
    os << "\n - has context extension slot";
  }

  if (HasPositionInfo()) {
    os << "\n - start position: " << StartPosition();
    os << "\n - end position: " << EndPosition();
  }
  os << "\n - length: " << length();
  if (length() > 0) {
    PrintScopeInfoList(*this, os, "context slots", ContextLocalCount());
    // TODO(neis): Print module stuff if present.
  }
  os << "\n";
}

void PreparseData::PreparseDataPrint(std::ostream& os) {
  PrintHeader(os, "PreparseData");
  os << "\n - data_length: " << data_length();
  os << "\n - children_length: " << children_length();
  if (data_length() > 0) {
    os << "\n - data-start: " << (address() + kDataStartOffset);
  }
  if (children_length() > 0) {
    os << "\n - children-start: " << inner_start_offset();
  }
  for (int i = 0; i < children_length(); ++i) {
    os << "\n - [" << i << "]: " << Brief(get_child(i));
  }
  os << "\n";
}

void HeapNumber::HeapNumberPrint(std::ostream& os) {
  PrintHeader(os, "HeapNumber");
  os << "\n - value: ";
  HeapNumberShortPrint(os);
  os << "\n";
}

#endif  // OBJECT_PRINT

void HeapObject::Print() { Print(*this); }

// static
void HeapObject::Print(Tagged<Object> obj) { v8::internal::Print(obj); }

// static
void HeapObject::Print(Tagged<Object> obj, std::ostream& os) {
  v8::internal::Print(obj, os);
}

void HeapObject::HeapObjectShortPrint(std::ostream& os) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  os << AsHex::Address(this->ptr()) << " ";

  if (IsString(*this, cage_base)) {
    HeapStringAllocator allocator;
    StringStream accumulator(&allocator);
    Cast<String>(*this)->StringShortPrint(&accumulator);
    os << accumulator.ToCString().get();
    return;
  }
  if (IsJSObject(*this, cage_base)) {
    HeapStringAllocator allocator;
    StringStream accumulator(&allocator);
    Cast<JSObject>(*this)->JSObjectShortPrint(&accumulator);
    os << accumulator.ToCString().get();
    return;
  }
  switch (map(cage_base)->instance_type()) {
    case MAP_TYPE: {
      Tagged<Map> map = Cast<Map>(*this);
      if (map->instance_type() == MAP_TYPE) {
        // This is one of the meta maps, print only relevant fields.
        os << "<MetaMap (" << Brief(map->native_context_or_null()) << ")>";
      } else {
        os << "<Map";
        if (map->instance_size() != kVariableSizeSentinel) {
          os << "[" << map->instance_size() << "]";
        }
        os << "(";
        if (IsJSObjectMap(map)) {
          os << ElementsKindToString(map->elements_kind());
        } else {
          os << map->instance_type();
        }
        os << ")>";
      }
    } break;
    case AWAIT_CONTEXT_TYPE: {
      os << "<AwaitContext generator= ";
      HeapStringAllocator allocator;
      StringStream accumulator(&allocator);
      ShortPrint(Cast<Context>(*this)->extension(), &accumulator);
      os << accumulator.ToCString().get();
      os << '>';
      break;
    }
    case BLOCK_CONTEXT_TYPE:
      os << "<BlockContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case CATCH_CONTEXT_TYPE:
      os << "<CatchContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case DEBUG_EVALUATE_CONTEXT_TYPE:
      os << "<DebugEvaluateContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case EVAL_CONTEXT_TYPE:
      os << "<EvalContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case FUNCTION_CONTEXT_TYPE:
      os << "<FunctionContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case MODULE_CONTEXT_TYPE:
      os << "<ModuleContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case NATIVE_CONTEXT_TYPE:
      os << "<NativeContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case SCRIPT_CONTEXT_TYPE:
      os << "<ScriptContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case WITH_CONTEXT_TYPE:
      os << "<WithContext[" << Cast<Context>(*this)->length() << "]>";
      break;
    case SCRIPT_CONTEXT_TABLE_TYPE:
      os << "<ScriptContextTable["
         << Cast<ScriptContextTable>(*this)->capacity() << "]>";
      break;
    case HASH_TABLE_TYPE:
      os << "<HashTable[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case ORDERED_HASH_MAP_TYPE:
      os << "<OrderedHashMap[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case ORDERED_HASH_SET_TYPE:
      os << "<OrderedHashSet[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case ORDERED_NAME_DICTIONARY_TYPE:
      os << "<OrderedNameDictionary[" << Cast<FixedArray>(*this)->length()
         << "]>";
      break;
    case NAME_DICTIONARY_TYPE:
      os << "<NameDictionary[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case SWISS_NAME_DICTIONARY_TYPE:
      os << "<SwissNameDictionary["
         << Cast<SwissNameDictionary>(*this)->Capacity() << "]>";
      break;
    case GLOBAL_DICTIONARY_TYPE:
      os << "<GlobalDictionary[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case NUMBER_DICTIONARY_TYPE:
      os << "<NumberDictionary[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      os << "<SimpleNumberDictionary[" << Cast<FixedArray>(*this)->length()
         << "]>";
      break;
    case FIXED_ARRAY_TYPE:
      os << "<FixedArray[" << Cast<FixedArray>(*this)->length() << "]>";
      break;
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
      os << "<ObjectBoilerplateDescription["
         << Cast<ObjectBoilerplateDescription>(*this)->capacity() << "]>";
      break;
    case FIXED_DOUBLE_ARRAY_TYPE:
      os << "<FixedDoubleArray[" << Cast<FixedDoubleArray>(*this)->length()
         << "]>";
      break;
    case BYTE_ARRAY_TYPE:
      os << "<ByteArray[" << Cast<ByteArray>(*this)->length() << "]>";
      break;
    case BYTECODE_ARRAY_TYPE:
      os << "<BytecodeArray[" << Cast<BytecodeArray>(*this)->length() << "]>";
      break;
    case DESCRIPTOR_ARRAY_TYPE:
      os << "<DescriptorArray["
         << Cast<DescriptorArray>(*this)->number_of_descriptors() << "]>";
      break;
    case WEAK_FIXED_ARRAY_TYPE:
      os << "<WeakFixedArray[" << Cast<WeakFixedArray>(*this)->length() << "]>";
      break;
    case TRANSITION_ARRAY_TYPE:
      os << "<TransitionArray[" << Cast<TransitionArray>(*this)->length()
         << "]>";
      break;
    case PROPERTY_ARRAY_TYPE:
      os << "<PropertyArray[" << Cast<PropertyArray>(*this)->length() << "]>";
      break;
    case FEEDBACK_CELL_TYPE: {
      {
        ReadOnlyRoots roots = GetReadOnlyRoots();
        os << "<FeedbackCell[";
        if (map() == roots.no_closures_cell_map()) {
          os << "no feedback";
        } else if (map() == roots.one_closure_cell_map()) {
          os << "one closure";
        } else if (map() == roots.many_closures_cell_map()) {
          os << "many closures";
        } else {
          os << "!!!INVALID MAP!!!";
        }
        os << "]>";
      }
      break;
    }
    case CLOSURE_FEEDBACK_CELL_ARRAY_TYPE:
      os << "<ClosureFeedbackCellArray["
         << Cast<ClosureFeedbackCellArray>(*this)->length() << "]>";
      break;
    case FEEDBACK_VECTOR_TYPE:
      os << "<FeedbackVector[" << Cast<FeedbackVector>(*this)->length() << "]>";
      break;
    case FREE_SPACE_TYPE:
      os << "<FreeSpace[" << Cast<FreeSpace>(*this)->size(kRelaxedLoad) << "]>";
      break;

    case PREPARSE_DATA_TYPE: {
      Tagged<PreparseData> data = Cast<PreparseData>(*this);
      os << "<PreparseData[data=" << data->data_length()
         << " children=" << data->children_length() << "]>";
      break;
    }

    case UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_TYPE: {
      Tagged<UncompiledDataWithoutPreparseData> data =
          Cast<UncompiledDataWithoutPreparseData>(*this);
      os << "<UncompiledDataWithoutPreparseData (" << data->start_position()
         << ", " << data->end_position() << ")]>";
      break;
    }

    case UNCOMPILED_DATA_WITH_PREPARSE_DATA_TYPE: {
      Tagged<UncompiledDataWithPreparseData> data =
          Cast<UncompiledDataWithPreparseData>(*this);
      os << "<UncompiledDataWithPreparseData (" << data->start_position()
         << ", " << data->end_position()
         << ") preparsed=" << Brief(data->preparse_data()) << ">";
      break;
    }

    case SHARED_FUNCTION_INFO_TYPE: {
      Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(*this);
      std::unique_ptr<char[]> debug_name = shared->DebugNameCStr();
      if (debug_name[0] != '\0') {
        os << "<SharedFunctionInfo " << debug_name.get() << ">";
      } else {
        os << "<SharedFunctionInfo>";
      }
      break;
    }
    case JS_MESSAGE_OBJECT_TYPE:
      os << "<JSMessageObject>";
      break;
#define MAKE_STRUCT_CASE(TYPE, Name, name)    \
  case TYPE:                                  \
    os << "<" #Name;                          \
    Cast<Name>(*this)->BriefPrintDetails(os); \
    os << ">";                                \
    break;
      STRUCT_LIST(MAKE_STRUCT_CASE)
#undef MAKE_STRUCT_CASE
    case ALLOCATION_SITE_TYPE: {
      os << "<AllocationSite";
      Cast<AllocationSite>(*this)->BriefPrintDetails(os);
      os << ">";
      break;
    }
    case SCOPE_INFO_TYPE: {
      Tagged<ScopeInfo> scope = Cast<ScopeInfo>(*this);
      os << "<ScopeInfo";
      if (!scope->IsEmpty()) os << " " << scope->scope_type();
      os << ">";
      break;
    }
    case CODE_TYPE: {
      Tagged<Code> code = Cast<Code>(*this);
      os << "<Code " << CodeKindToString(code->kind());
      if (code->is_builtin()) {
        os << " " << Builtins::name(code->builtin_id());
      }
      os << ">";
      break;
    }
    case HOLE_TYPE: {
#define PRINT_HOLE(Type, Value, _) \
  if (Is##Type(*this)) {           \
    os << "<" #Value ">";          \
    break;                         \
  }
      HOLE_LIST(PRINT_HOLE)
#undef PRINT_HOLE
      UNREACHABLE();
    }
    case INSTRUCTION_STREAM_TYPE: {
      Tagged<InstructionStream> istream = Cast<InstructionStream>(*this);
      Tagged<Code> code = istream->code(kAcquireLoad);
      os << "<InstructionStream " << CodeKindToString(code->kind());
      if (code->is_builtin()) {
        os << " " << Builtins::name(code->builtin_id());
      }
      os << ">";
      break;
    }
    case ODDBALL_TYPE: {
      if (IsUndefined(*this)) {
        os << "<undefined>";
      } else if (IsNull(*this)) {
        os << "<null>";
      } else if (IsTrue(*this)) {
        os << "<true>";
      } else if (IsFalse(*this)) {
        os << "<false>";
      } else {
        os << "<Odd Oddball: ";
        os << Cast<Oddball>(*this)->to_string()->ToCString().get();
        os << ">";
      }
      break;
    }
    case SYMBOL_TYPE: {
      Tagged<Symbol> symbol = Cast<Symbol>(*this);
      symbol->SymbolShortPrint(os);
      break;
    }
    case HEAP_NUMBER_TYPE: {
      os << "<HeapNumber ";
      Cast<HeapNumber>(*this)->HeapNumberShortPrint(os);
      os << ">";
      break;
    }
    case BIGINT_TYPE: {
      os << "<BigInt ";
      Cast<BigInt>(*this)->BigIntShortPrint(os);
      os << ">";
      break;
    }
    case JS_PROXY_TYPE:
      os << "<JSProxy>";
      break;
    case FOREIGN_TYPE:
      os << "<Foreign>";
      break;
    case CELL_TYPE: {
      os << "<Cell value= ";
      HeapStringAllocator allocator;
      StringStream accumulator(&allocator);
      ShortPrint(Cast<Cell>(*this)->value(), &accumulator);
      os << accumulator.ToCString().get();
      os << '>';
      break;
    }
    case PROPERTY_CELL_TYPE: {
      Tagged<PropertyCell> cell = Cast<PropertyCell>(*this);
      os << "<PropertyCell name=";
      ShortPrint(cell->name(), os);
      os << " value=";
      HeapStringAllocator allocator;
      StringStream accumulator(&allocator);
      ShortPrint(cell->value(kAcquireLoad), &accumulator);
      os << accumulator.ToCString().get();
      os << '>';
      break;
    }
    case CONTEXT_SIDE_PROPERTY_CELL_TYPE: {
      os << "<ContextSidePropertyCell>";
      break;
    }
    case ACCESSOR_INFO_TYPE: {
      Tagged<AccessorInfo> info = Cast<AccessorInfo>(*this);
      os << "<AccessorInfo ";
      os << "name= " << Brief(info->name());
      os << ", data= " << Brief(info->data());
      os << ">";
      break;
    }
    case FUNCTION_TEMPLATE_INFO_TYPE: {
      Tagged<FunctionTemplateInfo> info = Cast<FunctionTemplateInfo>(*this);
      os << "<FunctionTemplateInfo ";
      Isolate* isolate;
      if (GetIsolateFromHeapObject(*this, &isolate)) {
        os << "callback= " << reinterpret_cast<void*>(info->callback(isolate));
      } else {
        os << "callback= " << kUnavailableString;
      }
      os << ", data= " << Brief(info->callback_data(kAcquireLoad));
      os << ", has_side_effects= ";
      if (info->has_side_effects()) {
        os << "true>";
      } else {
        os << "false>";
      }
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case WASM_DISPATCH_TABLE_TYPE:
      os << "<WasmDispatchTable[" << Cast<WasmDispatchTable>(*this)->length()
         << "]>";
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      os << "<Other heap object (" << map()->instance_type() << ")>";
      break;
  }
}

void HeapNumber::HeapNumberShortPrint(std::ostream& os) {
  static constexpr uint64_t kUint64AllBitsSet =
      static_cast<uint64_t>(int64_t{-1});
  // Min/max integer values representable by 52 bits of mantissa and 1 sign bit.
  static constexpr int64_t kMinSafeInteger =
      static_cast<int64_t>(kUint64AllBitsSet << 53);
  static constexpr int64_t kMaxSafeInteger = -(kMinSafeInteger + 1);

  double val = value();
  if (i::IsMinusZero(val)) {
    os << "-0.0";
  } else if (val == DoubleToInteger(val) &&
             val >= static_cast<double>(kMinSafeInteger) &&
             val <= static_cast<double>(kMaxSafeInteger)) {
    // Print integer HeapNumbers in safe integer range with max precision: as
    // 9007199254740991.0 instead of 9.0072e+15
    int64_t i = static_cast<int64_t>(val);
    os << i << ".0";
  } else {
    os << val;
  }
}

// TODO(cbruni): remove once the new maptracer is in place.
void Name::NameShortPrint() {
  if (IsString(this)) {
    PrintF("%s", Cast<String>(this)->ToCString().get());
  } else {
    DCHECK(IsSymbol(this));
    Tagged<Symbol> s = Cast<Symbol>(this);
    if (IsUndefined(s->description())) {
      PrintF("#<%s>", s->PrivateSymbolToName());
    } else {
      PrintF("<%s>", Cast<String>(s->description())->ToCString().get());
    }
  }
}

// TODO(cbruni): remove once the new maptracer is in place.
int Name::NameShortPrint(base::Vector<char> str) {
  if (IsString(this)) {
    return SNPrintF(str, "%s", Cast<String>(this)->ToCString().get());
  } else {
    DCHECK(IsSymbol(this));
    Tagged<Symbol> s = Cast<Symbol>(this);
    if (IsUndefined(s->description())) {
      return SNPrintF(str, "#<%s>", s->PrivateSymbolToName());
    } else {
      return SNPrintF(str, "<%s>",
                      Cast<String>(s->description())->ToCString().get());
    }
  }
}

void Symbol::SymbolShortPrint(std::ostream& os) {
  os << "<Symbol:";
  if (!IsUndefined(description())) {
    os << " ";
    Tagged<String> description_as_string = Cast<String>(description());
    description_as_string->PrintUC16(os, 0, description_as_string->length());
  } else {
    os << " (" << PrivateSymbolToName() << ")";
  }
  os << ">";
}

void Map::PrintMapDetails(std::ostream& os) {
  DisallowGarbageCollection no_gc;
  this->MapPrint(os);
  instance_descriptors()->PrintDescriptors(os);
}

void Map::MapPrint(std::ostream& os) {
  bool is_meta_map = instance_type() == MAP_TYPE;
#ifdef OBJECT_PRINT
  PrintHeader(os, is_meta_map ? "MetaMap" : "Map");
#else
  os << (is_meta_map ? "MetaMap=" : "Map=") << reinterpret_cast<void*>(ptr());
#endif
  os << "\n - type: " << instance_type();
  os << "\n - instance size: ";
  if (instance_size() == kVariableSizeSentinel) {
    os << "variable";
  } else {
    os << instance_size();
  }
  if (is_meta_map) {
    // This is one of the meta maps, print only relevant fields.
    os << "\n - native_context: " << Brief(native_context_or_null());
    os << "\n";
    return;
  }

  if (IsJSObjectMap(*this)) {
    os << "\n - inobject properties: " << GetInObjectProperties();
    os << "\n - unused property fields: " << UnusedPropertyFields();
  }
  os << "\n - elements kind: " << ElementsKindToString(elements_kind());
```