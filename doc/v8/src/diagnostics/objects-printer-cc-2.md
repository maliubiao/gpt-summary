Response:
The user wants a summary of the provided C++ code snippet. The snippet is part of the `objects-printer.cc` file in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:**  The code consists of numerous functions named like `JS<Something>Print`. This strongly suggests the purpose is to *print* information about various V8 internal objects. The `std::ostream& os` parameter in each function reinforces this.

2. **Recognize the Pattern:**  Each `...Print` function generally follows a pattern:
    * Call `JSObjectPrintHeader` to print the object's basic information and type.
    * Print specific fields of the object with labels, often using `Brief()` to get a concise representation.
    * Call `JSObjectPrintBody` to print further details (likely inherited or common).

3. **Determine the Scope:**  The filename `objects-printer.cc` and the object types (e.g., `JSSetIterator`, `JSWeakRef`, `JSFunction`, `JSArrayBuffer`) indicate this code is responsible for *debugging and inspection* of V8's internal object representation. It's not directly involved in JavaScript execution logic.

4. **Address Specific Instructions:**

    * **".tq" Check:** The code ends in ".cc", not ".tq". This is a straightforward check.
    * **JavaScript Relationship:** While not directly *executing* JavaScript, this code prints information about JavaScript objects. Need to demonstrate this link. A simple JavaScript example creating a few of the mentioned objects and explaining how this printer could be used in a debugger scenario is a good approach.
    * **Code Logic Inference:**  The code is mostly about printing, not complex logic. However, the `JSFinalizationRegistryPrint` function has a loop iterating through linked lists (`active_cells`, `cleared_cells`). This presents an opportunity for a simple input/output example.
    * **Common Programming Errors:**  Since this code deals with internal objects, the "common programming errors" would likely be related to misusing or misunderstanding these concepts when working with the V8 API or embedding V8. Examples like forgetting to detach `ArrayBuffer` or not handling weak references correctly are relevant.
    * **Part Number:**  Acknowledge that this is part 3 of 5.
    * **Overall Functionality (the main request):**  Summarize the identified core functionality in a concise way.

5. **Structure the Answer:**  Organize the information logically following the user's request. Start with the main functionality, then address each specific point. Use clear headings and formatting.

6. **Refine the Examples:** Ensure the JavaScript and logic examples are simple and easy to understand, focusing on the connection to the C++ code. For the logic example, choose simple scenarios for the linked lists. For the programming errors, select common pitfalls related to the object types being printed.

7. **Review and Verify:**  Read through the generated answer to ensure it's accurate, addresses all parts of the prompt, and is easy to understand. Double-check the file extension and the overall purpose of the code.

By following these steps, we can arrive at a comprehensive and accurate answer that addresses all aspects of the user's request.
```cpp
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
  os
}
```

## v8/src/diagnostics/objects-printer.cc 的功能 (第 3 部分)

这段代码是 V8 引擎的调试工具的一部分，它专注于以可读的格式打印 V8 堆中各种 JavaScript 对象的内部状态信息。  每个以 `...Print` 结尾的函数都负责打印特定类型的 V8 对象。

**具体功能归纳:**

这段代码定义了多个用于打印特定 V8 内部对象状态的函数。 这些函数的主要目的是为了在调试 V8 引擎时，能够方便地查看和理解各种对象的内部结构和数据。

以下是这段代码中涉及的 V8 对象类型及其打印功能的概括：

* **`JSSetIterator` 和 `JSMapIterator`**:  打印 Set 和 Map 迭代器的信息。
* **`JSWeakRef`**: 打印弱引用的目标对象。
* **`JSShadowRealm`**: 打印 Shadow Realm 的原生上下文。
* **`JSWrappedFunction`**: 打印包装函数的原始目标函数。
* **`JSFinalizationRegistry`**: 打印 FinalizationRegistry 的原生上下文、清理函数、活跃和已清除的单元格以及键映射。
* **`JSSharedArray` 和 `JSSharedStruct`**: 打印共享数组和共享结构体的隔离区信息。
* **`JSAtomicsMutex` 和 `JSAtomicsCondition`**: 打印原子互斥锁和条件变量的状态和拥有线程 ID。
* **`JSDisposableStackBase` 和 `JSAsyncDisposableStack`**: 打印可清理的栈的状态，包括长度、当前状态、错误信息等。
* **`JSIteratorMapHelper`, `JSIteratorFilterHelper`, `JSIteratorTakeHelper`, `JSIteratorDropHelper`, `JSIteratorFlatMapHelper`**: 打印各种迭代器辅助对象的状态，例如映射函数、谓词、剩余数量等。
* **`JSWeakMap` 和 `JSWeakSet`**: 打印弱映射和弱集合的内部哈希表。
* **`JSArrayBuffer`**: 打印 ArrayBuffer 的底层存储、长度、是否共享、是否可分离等信息。
* **`JSTypedArray`**: 打印类型化数组的缓冲区、偏移量、长度、数据指针等信息。
* **`JSArrayIterator`**: 打印数组迭代器的迭代对象、当前索引和迭代类型。
* **`JSDataView` 和 `JSRabGsabDataView`**: 打印 DataView 的缓冲区、偏移量和长度信息。
* **`JSBoundFunction`**: 打印绑定函数的原始目标函数、绑定的 `this` 值和参数。
* **`JSFunction`**:  打印函数的原型、共享信息、名称、内置函数信息、参数数量、上下文、代码以及可能的反馈向量信息。
* **`SharedFunctionInfo`**: 打印共享函数信息，包括名称、推断名称、种类、参数数量、源代码、脚本信息、作用域信息和反馈元数据。
* **`SharedFunctionInfoWrapper`**: 打印 `SharedFunctionInfoWrapper` 包含的 `SharedFunctionInfo`。
* **`JSGlobalProxy` 和 `JSGlobalObject`**: 打印全局代理和全局对象的信息。
* **`PropertyCell` 和 `ContextSidePropertyCell`**: 打印属性单元和上下文侧属性单元的名称、值和详细信息。
* **`InstructionStream` 和 `Code`**: 打印指令流和代码对象的各种属性，包括代码种类、是否为内置函数、反优化数据、位置表、参数数量、指令起始地址、是否经过 TurboFan 优化、栈槽数量、是否标记为反优化、指令大小以及反汇编代码（如果启用）。
* **`CodeWrapper`**: 打印 `CodeWrapper` 包含的代码对象。
* **`Foreign` 和 `TrustedForeign`**: 打印指向外部内存地址的指针。
* **`AsyncGeneratorRequest`**: 打印异步生成器请求的恢复模式和值。
* **`Module` (及其子类 `SourceTextModule` 和 `SyntheticModule`) 和 `JSModuleNamespace`**: 打印模块及其命名空间的导出、状态、异常、源代码、请求的模块以及导入的元数据。
* **`PrototypeInfo`**: 打印原型信息，包括模块命名空间、原型用户和派生映射。
* **`ArrayBoilerplateDescription`**: 打印数组样板描述，包括元素种类和常量元素。
* **WebAssembly 相关对象 (`AsmWasmData`, `WasmTypeInfo`, `WasmStruct`, `WasmArray`, `WasmContinuationObject`, `WasmSuspenderObject`, `WasmSuspendingObject`, `WasmInstanceObject`, `WasmTrustedInstanceData`, `WasmDispatchTable`):** 打印各种 WebAssembly 相关的对象信息，例如本地模块、类型地址、结构体字段、数组元素、延续对象、挂起对象、实例对象、可信实例数据和分发表格。

**关于文件类型和 JavaScript 关系：**

* **文件类型:** `v8/src/diagnostics/objects-printer.cc` 以 `.cc` 结尾，因此它是 **C++** 源代码，而不是 Torque 源代码。
* **JavaScript 关系:**  虽然 `objects-printer.cc` 是 C++ 代码，但它的功能 **与 JavaScript 的功能密切相关**。它用于检查和调试 V8 引擎内部表示的 JavaScript 对象。

**JavaScript 示例：**

```javascript
const set = new Set([1, 2, 3]);
const map = new Map([['a', 1], ['b', 2]]);
const weakRef = new WeakRef({});
const finalRegistry = new FinalizationRegistry(() => {});
const sharedArray = new SharedArrayBuffer(1024);
const typedArray = new Uint8Array(10);
const buffer = new ArrayBuffer(16);
const dataView = new DataView(buffer);
const boundFunction = function(y) { console.log(this.x + y); }.bind({ x: 10 });
function normalFunction(a) { return a * 2; }

// 这些 JavaScript 对象在 V8 引擎内部会被表示为不同的 C++ 对象。
// objects-printer.cc 中的函数可以打印这些内部对象的状态。

// 例如，如果我们在 V8 调试器中，并且有一个指向 'set' 变量内部表示的指针，
// 那么可能会调用 `JSSet::JSSetPrint(std::ostream& os)` 来查看其内容。
```

**代码逻辑推理示例：**

以 `JSFinalizationRegistry::JSFinalizationRegistryPrint` 为例：

**假设输入：**

一个 `JSFinalizationRegistry` 对象，其 `active_cells` 链表中包含两个 `WeakCell` 对象，`cleared_cells` 链表为空。

**输出：**

```
[0x...] JSFinalizationRegistry
 - native_context: [0x...]
 - cleanup: [0x...]
 - active_cells: [0x...]
   - [0x...]
   - [0x...]
 - cleared_cells: [0x...]
 - key_map: [0x...]
[0x...] JSObject
```

这里会打印出 `active_cells` 链表中的每个 `WeakCell` 的地址。

**用户常见的编程错误示例：**

这段代码本身不直接涉及用户编写的 JavaScript 代码的执行，而是用于调试 V8 引擎内部。然而，它揭示了 V8 内部的一些机制，理解这些机制可以帮助避免一些编程错误。

例如，观察 `JSArrayBufferPrint` 可以看到 `ArrayBuffer` 有 `detached` 状态。 如果用户在 `ArrayBuffer` 被分离后尝试访问它，就会导致运行时错误。

```javascript
const buffer = new ArrayBuffer(10);
const view = new Uint8Array(buffer);
// ... 使用 view ...
buffer.detach(); // 分离 ArrayBuffer
// view[0] = 1; // 错误: Cannot perform操作 on detached ArrayBuffer
```

另一个例子是 `JSWeakRefPrint`。 如果用户依赖 `WeakRef` 指向的对象总是存在，可能会导致意外的行为，因为垃圾回收器可能会在任何时候回收弱引用指向的对象。

```javascript
let obj = { data: 123 };
const weakRef = new WeakRef(obj);

// ... 一段时间后 ...

const derefObj = weakRef.deref();
if (derefObj) {
  console.log(derefObj.data);
} else {
  console.log("对象已被回收");
}
```

**归纳一下它的功能 (第 3 部分):**

作为 `objects-printer.cc` 的一部分，这段代码（第 3 部分）延续了其核心功能，即提供了一系列用于打印 V8 堆中各种 JavaScript 对象详细内部状态的 C++ 函数。 这些函数覆盖了包括迭代器、弱引用、FinalizationRegistry、共享内存、原子操作、可清理资源、各种迭代器辅助类、弱集合和映射、不同类型的数组、绑定函数、普通函数、共享函数信息以及全局对象等多种重要的 JavaScript 概念在 V8 内部的表示。  这段代码是 V8 引擎开发人员和调试人员用于理解和诊断 V8 内部行为的关键工具。

Prompt: 
```
这是目录为v8/src/diagnostics/objects-printer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/objects-printer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
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
  os
"""


```