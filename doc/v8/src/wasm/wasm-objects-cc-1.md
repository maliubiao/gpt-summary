Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet from `v8/src/wasm/wasm-objects.cc`.

Here's a breakdown of the code's functions and their roles:

1. **`SetInstanceMemory`**:  This function updates the memory details within the `WasmTrustedInstanceData` object, linking it to a specific `JSArrayBuffer`. It performs various checks to ensure memory safety and integrity.

2. **`WasmMemoryObject::New` (two overloads)**: These functions are responsible for creating new `WasmMemoryObject` instances. They handle the allocation of the underlying `JSArrayBuffer`, manage shared memory, and store debugging information.

3. **`WasmMemoryObject::UseInInstance`**:  This function associates a `WasmMemoryObject` with a `WasmInstanceObject` by storing the buffer information in the instance's trusted data and maintaining a list of instances using this memory.

4. **`WasmMemoryObject::SetNewBuffer`**:  When a memory needs to be reallocated (e.g., due to `memory.grow`), this function updates all associated `WasmInstanceObject`s with the new `JSArrayBuffer`.

5. **`WasmMemoryObject::Grow`**: This is the core logic for the `memory.grow` operation in WebAssembly. It attempts to grow the underlying `JSArrayBuffer`, handling both in-place growth and allocation of a new buffer with copying. It also manages shared memory growth and adheres to memory limits.

6. **`WasmGlobalObject::New`**: Creates new `WasmGlobalObject` instances, which represent global variables in WebAssembly. It handles both typed values and reference types, allocating appropriate storage.

7. **`FunctionTargetAndImplicitArg::FunctionTargetAndImplicitArg`**: This constructor prepares the necessary information for calling a WebAssembly function, including the target instance and function index. It handles both imported and non-imported functions.

8. **`ImportedFunctionEntry::SetGenericWasmToJs`**:  Sets up an import entry for calling a JavaScript function from WebAssembly, using a generic wrapper.

9. **`ImportedFunctionEntry::SetCompiledWasmToJs`**: Sets up an import entry for calling a JavaScript function from WebAssembly, using a compiled (optimized) wrapper.

10. **`ImportedFunctionEntry::SetWasmToWasm`**: Sets up an import entry for calling another WebAssembly function.

11. **`ImportedFunctionEntry::maybe_callable`, `ImportedFunctionEntry::callable`, `ImportedFunctionEntry::implicit_arg`, `ImportedFunctionEntry::target`, `ImportedFunctionEntry::function_index_in_called_module`**: Accessor methods to retrieve information from an import entry.

12. **`WasmTrustedInstanceData::EnsureMinimumDispatchTableSize`**: Ensures that a dispatch table within `WasmTrustedInstanceData` has at least a certain size, growing it if necessary.

13. **`WasmTrustedInstanceData::SetRawMemory`**:  Directly sets the raw memory base address and size within the `WasmTrustedInstanceData`.

14. **`WasmTrustedInstanceData::GetOrCreateInterpreterObject`, `WasmTrustedInstanceData::GetInterpreterObject`**:  Functions related to accessing the interpreter object for a WebAssembly instance (used in jitless mode).

15. **`WasmTrustedInstanceData::New`**: Creates a new `WasmTrustedInstanceData` object, which holds the runtime state for a WebAssembly instance. It allocates various internal data structures, including dispatch tables, memory information, and global variable storage.

16. **`WasmTrustedInstanceData::InitDataSegmentArrays`**: Initializes the data segment arrays within `WasmTrustedInstanceData`.

Considering the request's structure, I will focus on summarizing the functionalities presented in this specific code block, paying attention to the instructions provided.
这是V8源代码文件 `v8/src/wasm/wasm-objects.cc` 的一部分，主要负责 **管理和操作 WebAssembly 的运行时对象**。它定义了与 WebAssembly 内存 (`WasmMemoryObject`)、全局变量 (`WasmGlobalObject`) 和函数调用 (`ImportedFunctionEntry`, `FunctionTargetAndImplicitArg`) 相关的类和方法，并涉及到 WebAssembly 实例数据的管理 (`WasmTrustedInstanceData`)。

以下是对这段代码功能的归纳：

**核心功能：WebAssembly 运行时对象管理**

这段代码主要负责创建、初始化、使用和管理以下 WebAssembly 相关的运行时对象：

1. **WasmMemoryObject (WebAssembly 内存对象):**
    *   **创建新的 `WasmMemoryObject`:**  `WasmMemoryObject::New` 函数负责创建新的 WebAssembly 内存对象，它会关联一个 `JSArrayBuffer` 来存储实际的内存数据。它可以创建固定大小或可增长的内存，并处理共享内存的情况。
    *   **在实例中使用内存:** `WasmMemoryObject::UseInInstance` 函数将一个 `WasmMemoryObject` 与一个 `WasmInstanceObject` 关联起来，以便该实例可以访问和操作这块内存。
    *   **设置新的内存 buffer:** `WasmMemoryObject::SetNewBuffer` 函数在内存增长时，更新所有引用该内存的 `WasmInstanceObject`，确保它们指向新的 `JSArrayBuffer`。
    *   **增长内存:** `WasmMemoryObject::Grow` 函数实现了 WebAssembly 的 `memory.grow` 操作。它可以尝试在原地扩展内存，如果失败则会分配新的内存并复制数据。它还会处理共享内存的增长情况。

2. **WasmGlobalObject (WebAssembly 全局变量对象):**
    *   **创建新的 `WasmGlobalObject`:** `WasmGlobalObject::New` 函数用于创建表示 WebAssembly 全局变量的对象。它可以关联一个 `JSArrayBuffer` (用于存储值类型) 或一个 `FixedArray` (用于存储引用类型)。

3. **函数调用相关:**
    *   **`FunctionTargetAndImplicitArg`:**  用于存储函数调用的目标信息，包括目标实例和函数索引。
    *   **`ImportedFunctionEntry`:**  用于表示导入的函数，可以指向 JavaScript 函数 (`SetGenericWasmToJs`, `SetCompiledWasmToJs`) 或其他的 WebAssembly 函数 (`SetWasmToWasm`)。它还提供了访问导入函数信息的接口。

4. **WasmTrustedInstanceData (WebAssembly 受信任实例数据):**
    *   **创建新的 `WasmTrustedInstanceData`:** `WasmTrustedInstanceData::New` 函数负责创建存储 WebAssembly 实例运行时状态的受信任数据对象。这包括内存、全局变量、导入函数表等信息。
    *   **设置原始内存:** `WasmTrustedInstanceData::SetRawMemory` 函数直接设置实例中指定内存的起始地址和大小。
    *   **确保最小调度表大小:** `WasmTrustedInstanceData::EnsureMinimumDispatchTableSize` 确保导入函数调度表有足够的空间。
    *   **获取或创建解释器对象:** `WasmTrustedInstanceData::GetOrCreateInterpreterObject` 和 `WasmTrustedInstanceData::GetInterpreterObject` 用于获取与实例关联的解释器对象（在无 JIT 模式下使用）。
    *   **初始化数据段数组:** `WasmTrustedInstanceData::InitDataSegmentArrays` 初始化用于存储数据段的数组。

**与其他概念的关系：**

*   **JSArrayBuffer:**  `WasmMemoryObject` 内部使用 `JSArrayBuffer` 来存储实际的 WebAssembly 内存数据。
*   **WasmInstanceObject:**  `WasmMemoryObject` 和 `WasmGlobalObject` 都与 `WasmInstanceObject` 关联，表示它们属于哪个 WebAssembly 实例。
*   **WasmModuleObject:**  `WasmTrustedInstanceData` 持有一个指向 `WasmModuleObject` 的指针，表示该实例是基于哪个模块创建的。
*   **NativeModule:**  `WasmTrustedInstanceData` 内部包含了对 `NativeModule` 的受信任管理指针，用于访问编译后的代码和其他模块级信息。

**代码逻辑推理示例：**

假设我们有一个 WebAssembly 模块定义了一个初始大小为 1 页，最大大小为 10 页的内存。

**输入:**

*   `isolate`: 当前 V8 隔离对象。
*   `initial = 1` (初始页数)
*   `maximum = 10` (最大页数)
*   `shared = SharedFlag::kNotShared`

**执行 `WasmMemoryObject::New`:**

1. `New` 函数会计算出初始的字节大小：`1 * wasm::kWasmPageSize`。
2. 它会调用 `BackingStore::AllocateWasmMemory` 分配一块大小足够的内存区域。
3. 创建一个新的 `JSArrayBuffer` 并关联这块内存。
4. 创建一个新的 `WasmMemoryObject`，并设置其 `array_buffer` 指向新创建的 `JSArrayBuffer`，`maximum_pages` 为 10。

**输出:**

*   一个指向新创建的 `WasmMemoryObject` 的 `Handle`。

**用户常见的编程错误 (与 `WasmMemoryObject::Grow` 相关):**

*   **尝试增长超过最大大小:**  如果 WebAssembly 代码尝试调用 `memory.grow` 增长的页数加上当前的页数超过了 `WasmMemoryObject` 中设置的最大页数，`WasmMemoryObject::Grow` 会返回 -1，表示增长失败。

    **JavaScript 示例:**

    ```javascript
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
      0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x0a, 0x0a,
      0x01, 0x08, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x3c, 0x04, 0x00, 0x00, 0x0a,
      0x0a
    ]);
    const wasmModule = new WebAssembly.Module(wasmCode);
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
    const wasmInstance = new WebAssembly.Instance(wasmModule, { env: { memory } });

    console.log(memory.grow(1)); // 输出 1 (增长成功)
    console.log(memory.grow(1)); // 输出 -1 (增长失败，因为超过最大值)
    ```

**总结这段代码的功能：**

这段代码是 V8 引擎中处理 WebAssembly 运行时对象的核心部分。它定义了用于表示 WebAssembly 内存、全局变量和函数调用的对象，并提供了创建、管理和操作这些对象的方法。`WasmTrustedInstanceData` 则作为 WebAssembly 实例的受信任数据容器，管理实例的运行时状态。这段代码确保了 WebAssembly 代码在 V8 中的正确执行和内存管理。

### 提示词
```
这是目录为v8/src/wasm/wasm-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
PLIES(use_trap_handler, is_wasm_module);
  // ArrayBuffers allocated for Wasm do always have a BackingStore.
  std::shared_ptr<BackingStore> backing_store = buffer->GetBackingStore();
  CHECK_IMPLIES(is_wasm_module, backing_store);
  CHECK_IMPLIES(is_wasm_module, backing_store->is_wasm_memory());
  // Wasm modules compiled to use the trap handler don't have bounds checks,
  // so they must have a memory that has guard regions.
  // Note: This CHECK can fail when in-sandbox corruption modified a
  // WasmMemoryObject. We currently believe that this would at worst
  // corrupt the contents of other Wasm memories or ArrayBuffers, but having
  // this CHECK in release mode is nice as an additional layer of defense.
  CHECK_IMPLIES(use_trap_handler, backing_store->has_guard_regions());
  // We checked this before, but a malicious worker thread with an in-sandbox
  // corruption primitive could have modified it since then.
  size_t byte_length = buffer->byte_length();
  SBXCHECK_GE(byte_length, memory.min_memory_size);

  trusted_instance_data->SetRawMemory(
      memory_index, reinterpret_cast<uint8_t*>(buffer->backing_store()),
      byte_length);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless &&
      trusted_instance_data->has_interpreter_object()) {
    AllowHeapAllocation allow_heap;
    Isolate* isolate = trusted_instance_data->instance_object()->GetIsolate();
    HandleScope scope(isolate);
    wasm::WasmInterpreterRuntime::UpdateMemoryAddress(
        handle(trusted_instance_data->instance_object(), isolate));
  }
#endif  // V8_ENABLE_DRUMBRAKE
}

}  // namespace

Handle<WasmMemoryObject> WasmMemoryObject::New(Isolate* isolate,
                                               Handle<JSArrayBuffer> buffer,
                                               int maximum,
                                               wasm::AddressType address_type) {
  Handle<JSFunction> memory_ctor(
      isolate->native_context()->wasm_memory_constructor(), isolate);

  auto memory_object = Cast<WasmMemoryObject>(
      isolate->factory()->NewJSObject(memory_ctor, AllocationType::kOld));
  memory_object->set_array_buffer(*buffer);
  memory_object->set_maximum_pages(maximum);
  memory_object->set_address_type(address_type);
  memory_object->set_padding_for_address_type_0(0);
  memory_object->set_padding_for_address_type_1(0);
#if TAGGED_SIZE_8_BYTES
  memory_object->set_padding_for_address_type_2(0);
#endif
  memory_object->set_instances(ReadOnlyRoots{isolate}.empty_weak_array_list());

  std::shared_ptr<BackingStore> backing_store = buffer->GetBackingStore();
  if (buffer->is_shared()) {
    // Only Wasm memory can be shared (in contrast to asm.js memory).
    CHECK(backing_store && backing_store->is_wasm_memory());
    backing_store->AttachSharedWasmMemoryObject(isolate, memory_object);
  } else if (backing_store) {
    CHECK(!backing_store->is_shared());
  }

  // For debugging purposes we memorize a link from the JSArrayBuffer
  // to its owning WasmMemoryObject instance.
  Handle<Symbol> symbol = isolate->factory()->array_buffer_wasm_memory_symbol();
  Object::SetProperty(isolate, buffer, symbol, memory_object).Check();

  return memory_object;
}

MaybeHandle<WasmMemoryObject> WasmMemoryObject::New(
    Isolate* isolate, int initial, int maximum, SharedFlag shared,
    wasm::AddressType address_type) {
  bool has_maximum = maximum != kNoMaximum;

  int engine_maximum = address_type == wasm::AddressType::kI64
                           ? static_cast<int>(wasm::max_mem64_pages())
                           : static_cast<int>(wasm::max_mem32_pages());

  if (initial > engine_maximum) return {};

#ifdef V8_TARGET_ARCH_32_BIT
  // On 32-bit platforms we need an heuristic here to balance overall memory
  // and address space consumption.
  constexpr int kGBPages = 1024 * 1024 * 1024 / wasm::kWasmPageSize;
  // We allocate the smallest of the following sizes, but at least the initial
  // size:
  // 1) the module-defined maximum;
  // 2) 1GB;
  // 3) the engine maximum;
  int allocation_maximum = std::min(kGBPages, engine_maximum);
  int heuristic_maximum;
  if (initial > kGBPages) {
    // We always allocate at least the initial size.
    heuristic_maximum = initial;
  } else if (has_maximum) {
    // We try to reserve the maximum, but at most the allocation_maximum to
    // avoid OOMs.
    heuristic_maximum = std::min(maximum, allocation_maximum);
  } else if (shared == SharedFlag::kShared) {
    // If shared memory has no maximum, we use the allocation_maximum as an
    // implicit maximum.
    heuristic_maximum = allocation_maximum;
  } else {
    // If non-shared memory has no maximum, we only allocate the initial size
    // and then grow with realloc.
    heuristic_maximum = initial;
  }
#else
  int heuristic_maximum =
      has_maximum ? std::min(engine_maximum, maximum) : engine_maximum;
#endif

  std::unique_ptr<BackingStore> backing_store =
      BackingStore::AllocateWasmMemory(isolate, initial, heuristic_maximum,
                                       address_type == wasm::AddressType::kI32
                                           ? WasmMemoryFlag::kWasmMemory32
                                           : WasmMemoryFlag::kWasmMemory64,
                                       shared);

  if (!backing_store) return {};

  Handle<JSArrayBuffer> buffer =
      shared == SharedFlag::kShared
          ? isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store))
          : isolate->factory()->NewJSArrayBuffer(std::move(backing_store));

  return New(isolate, buffer, maximum, address_type);
}

void WasmMemoryObject::UseInInstance(
    Isolate* isolate, DirectHandle<WasmMemoryObject> memory,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
    int memory_index_in_instance) {
  SetInstanceMemory(*trusted_instance_data, memory->array_buffer(),
                    memory_index_in_instance);
  if (!shared_trusted_instance_data.is_null()) {
    SetInstanceMemory(*shared_trusted_instance_data, memory->array_buffer(),
                      memory_index_in_instance);
  }
  Handle<WeakArrayList> instances{memory->instances(), isolate};
  auto weak_instance_object = MaybeObjectDirectHandle::Weak(
      trusted_instance_data->instance_object(), isolate);
  instances = WeakArrayList::Append(isolate, instances, weak_instance_object);
  memory->set_instances(*instances);
}

void WasmMemoryObject::SetNewBuffer(Tagged<JSArrayBuffer> new_buffer) {
  DisallowGarbageCollection no_gc;
  set_array_buffer(new_buffer);
  Tagged<WeakArrayList> instances = this->instances();
  Isolate* isolate = GetIsolate();
  for (int i = 0, len = instances->length(); i < len; ++i) {
    Tagged<MaybeObject> elem = instances->Get(i);
    if (elem.IsCleared()) continue;
    Tagged<WasmInstanceObject> instance_object =
        Cast<WasmInstanceObject>(elem.GetHeapObjectAssumeWeak());
    Tagged<WasmTrustedInstanceData> trusted_data =
        instance_object->trusted_data(isolate);
    // TODO(clemens): Avoid the iteration by also remembering the memory index
    // if we ever see larger numbers of memories.
    Tagged<FixedArray> memory_objects = trusted_data->memory_objects();
    int num_memories = memory_objects->length();
    for (int mem_idx = 0; mem_idx < num_memories; ++mem_idx) {
      if (memory_objects->get(mem_idx) == *this) {
        SetInstanceMemory(trusted_data, new_buffer, mem_idx);
      }
    }
  }
}

// static
int32_t WasmMemoryObject::Grow(Isolate* isolate,
                               Handle<WasmMemoryObject> memory_object,
                               uint32_t pages) {
  TRACE_EVENT0("v8.wasm", "wasm.GrowMemory");
  DirectHandle<JSArrayBuffer> old_buffer(memory_object->array_buffer(),
                                         isolate);

  std::shared_ptr<BackingStore> backing_store = old_buffer->GetBackingStore();
  // Only Wasm memory can grow, and Wasm memory always has a backing store.
  DCHECK_NOT_NULL(backing_store);

  // Check for maximum memory size.
  // Note: The {wasm::max_mem_pages()} limit is already checked in
  // {BackingStore::CopyWasmMemory}, and is irrelevant for
  // {GrowWasmMemoryInPlace} because memory is never allocated with more
  // capacity than that limit.
  size_t old_size = old_buffer->byte_length();
  DCHECK_EQ(0, old_size % wasm::kWasmPageSize);
  size_t old_pages = old_size / wasm::kWasmPageSize;
  size_t max_pages = memory_object->is_memory64() ? wasm::max_mem64_pages()
                                                  : wasm::max_mem32_pages();
  if (memory_object->has_maximum_pages()) {
    max_pages = std::min(max_pages,
                         static_cast<size_t>(memory_object->maximum_pages()));
  }
  DCHECK_GE(max_pages, old_pages);
  if (pages > max_pages - old_pages) return -1;

  const bool must_grow_in_place =
      old_buffer->is_shared() || backing_store->has_guard_regions();
  const bool try_grow_in_place =
      must_grow_in_place || !v8_flags.stress_wasm_memory_moving;

  std::optional<size_t> result_inplace =
      try_grow_in_place
          ? backing_store->GrowWasmMemoryInPlace(isolate, pages, max_pages)
          : std::nullopt;
  if (must_grow_in_place && !result_inplace.has_value()) {
    // There are different limits per platform, thus crash if the correctness
    // fuzzer is running.
    if (v8_flags.correctness_fuzzer_suppressions) {
      FATAL("could not grow wasm memory");
    }
    return -1;
  }

  // Handle shared memory first.
  if (old_buffer->is_shared()) {
    DCHECK(result_inplace.has_value());
    backing_store->BroadcastSharedWasmMemoryGrow(isolate);
    // Broadcasting the update should update this memory object too.
    CHECK_NE(*old_buffer, memory_object->array_buffer());
    size_t new_pages = result_inplace.value() + pages;
    // If the allocation succeeded, then this can't possibly overflow:
    size_t new_byte_length = new_pages * wasm::kWasmPageSize;
    // This is a less than check, as it is not guaranteed that the SAB
    // length here will be equal to the stashed length above as calls to
    // grow the same memory object can come in from different workers.
    // It is also possible that a call to Grow was in progress when
    // handling this call.
    CHECK_LE(new_byte_length, memory_object->array_buffer()->byte_length());
    // As {old_pages} was read racefully, we return here the synchronized
    // value provided by {GrowWasmMemoryInPlace}, to provide the atomic
    // read-modify-write behavior required by the spec.
    return static_cast<int32_t>(result_inplace.value());  // success
  }

  // Check if the non-shared memory could grow in-place.
  if (result_inplace.has_value()) {
    // Detach old and create a new one with the grown backing store.
    JSArrayBuffer::Detach(old_buffer, true).Check();
    Handle<JSArrayBuffer> new_buffer =
        isolate->factory()->NewJSArrayBuffer(std::move(backing_store));
    memory_object->SetNewBuffer(*new_buffer);
    // For debugging purposes we memorize a link from the JSArrayBuffer
    // to its owning WasmMemoryObject instance.
    Handle<Symbol> symbol =
        isolate->factory()->array_buffer_wasm_memory_symbol();
    Object::SetProperty(isolate, new_buffer, symbol, memory_object).Check();
    DCHECK_EQ(result_inplace.value(), old_pages);
    return static_cast<int32_t>(result_inplace.value());  // success
  }

  size_t new_pages = old_pages + pages;
  // Check for overflow (should be excluded via {max_pages} above).
  DCHECK_LE(old_pages, new_pages);
  // Trying to grow in-place without actually growing must always succeed.
  DCHECK_IMPLIES(try_grow_in_place, old_pages < new_pages);

  // Try allocating a new backing store and copying.
  // To avoid overall quadratic complexity of many small grow operations, we
  // grow by at least 0.5 MB + 12.5% of the existing memory size.
  // These numbers are kept small because we must be careful about address
  // space consumption on 32-bit platforms.
  size_t min_growth = old_pages + 8 + (old_pages >> 3);
  // First apply {min_growth}, then {max_pages}. The order is important, because
  // {min_growth} can be bigger than {max_pages}, and in that case we want to
  // cap to {max_pages}.
  size_t new_capacity = std::min(max_pages, std::max(new_pages, min_growth));
  DCHECK_LE(new_pages, new_capacity);
  std::unique_ptr<BackingStore> new_backing_store =
      backing_store->CopyWasmMemory(isolate, new_pages, new_capacity,
                                    memory_object->is_memory64()
                                        ? WasmMemoryFlag::kWasmMemory64
                                        : WasmMemoryFlag::kWasmMemory32);
  if (!new_backing_store) {
    // Crash on out-of-memory if the correctness fuzzer is running.
    if (v8_flags.correctness_fuzzer_suppressions) {
      FATAL("could not grow wasm memory");
    }
    return -1;
  }

  // Detach old and create a new one with the new backing store.
  JSArrayBuffer::Detach(old_buffer, true).Check();
  Handle<JSArrayBuffer> new_buffer =
      isolate->factory()->NewJSArrayBuffer(std::move(new_backing_store));
  memory_object->SetNewBuffer(*new_buffer);
  // For debugging purposes we memorize a link from the JSArrayBuffer
  // to its owning WasmMemoryObject instance.
  Handle<Symbol> symbol = isolate->factory()->array_buffer_wasm_memory_symbol();
  Object::SetProperty(isolate, new_buffer, symbol, memory_object).Check();
  return static_cast<int32_t>(old_pages);  // success
}

// static
MaybeHandle<WasmGlobalObject> WasmGlobalObject::New(
    Isolate* isolate, Handle<WasmTrustedInstanceData> trusted_data,
    MaybeHandle<JSArrayBuffer> maybe_untagged_buffer,
    MaybeHandle<FixedArray> maybe_tagged_buffer, wasm::ValueType type,
    int32_t offset, bool is_mutable) {
  Handle<JSFunction> global_ctor(
      isolate->native_context()->wasm_global_constructor(), isolate);
  auto global_obj =
      Cast<WasmGlobalObject>(isolate->factory()->NewJSObject(global_ctor));
  {
    // Disallow GC until all fields have acceptable types.
    DisallowGarbageCollection no_gc;
    if (!trusted_data.is_null()) {
      global_obj->set_trusted_data(*trusted_data);
    } else {
      global_obj->clear_trusted_data();
    }
    global_obj->set_type(type);
    global_obj->set_offset(offset);
    global_obj->set_is_mutable(is_mutable);
  }

  if (type.is_reference()) {
    DCHECK(maybe_untagged_buffer.is_null());
    Handle<FixedArray> tagged_buffer;
    if (!maybe_tagged_buffer.ToHandle(&tagged_buffer)) {
      // If no buffer was provided, create one.
      tagged_buffer =
          isolate->factory()->NewFixedArray(1, AllocationType::kOld);
      CHECK_EQ(offset, 0);
    }
    global_obj->set_tagged_buffer(*tagged_buffer);
  } else {
    DCHECK(maybe_tagged_buffer.is_null());
    uint32_t type_size = type.value_kind_size();

    Handle<JSArrayBuffer> untagged_buffer;
    if (!maybe_untagged_buffer.ToHandle(&untagged_buffer)) {
      MaybeHandle<JSArrayBuffer> result =
          isolate->factory()->NewJSArrayBufferAndBackingStore(
              offset + type_size, InitializedFlag::kZeroInitialized);

      if (!result.ToHandle(&untagged_buffer)) return {};
    }

    // Check that the offset is in bounds.
    CHECK_LE(offset + type_size, untagged_buffer->byte_length());

    global_obj->set_untagged_buffer(*untagged_buffer);
  }

  return global_obj;
}

FunctionTargetAndImplicitArg::FunctionTargetAndImplicitArg(
    Isolate* isolate, Handle<WasmTrustedInstanceData> target_instance_data,
    int target_func_index) {
  implicit_arg_ = target_instance_data;
  if (target_func_index <
      static_cast<int>(
          target_instance_data->module()->num_imported_functions)) {
    // The function in the target instance was imported. Load the ref from the
    // dispatch table for imports.
    implicit_arg_ = handle(
        Cast<TrustedObject>(
            target_instance_data->dispatch_table_for_imports()->implicit_arg(
                target_func_index)),
        isolate);
#if V8_ENABLE_DRUMBRAKE
    target_func_index_ = target_instance_data->imported_function_indices()->get(
        target_func_index);
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    // The function in the target instance was not imported.
#if V8_ENABLE_DRUMBRAKE
    target_func_index_ = target_func_index;
#endif  // V8_ENABLE_DRUMBRAKE
  }
  call_target_ = target_instance_data->GetCallTarget(target_func_index);
}

namespace {
Address WasmCodePointerAddress(WasmCodePointer pointer) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  return wasm::GetProcessWideWasmCodePointerTable()->GetEntrypoint(pointer);
#else
  return pointer;
#endif
}
}  // namespace

void ImportedFunctionEntry::SetGenericWasmToJs(
    Isolate* isolate, DirectHandle<JSReceiver> callable, wasm::Suspend suspend,
    const wasm::CanonicalSig* sig) {
  WasmCodePointer wrapper_entry;
  if (wasm::IsJSCompatibleSignature(sig)) {
    DCHECK(
        UseGenericWasmToJSWrapper(wasm::kDefaultImportCallKind, sig, suspend));
    wrapper_entry =
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate);
  } else {
    wrapper_entry =
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
            isolate);
  }
  TRACE_IFT("Import callable 0x%" PRIxPTR "[%d] = {callable=0x%" PRIxPTR
            ", target=0x%" PRIxPTR "}\n",
            instance_data_->ptr(), index_, callable->ptr(),
            WasmCodePointerAddress(wrapper_entry));
  DirectHandle<WasmImportData> import_data =
      isolate->factory()->NewWasmImportData(callable, suspend, instance_data_,
                                            sig);
  WasmImportData::SetImportIndexAsCallOrigin(import_data, index_);
  DisallowGarbageCollection no_gc;

  constexpr IsAWrapper kNotACompiledWrapper = IsAWrapper::kNo;
  instance_data_->dispatch_table_for_imports()->SetForImport(
      index_, *import_data, wrapper_entry, nullptr, kNotACompiledWrapper);
#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_, -1);
#endif  // V8_ENABLE_DRUMBRAKE
}

void ImportedFunctionEntry::SetCompiledWasmToJs(
    Isolate* isolate, DirectHandle<JSReceiver> callable,
    wasm::WasmCode* wasm_to_js_wrapper, wasm::Suspend suspend,
    const wasm::CanonicalSig* sig) {
  TRACE_IFT("Import callable 0x%" PRIxPTR "[%d] = {callable=0x%" PRIxPTR
            ", target=%p}\n",
            instance_data_->ptr(), index_, callable->ptr(),
            wasm_to_js_wrapper ? nullptr
                               : wasm_to_js_wrapper->instructions().begin());
  DCHECK(v8_flags.wasm_jitless ||
         wasm_to_js_wrapper->kind() == wasm::WasmCode::kWasmToJsWrapper ||
         wasm_to_js_wrapper->kind() == wasm::WasmCode::kWasmToCapiWrapper);
  DirectHandle<WasmImportData> import_data =
      isolate->factory()->NewWasmImportData(callable, suspend, instance_data_,
                                            sig);
  // The wasm-to-js wrapper is already optimized, the call_origin should never
  // be accessed.
  import_data->set_call_origin(
      Smi::FromInt(WasmImportData::kInvalidCallOrigin));
  DisallowGarbageCollection no_gc;
  Tagged<WasmDispatchTable> dispatch_table =
      instance_data_->dispatch_table_for_imports();
  if (V8_UNLIKELY(v8_flags.wasm_jitless)) {
    dispatch_table->SetForImport(index_, *import_data, Address{}, nullptr,
                                 IsAWrapper::kNo);
  } else {
    dispatch_table->SetForImport(index_, *import_data,
                                 wasm_to_js_wrapper->code_pointer(),
                                 wasm_to_js_wrapper, IsAWrapper::kYes);
  }

#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_, -1);
#endif  // V8_ENABLE_DRUMBRAKE
}

void ImportedFunctionEntry::SetWasmToWasm(
    Tagged<WasmTrustedInstanceData> target_instance_data,
    WasmCodePointer call_target
#if V8_ENABLE_DRUMBRAKE
    ,
    int exported_function_index
#endif  // V8_ENABLE_DRUMBRAKE
) {
  TRACE_IFT("Import Wasm 0x%" PRIxPTR "[%d] = {instance_data=0x%" PRIxPTR
            ", target=0x%" PRIxPTR "}\n",
            instance_data_->ptr(), index_, target_instance_data.ptr(),
            WasmCodePointerAddress(call_target));
  DisallowGarbageCollection no_gc;
  Tagged<WasmDispatchTable> dispatch_table =
      instance_data_->dispatch_table_for_imports();
  dispatch_table->SetForImport(index_, target_instance_data, call_target,
                               nullptr, IsAWrapper::kNo);

#if V8_ENABLE_DRUMBRAKE
  instance_data_->imported_function_indices()->set(index_,
                                                   exported_function_index);
#endif  // V8_ENABLE_DRUMBRAKE
}

// Returns an empty Tagged<Object>() if no callable is available, a JSReceiver
// otherwise.
Tagged<Object> ImportedFunctionEntry::maybe_callable() {
  Tagged<Object> data = implicit_arg();
  if (!IsWasmImportData(data)) return Tagged<Object>();
  return Cast<JSReceiver>(Cast<WasmImportData>(data)->callable());
}

Tagged<JSReceiver> ImportedFunctionEntry::callable() {
  return Cast<JSReceiver>(Cast<WasmImportData>(implicit_arg())->callable());
}

Tagged<Object> ImportedFunctionEntry::implicit_arg() {
  return instance_data_->dispatch_table_for_imports()->implicit_arg(index_);
}

WasmCodePointer ImportedFunctionEntry::target() {
  return instance_data_->dispatch_table_for_imports()->target(index_);
}

#if V8_ENABLE_DRUMBRAKE
int ImportedFunctionEntry::function_index_in_called_module() {
  return instance_data_->imported_function_indices()->get(index_);
}
#endif  // V8_ENABLE_DRUMBRAKE

// static
constexpr std::array<uint16_t, WasmTrustedInstanceData::kTaggedFieldsCount>
    WasmTrustedInstanceData::kTaggedFieldOffsets;
// static
constexpr std::array<const char*, WasmTrustedInstanceData::kTaggedFieldsCount>
    WasmTrustedInstanceData::kTaggedFieldNames;
// static
constexpr std::array<uint16_t, 6>
    WasmTrustedInstanceData::kProtectedFieldOffsets;
// static
constexpr std::array<const char*, 6>
    WasmTrustedInstanceData::kProtectedFieldNames;

// static
void WasmTrustedInstanceData::EnsureMinimumDispatchTableSize(
    Isolate* isolate,
    DirectHandle<WasmTrustedInstanceData> trusted_instance_data,
    int table_index, int minimum_size) {
  Handle<WasmDispatchTable> old_dispatch_table{
      trusted_instance_data->dispatch_table(table_index), isolate};
  if (old_dispatch_table->length() >= minimum_size) return;
  DirectHandle<WasmDispatchTable> new_dispatch_table =
      WasmDispatchTable::Grow(isolate, old_dispatch_table, minimum_size);

  if (*old_dispatch_table == *new_dispatch_table) return;
  trusted_instance_data->dispatch_tables()->set(table_index,
                                                *new_dispatch_table);
  if (table_index == 0) {
    trusted_instance_data->set_dispatch_table0(*new_dispatch_table);
  }
}

void WasmTrustedInstanceData::SetRawMemory(int memory_index, uint8_t* mem_start,
                                           size_t mem_size) {
  CHECK_LT(memory_index, module()->memories.size());

  CHECK_LE(mem_size, module()->memories[memory_index].is_memory64()
                         ? wasm::max_mem64_bytes()
                         : wasm::max_mem32_bytes());
  // All memory bases and sizes are stored in a TrustedFixedAddressArray.
  Tagged<TrustedFixedAddressArray> bases_and_sizes = memory_bases_and_sizes();
  bases_and_sizes->set(memory_index * 2, reinterpret_cast<Address>(mem_start));
  bases_and_sizes->set(memory_index * 2 + 1, mem_size);
  // Memory 0 has fast-access fields.
  if (memory_index == 0) {
    set_memory0_start(mem_start);
    set_memory0_size(mem_size);
  }
}

#if V8_ENABLE_DRUMBRAKE
Handle<Tuple2> WasmTrustedInstanceData::GetOrCreateInterpreterObject(
    Handle<WasmInstanceObject> instance) {
  DCHECK(v8_flags.wasm_jitless);
  Isolate* isolate = instance->GetIsolate();
  Handle<WasmTrustedInstanceData> trusted_data =
      handle(instance->trusted_data(isolate), isolate);
  if (trusted_data->has_interpreter_object()) {
    return handle(trusted_data->interpreter_object(), isolate);
  }
  Handle<Tuple2> new_interpreter = WasmInterpreterObject::New(instance);
  DCHECK(trusted_data->has_interpreter_object());
  return new_interpreter;
}

Handle<Tuple2> WasmTrustedInstanceData::GetInterpreterObject(
    Handle<WasmInstanceObject> instance) {
  DCHECK(v8_flags.wasm_jitless);
  Isolate* isolate = instance->GetIsolate();
  Handle<WasmTrustedInstanceData> trusted_data =
      handle(instance->trusted_data(isolate), isolate);
  CHECK(trusted_data->has_interpreter_object());
  return handle(trusted_data->interpreter_object(), isolate);
}
#endif  // V8_ENABLE_DRUMBRAKE

Handle<WasmTrustedInstanceData> WasmTrustedInstanceData::New(
    Isolate* isolate, DirectHandle<WasmModuleObject> module_object,
    bool shared) {
  // Read the link to the {std::shared_ptr<NativeModule>} once from the
  // `module_object` and use it to initialize the fields of the
  // `WasmTrustedInstanceData`. It will then be stored in a `TrustedManaged` in
  // the `WasmTrustedInstanceData` where it is safe from manipulation.
  std::shared_ptr<wasm::NativeModule> native_module =
      module_object->shared_native_module();

  // Do first allocate all objects that will be stored in instance fields,
  // because otherwise we would have to allocate when the instance is not fully
  // initialized yet, which can lead to heap verification errors.
  const WasmModule* module = native_module->module();

  int num_imported_functions = module->num_imported_functions;
  DirectHandle<WasmDispatchTable> dispatch_table_for_imports =
      isolate->factory()->NewWasmDispatchTable(num_imported_functions);
  DirectHandle<FixedArray> well_known_imports =
      isolate->factory()->NewFixedArray(num_imported_functions);

  DirectHandle<FixedArray> func_refs =
      isolate->factory()->NewFixedArrayWithZeroes(
          static_cast<int>(module->functions.size()));

  int num_imported_mutable_globals = module->num_imported_mutable_globals;
  // The imported_mutable_globals is essentially a FixedAddressArray (storing
  // sandboxed pointers), but some entries (the indices for reference-type
  // globals) are accessed as 32-bit integers which is more convenient with a
  // raw ByteArray.
  DirectHandle<FixedAddressArray> imported_mutable_globals =
      FixedAddressArray::New(isolate, num_imported_mutable_globals);

  int num_data_segments = module->num_declared_data_segments;
  DirectHandle<FixedAddressArray> data_segment_starts =
      FixedAddressArray::New(isolate, num_data_segments);
  DirectHandle<FixedUInt32Array> data_segment_sizes =
      FixedUInt32Array::New(isolate, num_data_segments);

#if V8_ENABLE_DRUMBRAKE
  Handle<FixedInt32Array> imported_function_indices =
      FixedInt32Array::New(isolate, num_imported_functions);
#endif  // V8_ENABLE_DRUMBRAKE

  static_assert(wasm::kV8MaxWasmMemories < kMaxInt / 2);
  int num_memories = static_cast<int>(module->memories.size());
  DirectHandle<FixedArray> memory_objects =
      isolate->factory()->NewFixedArray(num_memories);
  DirectHandle<TrustedFixedAddressArray> memory_bases_and_sizes =
      TrustedFixedAddressArray::New(isolate, 2 * num_memories);

  // TODO(clemensb): Should we have singleton empty dispatch table in the
  // trusted space?
  DirectHandle<WasmDispatchTable> empty_dispatch_table =
      isolate->factory()->NewWasmDispatchTable(0);
  DirectHandle<ProtectedFixedArray> empty_protected_fixed_array =
      isolate->factory()->empty_protected_fixed_array();

  // Use the same memory estimate as the (untrusted) Managed in
  // WasmModuleObject. This is not security critical, and we at least always
  // read the memory estimation of *some* NativeModule here.
  size_t estimated_size =
      module_object->managed_native_module()->estimated_size();
  DirectHandle<TrustedManaged<wasm::NativeModule>>
      trusted_managed_native_module = TrustedManaged<wasm::NativeModule>::From(
          isolate, estimated_size, native_module);

  // Now allocate the WasmTrustedInstanceData.
  // During this step, no more allocations should happen because the instance is
  // incomplete yet, so we should not trigger heap verification at this point.
  Handle<WasmTrustedInstanceData> trusted_data =
      isolate->factory()->NewWasmTrustedInstanceData();
  {
    DisallowHeapAllocation no_gc;

    // Some constants:
    uint8_t* empty_backing_store_buffer =
        reinterpret_cast<uint8_t*>(EmptyBackingStoreBuffer());
    ReadOnlyRoots ro_roots{isolate};
    Tagged<FixedArray> empty_fixed_array = ro_roots.empty_fixed_array();

    trusted_data->set_dispatch_table_for_imports(*dispatch_table_for_imports);
    trusted_data->set_imported_mutable_globals(*imported_mutable_globals);
    trusted_data->set_dispatch_table0(*empty_dispatch_table);
    trusted_data->set_dispatch_tables(*empty_protected_fixed_array);
    trusted_data->set_shared_part(*trusted_data);  // TODO(14616): Good enough?
    trusted_data->set_data_segment_starts(*data_segment_starts);
    trusted_data->set_data_segment_sizes(*data_segment_sizes);
    trusted_data->set_element_segments(empty_fixed_array);
    trusted_data->set_managed_native_module(*trusted_managed_native_module);
    trusted_data->set_new_allocation_limit_address(
        isolate->heap()->NewSpaceAllocationLimitAddress());
    trusted_data->set_new_allocation_top_address(
        isolate->heap()->NewSpaceAllocationTopAddress());
    trusted_data->set_old_allocation_limit_address(
        isolate->heap()->OldSpaceAllocationLimitAddress());
    trusted_data->set_old_allocation_top_address(
        isolate->heap()->OldSpaceAllocationTopAddress());
    trusted_data->set_globals_start(empty_backing_store_buffer);
#if V8_ENABLE_DRUMBRAKE
    trusted_data->set_imported_function_indices(*imported_function_indices);
#endif  // V8_ENABLE_DRUMBRAKE
    trusted_data->set_native_context(*isolate->native_context());
    trusted_data->set_jump_table_start(native_module->jump_table_start());
    trusted_data->set_hook_on_function_call_address(
        isolate->debug()->hook_on_function_call_address());
    trusted_data->set_managed_object_maps(
        *isolate->factory()->empty_fixed_array());
    trusted_data->set_well_known_imports(*well_known_imports);
    trusted_data->set_func_refs(*func_refs);
    trusted_data->set_feedback_vectors(
        *isolate->factory()->empty_fixed_array());
    trusted_data->set_tiering_budget_array(
        native_module->tiering_budget_array());
    trusted_data->set_break_on_entry(module_object->script()->break_on_entry());
    trusted_data->InitDataSegmentArrays(native_module.get());
    trusted_data->set_memory0_start(empty_backing_store_buffer);
    trusted_data->set_memory0_size(0);
    trusted_data->set_memory_objects(*memory_objects);
    trusted_data->set_memory_bases_and_sizes(*memory_bases_and_sizes);
    trusted_data->set_stress_deopt_counter_address(
        ExternalReference::stress_deopt_count(isolate).address());

    for (int i = 0; i < num_memories; ++i) {
      memory_bases_and_sizes->set(
          2 * i, reinterpret_cast<Address>(empty_backing_store_buffer));
      memory_bases_and_sizes->set(2 * i + 1, 0);
    }
  }

  // Allocate the exports object, to be store in the instance object.
  DirectHandle<JSObject> exports_object =
      isolate->factory()->NewJSObjectWithNullProto();

  Handle<WasmInstanceObject> instance_object;

  if (!shared) {
    // Allocate the WasmInstanceObject (JS wrapper).
    Handle<JSFunction> instance_cons(
        isolate->native_context()->wasm_instance_constructor(), isolate);
    instance_object = Cast<WasmInstanceObject>(
        isolate->factory()->NewJSObject(instance_cons, AllocationType::kOld));
    instance_object->set_trusted_data(*trusted_data);
    instance_object->set_module_object(*module_object);
    instance_object->set_exports_object(*exports_object);
    trusted_data->set_instance_object(*instance_object);
  }

  // Insert the new instance into the scripts weak list of instances. This list
  // is used for breakpoints affecting all instances belonging to the script.
  if (module_object->script()->type() == Script::Type::kWasm &&
      !instance_object.is_null()) {
    Handle<WeakArrayList> weak_instance_list(
        module_object->script()->wasm_weak_instance_list(), isolate);
    weak_instance_list =
        WeakArrayList::Append(isolate, weak_instance_list,
                              MaybeObjectDirectHandle::Weak(instance_object));
    module_object->script()->set_wasm_weak_instance_list(*weak_instance_list);
  }

  return trusted_data;
}

void WasmTrustedInstanceData::InitDataSegmentArrays(
    const wasm::NativeModule* native_module) {
  const WasmModule* module = native_module->module();
  base
```