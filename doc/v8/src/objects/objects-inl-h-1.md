Response:
The user wants a summary of the provided C++ code snippet from `v8/src/objects/objects-inl.h`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The code defines inline methods for the `HeapObject` class. These methods are about interacting with the memory layout of objects in the V8 heap.

2. **Group Functionality:**  Notice patterns in the methods. They primarily deal with:
    * Reading and writing fields of various types (tagged pointers, raw data, external pointers, C++ heap pointers, indirect pointers).
    * Handling pointer compression and sandboxing.
    * Managing object metadata (specifically the `map`).
    * Determining object size and alignment.
    * Utility functions for comparisons and property access (although these are less central to the "objects-inl.h" theme).

3. **Explain Key Concepts:** Briefly define terms like "tagged pointer," "write barrier," "pointer compression," "sandboxing," and "map." These are crucial for understanding the code's context.

4. **Address Specific Instructions:**
    * **`.tq` Check:** The code is C++, not Torque.
    * **JavaScript Relationship:**  Explain how these low-level operations underpin JavaScript object manipulation. Give simple examples of accessing properties.
    * **Code Logic/Assumptions:** Focus on the generic nature of the field accessors. Provide a basic example of reading a field.
    * **Common Errors:**  Discuss potential issues with incorrect offsets or types.

5. **Structure the Summary:**  Organize the points logically, starting with the main function and then delving into details. Use clear and concise language.

6. **Address the "Part 2" instruction:** Explicitly state that this part focuses on memory layout manipulation.

**Self-Correction/Refinement during thought process:**

* Initially, I might be tempted to go into excessive detail about each function. However, given the instruction to *summarize*, a higher-level overview is more appropriate.
* I need to make sure the JavaScript examples are simple and directly related to the C++ concepts.
*  It's important to clearly distinguish between the different types of pointers (tagged, external, C++ heap, indirect) and their implications.
* The instructions about `.tq` and JavaScript connections are key and need to be explicitly addressed.
这是对 `v8/src/objects/objects-inl.h` 文件中 `HeapObject` 类的一部分内联方法的定义。这些方法提供了访问和操作堆中对象字段的底层机制。

**功能归纳:**

这部分代码主要定义了 `HeapObject` 类中用于**读取和写入各种类型字段**的内联方法，并涉及到以下关键概念：

1. **不同类型的指针处理:**  代码中包含了处理多种指针类型的函数，例如：
    * **Sandboxed Pointers:** 用于沙箱环境，提供额外的安全性。
    * **Bounded Size Fields:** 读写有大小限制的字段。
    * **External Pointers:** 指向堆外内存的指针，需要特殊的管理。
    * **CppHeap Pointers:** 指向 C++ 堆内存的指针。
    * **Trusted Pointers (Indirect Pointers):**  用于优化访问，可能指向一个中间的间接指针表。
    * **Code Pointers:** 指向 `Code` 对象的指针，通常用于执行代码。

2. **延迟初始化:** 提供了延迟初始化某些类型指针字段的方法，例如 `SetupLazilyInitializedExternalPointerField` 和 `WriteLazilyInitializedExternalPointerField`。

3. **写屏障 (Write Barriers):**  在修改对象字段时，特别是指针字段时，会涉及到写屏障，以确保垃圾回收器的正确性。 代码中使用了 `CONDITIONAL_EXTERNAL_POINTER_WRITE_BARRIER` 和 `EXTERNAL_POINTER_WRITE_BARRIER` 宏。

4. **指针压缩 (Pointer Compression):** 代码中使用了 `PtrComprCageBase`，这与 V8 的指针压缩机制有关，用于减少内存占用。

5. **原子操作:**  在某些场景下，例如延迟初始化，使用了原子操作 (`base::AsAtomic32`) 来保证线程安全。

6. **对象大小和类型:** 提供了获取对象大小 (`Size()`) 和 `Map` (描述对象类型和布局) 的方法。

7. **类型转换:**  包含一些类型转换相关的辅助函数，例如 `Cast<Code>`.

**与 JavaScript 功能的关系 (使用 JavaScript 举例):**

虽然这些 C++ 代码是 V8 引擎的底层实现，但它直接支撑着 JavaScript 中对象的各种操作。每当你访问或修改 JavaScript 对象的属性时，V8 引擎在底层就可能调用这里定义的类似方法。

例如，考虑以下 JavaScript 代码：

```javascript
const obj = { x: 10 };
obj.y = { z: 20 };
const valueOfX = obj.x;
```

当执行这些代码时，V8 引擎内部会进行以下类似的操作：

* **`obj.y = { z: 20 }`:**  V8 会在 `obj` 对象的内存布局中找到 `y` 属性对应的偏移量，并调用类似 `HeapObject::WriteTaggedField` 或 `HeapObject::WriteSandboxedPointerField` 的方法来写入指向新对象 `{ z: 20 }` 的指针。这个写入操作可能涉及到写屏障。
* **`const valueOfX = obj.x;`:** V8 会根据 `x` 属性的偏移量，调用类似 `HeapObject::ReadTaggedField` 或 `HeapObject::ReadSandboxedPointerField` 的方法来读取 `x` 的值。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 `HeapObject` 实例 `myObject`，并且我们想读取它在偏移量为 8 字节处的 `Tagged<Object>` 类型的字段。

**假设输入:**

* `myObject`: 一个 `HeapObject` 的实例，其内存地址为 `0x12345678`。
* `offset`: `8`
* `cage_base`:  假设指针压缩基地址为 `0x10000000` (示例值)。

**预期输出:**

`HeapObject::ReadTaggedField(8, cage_base)` 方法会返回 `myObject` 对象地址 `0x12345678` 加上偏移量 `8` 处的 `Tagged<Object>` 的值。  这个值可能是一个指向另一个 `HeapObject` 的压缩指针或一个 Smi。

**用户常见的编程错误 (举例说明):**

在 V8 的 C++ 开发中，常见的编程错误包括：

1. **错误的偏移量 (Incorrect Offset):**  如果传递给 `ReadTaggedField` 或 `WriteTaggedField` 的偏移量与对象的实际布局不符，会导致读取或写入到错误的内存位置，可能导致崩溃或数据损坏。

   ```c++
   // 假设对象的 'name' 字段偏移量是 16，但错误地使用了 8。
   Tagged<String> name = my_heap_object->ReadTaggedField<String>(8); // 错误！
   ```

2. **类型不匹配 (Type Mismatch):**  尝试将一种类型的指针写入到预期另一种类型的字段中，会导致类型安全问题。

   ```c++
   Tagged<Number> number = ...;
   // 假设对象的某个字段应该存储 String
   my_heap_object->WriteTaggedField(offset, number); // 错误！类型不匹配。
   ```

3. **忘记写屏障 (Forgetting Write Barriers):**  在修改堆中对象的指针字段时，如果忘记调用相应的写屏障机制，可能会导致垃圾回收器无法正确追踪对象的引用关系，最终导致悬挂指针或内存泄漏。

   ```c++
   Tagged<OtherObject> other_obj = ...;
   my_heap_object->WriteTaggedField(offset, other_obj);
   // 应该调用 WriteBarrier::ForField 或类似机制
   ```

**功能归纳 (第2部分):**

这部分 `objects-inl.h` 代码的核心功能是为 `HeapObject` 提供**底层的、高性能的内联方法来直接操作其内存布局**，包括读取和写入各种类型的字段，处理指针压缩和沙箱环境，以及管理对象元数据（如 Map）。这些方法是 V8 引擎实现 JavaScript 对象语义的基础。

Prompt: 
```
这是目录为v8/src/objects/objects-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
e_t offset, PtrComprCageBase cage_base) const {
  return i::ReadSandboxedPointerField(field_address(offset), cage_base);
}

void HeapObject::WriteSandboxedPointerField(size_t offset,
                                            PtrComprCageBase cage_base,
                                            Address value) {
  i::WriteSandboxedPointerField(field_address(offset), cage_base, value);
}

void HeapObject::WriteSandboxedPointerField(size_t offset, Isolate* isolate,
                                            Address value) {
  i::WriteSandboxedPointerField(field_address(offset),
                                PtrComprCageBase(isolate), value);
}

size_t HeapObject::ReadBoundedSizeField(size_t offset) const {
  return i::ReadBoundedSizeField(field_address(offset));
}

void HeapObject::WriteBoundedSizeField(size_t offset, size_t value) {
  i::WriteBoundedSizeField(field_address(offset), value);
}

template <ExternalPointerTag tag>
void HeapObject::InitExternalPointerField(size_t offset,
                                          IsolateForSandbox isolate,
                                          Address value,
                                          WriteBarrierMode mode) {
  i::InitExternalPointerField<tag>(address(), field_address(offset), isolate,
                                   value);
  CONDITIONAL_EXTERNAL_POINTER_WRITE_BARRIER(*this, static_cast<int>(offset),
                                             tag, mode);
}

template <ExternalPointerTag tag>
Address HeapObject::ReadExternalPointerField(size_t offset,
                                             IsolateForSandbox isolate) const {
  return i::ReadExternalPointerField<tag>(field_address(offset), isolate);
}

template <CppHeapPointerTag lower_bound, CppHeapPointerTag upper_bound>
Address HeapObject::ReadCppHeapPointerField(
    size_t offset, IsolateForPointerCompression isolate) const {
  return i::ReadCppHeapPointerField<lower_bound, upper_bound>(
      field_address(offset), isolate);
}

Address HeapObject::ReadCppHeapPointerField(
    size_t offset, IsolateForPointerCompression isolate,
    CppHeapPointerTagRange tag_range) const {
  return i::ReadCppHeapPointerField(field_address(offset), isolate, tag_range);
}

template <ExternalPointerTag tag>
void HeapObject::WriteExternalPointerField(size_t offset,
                                           IsolateForSandbox isolate,
                                           Address value) {
  i::WriteExternalPointerField<tag>(field_address(offset), isolate, value);
}

void HeapObject::SetupLazilyInitializedExternalPointerField(size_t offset) {
#ifdef V8_ENABLE_SANDBOX
  auto location =
      reinterpret_cast<ExternalPointerHandle*>(field_address(offset));
  base::AsAtomic32::Release_Store(location, kNullExternalPointerHandle);
#else
  WriteMaybeUnalignedValue<Address>(field_address(offset), kNullAddress);
#endif  // V8_ENABLE_SANDBOX
}

template <ExternalPointerTag tag>
void HeapObject::WriteLazilyInitializedExternalPointerField(
    size_t offset, IsolateForSandbox isolate, Address value) {
#ifdef V8_ENABLE_SANDBOX
  static_assert(tag != kExternalPointerNullTag);
  ExternalPointerTable& table = isolate.GetExternalPointerTableFor(tag);
  auto location =
      reinterpret_cast<ExternalPointerHandle*>(field_address(offset));
  ExternalPointerHandle handle = base::AsAtomic32::Relaxed_Load(location);
  if (handle == kNullExternalPointerHandle) {
    // Field has not been initialized yet.
    ExternalPointerHandle handle = table.AllocateAndInitializeEntry(
        isolate.GetExternalPointerTableSpaceFor(tag, address()), value, tag);
    base::AsAtomic32::Release_Store(location, handle);
    // In this case, we're adding a reference from an existing object to a new
    // table entry, so we always require a write barrier.
    EXTERNAL_POINTER_WRITE_BARRIER(*this, static_cast<int>(offset), tag);
  } else {
    table.Set(handle, value, tag);
  }
#else
  WriteMaybeUnalignedValue<Address>(field_address(offset), value);
#endif  // V8_ENABLE_SANDBOX
}

void HeapObject::SetupLazilyInitializedCppHeapPointerField(size_t offset) {
  CppHeapPointerSlot(field_address(offset)).init();
}

template <CppHeapPointerTag tag>
void HeapObject::WriteLazilyInitializedCppHeapPointerField(
    size_t offset, IsolateForPointerCompression isolate, Address value) {
  i::WriteLazilyInitializedCppHeapPointerField<tag>(field_address(offset),
                                                    isolate, value);
}

void HeapObject::WriteLazilyInitializedCppHeapPointerField(
    size_t offset, IsolateForPointerCompression isolate, Address value,
    CppHeapPointerTag tag) {
  i::WriteLazilyInitializedCppHeapPointerField(field_address(offset), isolate,
                                               value, tag);
}

void HeapObject::InitSelfIndirectPointerField(size_t offset,
                                              IsolateForSandbox isolate) {
  DCHECK(IsExposedTrustedObject(*this));
  InstanceType instance_type = map()->instance_type();
  IndirectPointerTag tag = IndirectPointerTagFromInstanceType(instance_type);
  i::InitSelfIndirectPointerField(field_address(offset), isolate, *this, tag);
}

template <IndirectPointerTag tag>
Tagged<ExposedTrustedObject> HeapObject::ReadTrustedPointerField(
    size_t offset, IsolateForSandbox isolate) const {
  // Currently, trusted pointer loads always use acquire semantics as the
  // under-the-hood indirect pointer loads use acquire loads anyway.
  return ReadTrustedPointerField<tag>(offset, isolate, kAcquireLoad);
}

template <IndirectPointerTag tag>
Tagged<ExposedTrustedObject> HeapObject::ReadTrustedPointerField(
    size_t offset, IsolateForSandbox isolate,
    AcquireLoadTag acquire_load) const {
  Tagged<Object> object =
      ReadMaybeEmptyTrustedPointerField<tag>(offset, isolate, acquire_load);
  DCHECK(IsExposedTrustedObject(object));
  return Cast<ExposedTrustedObject>(object);
}

template <IndirectPointerTag tag>
Tagged<Object> HeapObject::ReadMaybeEmptyTrustedPointerField(
    size_t offset, IsolateForSandbox isolate,
    AcquireLoadTag acquire_load) const {
#ifdef V8_ENABLE_SANDBOX
  return i::ReadIndirectPointerField<tag>(field_address(offset), isolate,
                                          acquire_load);
#else
  return TaggedField<Object>::Acquire_Load(*this, static_cast<int>(offset));
#endif
}

template <IndirectPointerTag tag>
void HeapObject::WriteTrustedPointerField(size_t offset,
                                          Tagged<ExposedTrustedObject> value) {
  // Currently, trusted pointer stores always use release semantics as the
  // under-the-hood indirect pointer stores use release stores anyway.
#ifdef V8_ENABLE_SANDBOX
  i::WriteIndirectPointerField<tag>(field_address(offset), value,
                                    kReleaseStore);
#else
  TaggedField<ExposedTrustedObject>::Release_Store(
      *this, static_cast<int>(offset), value);
#endif
}

bool HeapObject::IsTrustedPointerFieldEmpty(size_t offset) const {
#ifdef V8_ENABLE_SANDBOX
  IndirectPointerHandle handle = ACQUIRE_READ_UINT32_FIELD(*this, offset);
  return handle == kNullIndirectPointerHandle;
#else
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return IsSmi(TaggedField<Object>::Acquire_Load(cage_base, *this,
                                                 static_cast<int>(offset)));
#endif
}

void HeapObject::ClearTrustedPointerField(size_t offset) {
#ifdef V8_ENABLE_SANDBOX
  RELEASE_WRITE_UINT32_FIELD(*this, offset, kNullIndirectPointerHandle);
#else
  TaggedField<Smi>::Release_Store(*this, static_cast<int>(offset), Smi::zero());
#endif
}

void HeapObject::ClearTrustedPointerField(size_t offset, ReleaseStoreTag) {
  return ClearTrustedPointerField(offset);
}

Tagged<Code> HeapObject::ReadCodePointerField(size_t offset,
                                              IsolateForSandbox isolate) const {
  return Cast<Code>(
      ReadTrustedPointerField<kCodeIndirectPointerTag>(offset, isolate));
}

void HeapObject::WriteCodePointerField(size_t offset, Tagged<Code> value) {
  WriteTrustedPointerField<kCodeIndirectPointerTag>(offset, value);
}

bool HeapObject::IsCodePointerFieldEmpty(size_t offset) const {
  return IsTrustedPointerFieldEmpty(offset);
}

void HeapObject::ClearCodePointerField(size_t offset) {
  ClearTrustedPointerField(offset);
}

Address HeapObject::ReadCodeEntrypointViaCodePointerField(
    size_t offset, CodeEntrypointTag tag) const {
  return i::ReadCodeEntrypointViaCodePointerField(field_address(offset), tag);
}

void HeapObject::WriteCodeEntrypointViaCodePointerField(size_t offset,
                                                        Address value,
                                                        CodeEntrypointTag tag) {
  i::WriteCodeEntrypointViaCodePointerField(field_address(offset), value, tag);
}

void HeapObject::AllocateAndInstallJSDispatchHandle(size_t offset,
                                                    IsolateForSandbox isolate,
                                                    uint16_t parameter_count,
                                                    Tagged<Code> code,
                                                    WriteBarrierMode mode) {
#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  JSDispatchTable::Space* space =
      isolate.GetJSDispatchTableSpaceFor(field_address(offset));
  JSDispatchHandle handle =
      jdt->AllocateAndInitializeEntry(space, parameter_count, code);

  // Use a Release_Store to ensure that the store of the pointer into the table
  // is not reordered after the store of the handle. Otherwise, other threads
  // may access an uninitialized table entry and crash.
  auto location = reinterpret_cast<JSDispatchHandle*>(field_address(offset));
  base::AsAtomic32::Release_Store(location, handle);
  CONDITIONAL_JS_DISPATCH_HANDLE_WRITE_BARRIER(*this, handle, mode);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_LEAPTIERING
}

ObjectSlot HeapObject::RawField(int byte_offset) const {
  return ObjectSlot(field_address(byte_offset));
}

MaybeObjectSlot HeapObject::RawMaybeWeakField(int byte_offset) const {
  return MaybeObjectSlot(field_address(byte_offset));
}

InstructionStreamSlot HeapObject::RawInstructionStreamField(
    int byte_offset) const {
  return InstructionStreamSlot(field_address(byte_offset));
}

ExternalPointerSlot HeapObject::RawExternalPointerField(
    int byte_offset, ExternalPointerTag tag) const {
  return ExternalPointerSlot(field_address(byte_offset), tag);
}

CppHeapPointerSlot HeapObject::RawCppHeapPointerField(int byte_offset) const {
  return CppHeapPointerSlot(field_address(byte_offset));
}

IndirectPointerSlot HeapObject::RawIndirectPointerField(
    int byte_offset, IndirectPointerTag tag) const {
  return IndirectPointerSlot(field_address(byte_offset), tag);
}

MapWord MapWord::FromMap(const Tagged<Map> map) {
  DCHECK(map.is_null() || !MapWord::IsPacked(map.ptr()));
#ifdef V8_MAP_PACKING
  return MapWord(Pack(map.ptr()));
#else
  return MapWord(map.ptr());
#endif
}

Tagged<Map> MapWord::ToMap() const {
#ifdef V8_MAP_PACKING
  return UncheckedCast<Map>(Tagged<Object>(Unpack(value_)));
#else
  return UncheckedCast<Map>(Tagged<Object>(value_));
#endif
}

bool MapWord::IsForwardingAddress() const {
#ifdef V8_EXTERNAL_CODE_SPACE
  // When external code space is enabled forwarding pointers are encoded as
  // Smi representing a diff from the source object address in kObjectAlignment
  // chunks.
  return HAS_SMI_TAG(value_);
#else
  return (value_ & kForwardingTagMask) == kForwardingTag;
#endif  // V8_EXTERNAL_CODE_SPACE
}

MapWord MapWord::FromForwardingAddress(Tagged<HeapObject> map_word_host,
                                       Tagged<HeapObject> object) {
#ifdef V8_EXTERNAL_CODE_SPACE
  // When external code space is enabled forwarding pointers are encoded as
  // Smi representing a diff from the source object address in kObjectAlignment
  // chunks.
  intptr_t diff = static_cast<intptr_t>(object.ptr() - map_word_host.ptr());
  DCHECK(IsAligned(diff, kObjectAlignment));
  MapWord map_word(Smi::FromIntptr(diff / kObjectAlignment).ptr());
  DCHECK(map_word.IsForwardingAddress());
  return map_word;
#else
  return MapWord(object.ptr() - kHeapObjectTag);
#endif  // V8_EXTERNAL_CODE_SPACE
}

Tagged<HeapObject> MapWord::ToForwardingAddress(
    Tagged<HeapObject> map_word_host) {
  DCHECK(IsForwardingAddress());
#ifdef V8_EXTERNAL_CODE_SPACE
  // When the sandbox or the external code space is enabled, forwarding
  // pointers are encoded as Smi representing a diff from the source object
  // address in kObjectAlignment chunks. This is required as we are using
  // multiple pointer compression cages in these scenarios.
  intptr_t diff =
      static_cast<intptr_t>(Tagged<Smi>(value_).value()) * kObjectAlignment;
  Address address = map_word_host.address() + diff;
  return HeapObject::FromAddress(address);
#else
  // The sandbox requires the external code space.
  DCHECK(!V8_ENABLE_SANDBOX_BOOL);
  return HeapObject::FromAddress(value_);
#endif  // V8_EXTERNAL_CODE_SPACE
}

#ifdef VERIFY_HEAP
void HeapObject::VerifyObjectField(Isolate* isolate, int offset) {
  Object::VerifyPointer(isolate,
                        TaggedField<Object>::load(isolate, *this, offset));
  static_assert(!COMPRESS_POINTERS_BOOL || kTaggedSize == kInt32Size);
}

void HeapObject::VerifyMaybeObjectField(Isolate* isolate, int offset) {
  Object::VerifyMaybeObjectPointer(
      isolate, TaggedField<MaybeObject>::load(isolate, *this, offset));
  static_assert(!COMPRESS_POINTERS_BOOL || kTaggedSize == kInt32Size);
}

void HeapObject::VerifySmiField(int offset) {
  CHECK(IsSmi(TaggedField<Object>::load(*this, offset)));
  static_assert(!COMPRESS_POINTERS_BOOL || kTaggedSize == kInt32Size);
}

#endif

ReadOnlyRoots HeapObject::EarlyGetReadOnlyRoots() const {
  return ReadOnlyHeap::EarlyGetReadOnlyRoots(*this);
}

ReadOnlyRoots HeapObjectLayout::EarlyGetReadOnlyRoots() const {
  return ReadOnlyHeap::EarlyGetReadOnlyRoots(Tagged(this));
}

ReadOnlyRoots HeapObject::GetReadOnlyRoots() const {
  return ReadOnlyHeap::GetReadOnlyRoots(*this);
}

ReadOnlyRoots HeapObjectLayout::GetReadOnlyRoots() const {
  return ReadOnlyHeap::GetReadOnlyRoots(Tagged(this));
}

// TODO(v8:13788): Remove this cage-ful accessor.
ReadOnlyRoots HeapObject::GetReadOnlyRoots(PtrComprCageBase cage_base) const {
  return GetReadOnlyRoots();
}

Tagged<Map> HeapObject::map() const {
  // This method is never used for objects located in code space
  // (InstructionStream and free space fillers) and thus it is fine to use
  // auto-computed cage base value.
  DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL, !HeapLayout::InCodeSpace(*this));
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return HeapObject::map(cage_base);
}

Tagged<Map> HeapObject::map(PtrComprCageBase cage_base) const {
  return map_word(cage_base, kRelaxedLoad).ToMap();
}

Tagged<Map> HeapObjectLayout::map() const {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->map();
}

Tagged<Map> HeapObjectLayout::map(AcquireLoadTag) const {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->map(kAcquireLoad);
}

void HeapObjectLayout::set_map(Isolate* isolate, Tagged<Map> value) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->set_map(isolate, value);
}

template <typename IsolateT>
void HeapObjectLayout::set_map(IsolateT* isolate, Tagged<Map> value,
                               ReleaseStoreTag) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->set_map(isolate, value, kReleaseStore);
}

template <typename IsolateT>
void HeapObjectLayout::set_map_safe_transition(IsolateT* isolate,
                                               Tagged<Map> value,
                                               ReleaseStoreTag) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->set_map_safe_transition(isolate, value,
                                                           kReleaseStore);
}

void HeapObject::set_map(Isolate* isolate, Tagged<Map> value) {
  set_map<EmitWriteBarrier::kYes>(isolate, value, kRelaxedStore,
                                  VerificationMode::kPotentialLayoutChange);
}

template <typename IsolateT>
void HeapObject::set_map(IsolateT* isolate, Tagged<Map> value,
                         ReleaseStoreTag tag) {
  set_map<EmitWriteBarrier::kYes>(isolate, value, kReleaseStore,
                                  VerificationMode::kPotentialLayoutChange);
}

template <typename IsolateT>
void HeapObject::set_map_safe_transition(IsolateT* isolate, Tagged<Map> value) {
  set_map<EmitWriteBarrier::kYes>(isolate, value, kRelaxedStore,
                                  VerificationMode::kSafeMapTransition);
}

template <typename IsolateT>
void HeapObject::set_map_safe_transition(IsolateT* isolate, Tagged<Map> value,
                                         ReleaseStoreTag tag) {
  set_map<EmitWriteBarrier::kYes>(isolate, value, kReleaseStore,
                                  VerificationMode::kSafeMapTransition);
}

void HeapObjectLayout::set_map_safe_transition_no_write_barrier(
    Isolate* isolate, Tagged<Map> value, RelaxedStoreTag tag) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  return Tagged<HeapObject>(this)->set_map_safe_transition_no_write_barrier(
      isolate, value, tag);
}

void HeapObject::set_map_safe_transition_no_write_barrier(Isolate* isolate,
                                                          Tagged<Map> value,
                                                          RelaxedStoreTag tag) {
  set_map<EmitWriteBarrier::kNo>(isolate, value, kRelaxedStore,
                                 VerificationMode::kSafeMapTransition);
}

void HeapObject::set_map_safe_transition_no_write_barrier(Isolate* isolate,
                                                          Tagged<Map> value,
                                                          ReleaseStoreTag tag) {
  set_map<EmitWriteBarrier::kNo>(isolate, value, kReleaseStore,
                                 VerificationMode::kSafeMapTransition);
}

void HeapObjectLayout::set_map_no_write_barrier(Isolate* isolate,
                                                Tagged<Map> value,
                                                RelaxedStoreTag tag) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  Tagged<HeapObject>(this)->set_map_no_write_barrier(isolate, value, tag);
}

// Unsafe accessor omitting write barrier.
void HeapObject::set_map_no_write_barrier(Isolate* isolate, Tagged<Map> value,
                                          RelaxedStoreTag tag) {
  set_map<EmitWriteBarrier::kNo>(isolate, value, kRelaxedStore,
                                 VerificationMode::kPotentialLayoutChange);
}

void HeapObject::set_map_no_write_barrier(Isolate* isolate, Tagged<Map> value,
                                          ReleaseStoreTag tag) {
  set_map<EmitWriteBarrier::kNo>(isolate, value, kReleaseStore,
                                 VerificationMode::kPotentialLayoutChange);
}

template <HeapObject::EmitWriteBarrier emit_write_barrier, typename MemoryOrder,
          typename IsolateT>
void HeapObject::set_map(IsolateT* isolate, Tagged<Map> value,
                         MemoryOrder order, VerificationMode mode) {
#if V8_ENABLE_WEBASSEMBLY
  // In {WasmGraphBuilder::SetMap} and {WasmGraphBuilder::LoadMap}, we treat
  // maps as immutable. Therefore we are not allowed to mutate them here.
  DCHECK(!IsWasmStructMap(value) && !IsWasmArrayMap(value));
#endif
  // Object layout changes are currently not supported on background threads.
  // This method might change object layout and therefore can't be used on
  // background threads.
  DCHECK_IMPLIES(mode != VerificationMode::kSafeMapTransition,
                 !LocalHeap::Current());
  if (v8_flags.verify_heap && !value.is_null()) {
    if (mode == VerificationMode::kSafeMapTransition) {
      HeapVerifier::VerifySafeMapTransition(isolate->heap()->AsHeap(), *this,
                                            value);
    } else {
      DCHECK_EQ(mode, VerificationMode::kPotentialLayoutChange);
      HeapVerifier::VerifyObjectLayoutChange(isolate->heap()->AsHeap(), *this,
                                             value);
    }
  }
  set_map_word(value, order);
  Heap::NotifyObjectLayoutChangeDone(*this);
#ifndef V8_DISABLE_WRITE_BARRIERS
  if (!value.is_null()) {
    if (emit_write_barrier == EmitWriteBarrier::kYes) {
      WriteBarrier::ForValue(*this, MaybeObjectSlot(map_slot()), value,
                             UPDATE_WRITE_BARRIER);
    } else {
      DCHECK_EQ(emit_write_barrier, EmitWriteBarrier::kNo);
      SLOW_DCHECK(!WriteBarrier::IsRequired(*this, value));
    }
  }
#endif
}

template <typename IsolateT>
void HeapObjectLayout::set_map_after_allocation(IsolateT* isolate,
                                                Tagged<Map> value,
                                                WriteBarrierMode mode) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  Tagged<HeapObject>(this)->set_map_after_allocation(isolate, value, mode);
}

template <typename IsolateT>
void HeapObject::set_map_after_allocation(IsolateT* isolate, Tagged<Map> value,
                                          WriteBarrierMode mode) {
  set_map_word(value, kRelaxedStore);
#ifndef V8_DISABLE_WRITE_BARRIERS
  if (mode != SKIP_WRITE_BARRIER) {
    DCHECK(!value.is_null());
    WriteBarrier::ForValue(*this, MaybeObjectSlot(map_slot()), value, mode);
  } else {
    SLOW_DCHECK(
        // We allow writes of a null map before root initialisation.
        value.is_null() ? !isolate->read_only_heap()->roots_init_complete()
                        : !WriteBarrier::IsRequired(*this, value));
  }
#endif
}

// static
void HeapObject::SetFillerMap(const WritableFreeSpace& writable_space,
                              Tagged<Map> value) {
  writable_space.WriteHeaderSlot<Map, kMapOffset>(value, kRelaxedStore);
}

DEF_ACQUIRE_GETTER(HeapObject, map, Tagged<Map>) {
  return map_word(cage_base, kAcquireLoad).ToMap();
}

ObjectSlot HeapObject::map_slot() const {
  return ObjectSlot(MapField::address(*this));
}

MapWord HeapObject::map_word(RelaxedLoadTag tag) const {
  // This method is never used for objects located in code space
  // (InstructionStream and free space fillers) and thus it is fine to use
  // auto-computed cage base value.
  DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL, !HeapLayout::InCodeSpace(*this));
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return HeapObject::map_word(cage_base, tag);
}
MapWord HeapObject::map_word(PtrComprCageBase cage_base,
                             RelaxedLoadTag tag) const {
  return MapField::Relaxed_Load_Map_Word(cage_base, *this);
}

void HeapObject::set_map_word(Tagged<Map> map, RelaxedStoreTag) {
  MapField::Relaxed_Store_Map_Word(*this, MapWord::FromMap(map));
}

void HeapObject::set_map_word_forwarded(Tagged<HeapObject> target_object,
                                        RelaxedStoreTag) {
  MapField::Relaxed_Store_Map_Word(
      *this, MapWord::FromForwardingAddress(*this, target_object));
}

MapWord HeapObject::map_word(AcquireLoadTag tag) const {
  // This method is never used for objects located in code space
  // (InstructionStream and free space fillers) and thus it is fine to use
  // auto-computed cage base value.
  DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL, !HeapLayout::InCodeSpace(*this));
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return HeapObject::map_word(cage_base, tag);
}
MapWord HeapObject::map_word(PtrComprCageBase cage_base,
                             AcquireLoadTag tag) const {
  return MapField::Acquire_Load_No_Unpack(cage_base, *this);
}

void HeapObject::set_map_word(Tagged<Map> map, ReleaseStoreTag) {
  MapField::Release_Store_Map_Word(*this, MapWord::FromMap(map));
}

void HeapObjectLayout::set_map_word_forwarded(Tagged<HeapObject> target_object,
                                              ReleaseStoreTag tag) {
  // TODO(leszeks): Support MapWord members and access via that instead.
  Tagged<HeapObject>(this)->set_map_word_forwarded(target_object, tag);
}

void HeapObject::set_map_word_forwarded(Tagged<HeapObject> target_object,
                                        ReleaseStoreTag) {
  MapField::Release_Store_Map_Word(
      *this, MapWord::FromForwardingAddress(*this, target_object));
}

bool HeapObject::release_compare_and_swap_map_word_forwarded(
    MapWord old_map_word, Tagged<HeapObject> new_target_object) {
  Tagged_t result = MapField::Release_CompareAndSwap(
      *this, old_map_word,
      MapWord::FromForwardingAddress(*this, new_target_object));
  return result == static_cast<Tagged_t>(old_map_word.ptr());
}

int HeapObjectLayout::Size() const { return Tagged<HeapObject>(this)->Size(); }

// TODO(v8:11880): consider dropping parameterless version.
int HeapObject::Size() const {
  DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL, !HeapLayout::InCodeSpace(*this));
  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  return HeapObject::Size(cage_base);
}
int HeapObject::Size(PtrComprCageBase cage_base) const {
  return SizeFromMap(map(cage_base));
}

inline bool IsSpecialReceiverInstanceType(InstanceType instance_type) {
  return instance_type <= LAST_SPECIAL_RECEIVER_TYPE;
}

// This should be in objects/map-inl.h, but can't, because of a cyclic
// dependency.
bool IsSpecialReceiverMap(Tagged<Map> map) {
  bool result = IsSpecialReceiverInstanceType(map->instance_type());
  DCHECK_IMPLIES(
      !result, !map->has_named_interceptor() && !map->is_access_check_needed());
  return result;
}

inline bool IsCustomElementsReceiverInstanceType(InstanceType instance_type) {
  return instance_type <= LAST_CUSTOM_ELEMENTS_RECEIVER;
}

// This should be in objects/map-inl.h, but can't, because of a cyclic
// dependency.
bool IsCustomElementsReceiverMap(Tagged<Map> map) {
  return IsCustomElementsReceiverInstanceType(map->instance_type());
}

// static
bool Object::ToArrayLength(Tagged<Object> obj, uint32_t* index) {
  return Object::ToUint32(obj, index);
}

// static
bool Object::ToArrayIndex(Tagged<Object> obj, uint32_t* index) {
  return Object::ToUint32(obj, index) && *index != kMaxUInt32;
}

// static
bool Object::ToIntegerIndex(Tagged<Object> obj, size_t* index) {
  if (IsSmi(obj)) {
    int num = Smi::ToInt(obj);
    if (num < 0) return false;
    *index = static_cast<size_t>(num);
    return true;
  }
  if (IsHeapNumber(obj)) {
    double num = Cast<HeapNumber>(obj)->value();
    if (!(num >= 0)) return false;  // Negation to catch NaNs.
    constexpr double max =
        std::min(kMaxSafeInteger,
                 // The maximum size_t is reserved as "invalid" sentinel.
                 static_cast<double>(std::numeric_limits<size_t>::max() - 1));
    if (num > max) return false;
    size_t result = static_cast<size_t>(num);
    if (num != result) return false;  // Conversion lost fractional precision.
    *index = result;
    return true;
  }
  return false;
}

WriteBarrierMode HeapObjectLayout::GetWriteBarrierMode(
    const DisallowGarbageCollection& promise) {
  return WriteBarrier::GetWriteBarrierModeForObject(this, promise);
}

WriteBarrierMode HeapObject::GetWriteBarrierMode(
    const DisallowGarbageCollection& promise) {
  return WriteBarrier::GetWriteBarrierModeForObject(*this, promise);
}

// static
AllocationAlignment HeapObject::RequiredAlignment(Tagged<Map> map) {
  // TODO(v8:4153): We should think about requiring double alignment
  // in general for ByteArray, since they are used as backing store for typed
  // arrays now.
  // TODO(ishell, v8:8875): Consider using aligned allocations for BigInt.
  if (USE_ALLOCATION_ALIGNMENT_BOOL) {
    int instance_type = map->instance_type();

    static_assert(!USE_ALLOCATION_ALIGNMENT_BOOL ||
                  (sizeof(FixedDoubleArray::Header) & kDoubleAlignmentMask) ==
                      kTaggedSize);
    if (instance_type == FIXED_DOUBLE_ARRAY_TYPE) return kDoubleAligned;

    static_assert(!USE_ALLOCATION_ALIGNMENT_BOOL ||
                  (offsetof(HeapNumber, value_) & kDoubleAlignmentMask) ==
                      kTaggedSize);
    if (instance_type == HEAP_NUMBER_TYPE) return kDoubleUnaligned;
  }
  return kTaggedAligned;
}

bool HeapObject::CheckRequiredAlignment(PtrComprCageBase cage_base) const {
  AllocationAlignment alignment = HeapObject::RequiredAlignment(map(cage_base));
  CHECK_EQ(0, Heap::GetFillToAlign(address(), alignment));
  return true;
}

Address HeapObject::GetFieldAddress(int field_offset) const {
  return field_address(field_offset);
}

// static
Maybe<bool> Object::GreaterThan(Isolate* isolate, Handle<Object> x,
                                Handle<Object> y) {
  Maybe<ComparisonResult> result = Compare(isolate, x, y);
  if (result.IsJust()) {
    switch (result.FromJust()) {
      case ComparisonResult::kGreaterThan:
        return Just(true);
      case ComparisonResult::kLessThan:
      case ComparisonResult::kEqual:
      case ComparisonResult::kUndefined:
        return Just(false);
    }
  }
  return Nothing<bool>();
}

// static
Maybe<bool> Object::GreaterThanOrEqual(Isolate* isolate, Handle<Object> x,
                                       Handle<Object> y) {
  Maybe<ComparisonResult> result = Compare(isolate, x, y);
  if (result.IsJust()) {
    switch (result.FromJust()) {
      case ComparisonResult::kEqual:
      case ComparisonResult::kGreaterThan:
        return Just(true);
      case ComparisonResult::kLessThan:
      case ComparisonResult::kUndefined:
        return Just(false);
    }
  }
  return Nothing<bool>();
}

// static
Maybe<bool> Object::LessThan(Isolate* isolate, Handle<Object> x,
                             Handle<Object> y) {
  Maybe<ComparisonResult> result = Compare(isolate, x, y);
  if (result.IsJust()) {
    switch (result.FromJust()) {
      case ComparisonResult::kLessThan:
        return Just(true);
      case ComparisonResult::kEqual:
      case ComparisonResult::kGreaterThan:
      case ComparisonResult::kUndefined:
        return Just(false);
    }
  }
  return Nothing<bool>();
}

// static
Maybe<bool> Object::LessThanOrEqual(Isolate* isolate, Handle<Object> x,
                                    Handle<Object> y) {
  Maybe<ComparisonResult> result = Compare(isolate, x, y);
  if (result.IsJust()) {
    switch (result.FromJust()) {
      case ComparisonResult::kEqual:
      case ComparisonResult::kLessThan:
        return Just(true);
      case ComparisonResult::kGreaterThan:
      case ComparisonResult::kUndefined:
        return Just(false);
    }
  }
  return Nothing<bool>();
}

MaybeHandle<Object> Object::GetPropertyOrElement(Isolate* isolate,
                                                 Handle<JSAny> object,
                                                 Handle<Name> name) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key);
  return GetProperty(&it);
}

MaybeHandle<Object> Object::SetPropertyOrElement(
    Isolate* isolate, Handle<JSAny> object, Handle<Name> name,
    Handle<Object> value, Maybe<ShouldThrow> should_throw,
    StoreOrigin store_origin) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key);
  MAYBE_RETURN_NULL(SetProperty(&it, value, store_origin, should_throw));
  return value;
}

MaybeHandle<Object> Object::GetPropertyOrElement(Handle<JSAny> receiver,
                                                 Handle<Name> name,
                                                 Handle<JSReceiver> holder) {
  Isolate* isolate = holder->GetIsolate();
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, receiver, key, holder);
  return GetProperty(&it);
}

// static
Tagged<Object> Object::GetSimpleHash(Tagged<Object> object) {
  DisallowGarbageCollection no_gc;
  if (IsSmi(object)) {
    uint32_t hash = ComputeUnseededHash(Smi::ToInt(object));
    return Smi::FromInt(hash & Smi::kMaxValue);
  }
  auto instance_type = Cast<HeapObject>(object)->map()->instance_type();
  if (InstanceTypeChecker::IsHeapNumber(instance_type)) {
    double num = Cast<HeapNumber>(object)->value();
    if (std::isnan(num)) return Smi::FromInt(Smi::kMaxValue);
    // Use ComputeUnseededHash for all values in Signed32 range, including -0,
    // which is considered equal to 0 because collections use SameValueZero.
    uint32_t hash;
    // Check range before conversion to avoid undefined behavior.
    if (num >= kMinInt &&
"""


```