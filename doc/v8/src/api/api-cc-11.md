Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `api.cc` file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file:** The file is `v8/src/api/api.cc`. The path indicates it's part of the public API of V8.

2. **Check for Torque:** The prompt specifically asks if the file ends with `.tq`. This file ends with `.cc`, so it's C++ code, not Torque.

3. **Relate to JavaScript:**  The prompt asks about the connection to JavaScript. The `v8::` namespace strongly suggests this code defines the C++ interface that JavaScript interacts with when dealing with certain built-in objects. Looking at the class names like `ArrayBuffer`, `SharedArrayBuffer`, `Symbol`, `BigInt`, `Number`, `Integer`, `DataView`, and `TypedArray` confirms this connection. These are all JavaScript types or related concepts.

4. **Analyze Functionality (Iterate through the code):**
   - **`ArrayBuffer` functions:**  Focus on the methods provided: `Detach`, `SetDetachKey`, `ByteLength`, `MaxByteLength`, `MaybeNew`, `New`, `NewBackingStore`, `NewResizableBackingStore`. These clearly relate to creating, managing, and querying `ArrayBuffer` objects in JavaScript. The `Detach` functions handle detaching the underlying memory buffer. `New` creates new `ArrayBuffer` instances. `NewBackingStore` deals with the raw memory allocation.
   - **`ArrayBufferView` functions:** `Buffer`, `CopyContents`, `GetContents`, `HasBuffer`, `ByteOffset`, `ByteLength`. These operate on objects that *view* a part of an `ArrayBuffer` (like `TypedArray` and `DataView`). They provide ways to access the underlying buffer, copy data, and get information about the view.
   - **`TypedArray` functions:** `Length`, and the `New` methods for specific typed arrays (e.g., `Uint8Array`, `Int32Array`). These methods are for creating and getting the length of JavaScript Typed Array objects.
   - **`DataView` functions:**  The `New` methods. These create `DataView` objects in JavaScript.
   - **`SharedArrayBuffer` functions:** Similar to `ArrayBuffer`: `ByteLength`, `MaxByteLength`, `New`, `NewBackingStore`. These manage shared memory buffers.
   - **`Symbol` functions:** `New`, `For`, `ForApi`, and `Get<WellKnownSymbol>`. These are about creating and retrieving JavaScript Symbol objects.
   - **`Private` functions:** `New`, `ForApi`. These deal with private symbols.
   - **`Number`, `Integer`, `BigInt` functions:** `New`, `NewFromUnsigned`, `NewFromWords`, `Uint64Value`, `Int64Value`, `WordCount`, `ToWordsArray`. These are for creating and retrieving values of JavaScript number and bigint types.
   - **`Isolate` functions:**  These are more general V8 API functions related to the isolate (an isolated V8 instance): `HandleExternalMemoryInterrupt`, `GetHeapProfiler`, `SetIdle`, `GetArrayBufferAllocator`, `InContext`, `ClearKeptObjects`, `GetCurrentContext`, `GetEnteredOrMicrotaskContext`, `GetIncumbentContext`, `GetCurrentHostDefinedOptions`, `ThrowError`, `ThrowException`, `HasPendingException`, `AddGCPrologueCallback`, `RemoveGCPrologueCallback`, `AddGCEpilogueCallback`, `RemoveGCEpilogueCallback`, `SetEmbedderRootsHandler`, `AttachCppHeap`. These cover memory management, error handling, context management, and more.

5. **Illustrate with JavaScript examples:** For each major functionality area, provide a simple JavaScript example demonstrating its usage. This reinforces the connection between the C++ API and the JavaScript language.

6. **Provide Code Logic Reasoning (Hypothetical Input/Output):** For a representative function (like `ArrayBuffer::Detach`), create a hypothetical scenario with inputs and explain the expected output based on the code's behavior.

7. **Address Common Programming Errors:** Think about how developers might misuse these APIs. For example, trying to detach a detached buffer, or creating typed arrays with incorrect offsets/lengths.

8. **Summarize Functionality:**  Combine the individual functionalities into a concise summary explaining the overall purpose of the code. Emphasize that it's the C++ implementation of core JavaScript object functionalities.

9. **Structure and Refine:** Organize the information logically with clear headings and explanations. Ensure the language is accurate and easy to understand. Review the prompt's specific requirements to ensure all points are addressed. For example, double-checking the "part number" and total parts.
```cpp
  }
    return Just(true);
  }
  ENTER_V8_NO_SCRIPT(i_isolate, context, ArrayBuffer, Detach, i::HandleScope);
  if (!key.IsEmpty()) {
    auto i_key = Utils::OpenHandle(*key);
    constexpr bool kForceForWasmMemory = false;
    has_exception =
        i::JSArrayBuffer::Detach(obj, kForceForWasmMemory, i_key).IsNothing();
  } else {
    has_exception = i::JSArrayBuffer::Detach(obj).IsNothing();
  }
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

void v8::ArrayBuffer::Detach() { Detach(Local<Value>()).Check(); }

void v8::ArrayBuffer::SetDetachKey(v8::Local<v8::Value> key) {
  auto obj = Utils::OpenDirectHandle(this);
  auto i_key = Utils::OpenDirectHandle(*key);
  obj->set_detach_key(*i_key);
}

size_t v8::ArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::ArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

namespace {
i::InitializedFlag GetInitializedFlag(
    BackingStoreInitializationMode initialization_mode) {
  switch (initialization_mode) {
    case BackingStoreInitializationMode::kUninitialized:
      return i::InitializedFlag::kUninitialized;
    case BackingStoreInitializationMode::kZeroInitialized:
      return i::InitializedFlag::kZeroInitialized;
  }
  UNREACHABLE();
}
}  // namespace

MaybeLocal<ArrayBuffer> v8::ArrayBuffer::MaybeNew(
    Isolate* isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, MaybeNew);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    return MaybeLocal<ArrayBuffer>();
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::ArrayBuffer::New");
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(
      ToInternal(std::move(backing_store)));
  Utils::ApiCheck(
      !i_backing_store->is_shared(), "v8_ArrayBuffer_New",
      "Cannot construct ArrayBuffer with a BackingStore of SharedArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocal(obj);
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, NewBackingStore);
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length,
                                i::SharedFlag::kNotShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::ArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
#ifdef V8_ENABLE_SANDBOX
  Utils::ApiCheck(!data || i::GetProcessWideSandbox()->Contains(data),
                  "v8_ArrayBuffer_NewBackingStore",
                  "When the V8 Sandbox is enabled, ArrayBuffer backing stores "
                  "must be allocated inside the sandbox address space. Please "
                  "use an appropriate ArrayBuffer::Allocator to allocate these "
                  "buffers, or disable the sandbox.");
#endif  // V8_ENABLE_SANDBOX

  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kNotShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

// static
std::unique_ptr<BackingStore> v8::ArrayBuffer::NewResizableBackingStore(
    size_t byte_length, size_t max_byte_length) {
  Utils::ApiCheck(byte_length <= max_byte_length,
                  "v8::ArrayBuffer::NewResizableBackingStore",
                  "Cannot construct resizable ArrayBuffer, byte_length must be "
                  "<= max_byte_length");
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::ArrayBuffer::NewResizableBackingStore",
      "Cannot construct resizable ArrayBuffer, requested length is too big");

  size_t page_size, initial_pages, max_pages;
  if (i::JSArrayBuffer::GetResizableBackingStorePageConfiguration(
          nullptr, byte_length, max_byte_length, i::kDontThrow, &page_size,
          &initial_pages, &max_pages)
          .IsNothing()) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::TryAllocateAndPartiallyCommitMemory(
          nullptr, byte_length, max_byte_length, page_size, initial_pages,
          max_pages, i::WasmMemoryFlag::kNotWasm, i::SharedFlag::kNotShared);
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<ArrayBuffer> v8::ArrayBufferView::Buffer() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  if (i::IsJSDataView(*obj)) {
    i::DirectHandle<i::JSDataView> data_view(i::Cast<i::JSDataView>(*obj),
                                             i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else if (i::IsJSRabGsabDataView(*obj)) {
    i::DirectHandle<i::JSRabGsabDataView> data_view(
        i::Cast<i::JSRabGsabDataView>(*obj), i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else {
    DCHECK(IsJSTypedArray(*obj));
    return Utils::ToLocal(i::Cast<i::JSTypedArray>(*obj)->GetBuffer());
  }
}

size_t v8::ArrayBufferView::CopyContents(void* dest, size_t byte_length) {
  auto self = Utils::OpenDirectHandle(this);
  size_t bytes_to_copy = std::min(byte_length, self->byte_length());
  if (bytes_to_copy) {
    i::DisallowGarbageCollection no_gc;
    const char* source;
    if (i::IsJSTypedArray(*self)) {
      i::Tagged<i::JSTypedArray> array = i::Cast<i::JSTypedArray>(*self);
      source = reinterpret_cast<char*>(array->DataPtr());
    } else {
      DCHECK(i::IsJSDataView(*self) || i::IsJSRabGsabDataView(*self));
      i::Tagged<i::JSDataViewOrRabGsabDataView> data_view =
          i::Cast<i::JSDataViewOrRabGsabDataView>(*self);
      source = reinterpret_cast<char*>(data_view->data_pointer());
    }
    memcpy(dest, source, bytes_to_copy);
  }
  return bytes_to_copy;
}

v8::MemorySpan<uint8_t> v8::ArrayBufferView::GetContents(
    v8::MemorySpan<uint8_t> storage) {
  internal::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  if (self->WasDetached()) {
    return {};
  }
  if (internal::IsJSTypedArray(*self)) {
    i::Tagged<i::JSTypedArray> typed_array = i::Cast<i::JSTypedArray>(*self);
    if (typed_array->is_on_heap()) {
      // The provided storage does not have enough capacity for the content of
      // the TypedArray.
      size_t bytes_to_copy = self->byte_length();
      CHECK_LE(bytes_to_copy, storage.size());
      const uint8_t* source =
          reinterpret_cast<uint8_t*>(typed_array->DataPtr());
      memcpy(reinterpret_cast<void*>(storage.data()), source, bytes_to_copy);
      return {storage.data(), bytes_to_copy};
    }
    // The TypedArray already has off-heap storage, just return a view on it.
    return {reinterpret_cast<uint8_t*>(typed_array->DataPtr()),
            typed_array->GetByteLength()};
  }
  if (i::IsJSDataView(*self)) {
    i::Tagged<i::JSDataView> data_view = i::Cast<i::JSDataView>(*self);
    return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
            data_view->byte_length()};
  }
  // Other types of ArrayBufferView always have an off-heap storage.
  DCHECK(i::IsJSRabGsabDataView(*self));
  i::Tagged<i::JSRabGsabDataView> data_view =
      i::Cast<i::JSRabGsabDataView>(*self);
  return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
          data_view->GetByteLength()};
}

bool v8::ArrayBufferView::HasBuffer() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSTypedArray(*self)) return true;
  auto typed_array = i::Cast<i::JSTypedArray>(self);
  return !typed_array->is_on_heap();
}

size_t v8::ArrayBufferView::ByteOffset() {
  auto obj = Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->byte_offset();
}

size_t v8::ArrayBufferView::ByteLength() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSArrayBufferView> obj = *Utils::OpenDirectHandle(this);
  if (obj->WasDetached()) {
    return 0;
  }
  if (i::IsJSTypedArray(obj)) {
    return i::Cast<i::JSTypedArray>(obj)->GetByteLength();
  }
  if (i::IsJSDataView(obj)) {
    return i::Cast<i::JSDataView>(obj)->byte_length();
  }
  return i::Cast<i::JSRabGsabDataView>(obj)->GetByteLength();
}

size_t v8::TypedArray::Length() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSTypedArray> obj = *Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->GetLength();
}

static_assert(v8::TypedArray::kMaxByteLength == i::JSTypedArray::kMaxByteLength,
              "v8::TypedArray::kMaxByteLength must match "
              "i::JSTypedArray::kMaxByteLength");

#define TYPED_ARRAY_NEW(Type, type, TYPE, ctype)                            \
  Local<Type##Array> Type##Array::New(Local<ArrayBuffer> array_buffer,      \
                                      size_t byte_offset, size_t length) {  \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*array_buffer)->GetIsolate();               \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(length <= kMaxLength,                              \
                         "v8::" #Type                                       \
                         "Array::New(Local<ArrayBuffer>, size_t, size_t)",  \
                         "length exceeds max allowed value")) {             \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*array_buffer);                         \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }                                                                         \
  Local<Type##Array> Type##Array::New(                                      \
      Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,     \
      size_t length) {                                                      \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();        \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(                                                   \
            length <= kMaxLength,                                           \
            "v8::" #Type                                                    \
            "Array::New(Local<SharedArrayBuffer>, size_t, size_t)",         \
            "length exceeds max allowed value")) {                          \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*shared_array_buffer);                  \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }

TYPED_ARRAYS_BASE(TYPED_ARRAY_NEW)
#undef TYPED_ARRAY_NEW

Local<Float16Array> Float16Array::New(Local<ArrayBuffer> array_buffer,
                                      size_t byte_offset, size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<ArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}
Local<Float16Array> Float16Array::New(
    Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,
    size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate =
      Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<SharedArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}

// TODO(v8:11111): Support creating length tracking DataViews via the API.
Local<DataView> DataView::New(Local<ArrayBuffer> array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

Local<DataView> DataView::New(Local<SharedArrayBuffer> shared_array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

size_t v8::SharedArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::SharedArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  std::unique_ptr<i::BackingStore> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));

  if (!backing_store) {
    // TODO(jbroman): It may be useful in the future to provide a MaybeLocal
    // version that throws an exception or otherwise does not crash.
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::SharedArrayBuffer::New");
  }

  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store));
  return Utils::ToLocalShared(obj);
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(ToInternal(backing_store));
  Utils::ApiCheck(
      i_backing_store->is_shared(), "v8::SharedArrayBuffer::New",
      "Cannot construct SharedArrayBuffer with BackingStore of ArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocalShared(obj);
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, NewBackingStore);
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::SharedArrayBuffer::NewBackingStore",
      "Cannot construct SharedArrayBuffer, requested length is too big");
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::SharedArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<Symbol> v8::Symbol::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Symbol, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> result = i_isolate->factory()->NewSymbol();
  if (!name.IsEmpty()) result->set_description(*Utils::OpenDirectHandle(*name));
  return Utils::ToLocal(result);
}

Local<Symbol> v8::Symbol::For(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kPublicSymbolTable, i_name, false));
}

Local<Symbol> v8::Symbol::ForApi(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kApiSymbolTable, i_name, false));
}

#define WELL_KNOWN_SYMBOLS(V)                 \
  V(AsyncIterator, async_iterator)            \
  V(HasInstance, has_instance)                \
  V(IsConcatSpreadable, is_concat_spreadable) \
  V(Iterator, iterator)                       \
  V(Match, match)                             \
  V(Replace, replace)                         \
  V(Search, search)                           \
  V(Split, split)                             \
  V(ToPrimitive, to_primitive)                \
  V(ToStringTag, to_string_tag)               \
  V(Unscopables, unscopables)

#define SYMBOL_GETTER(Name, name)                                      \
  Local<Symbol> v8::Symbol::Get##Name(Isolate* v8_isolate) {           \
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate); \
    return Utils::ToLocal(i_isolate->factory()->name##_symbol());      \
  }

WELL_KNOWN_SYMBOLS(SYMBOL_GETTER)

#undef SYMBOL_GETTER
#undef WELL_KNOWN_SYMBOLS

Local<Private> v8::Private::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Private, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> symbol = i_isolate->factory()->NewPrivateSymbol();
  if (!name.IsEmpty()) symbol->set_description(*Utils::OpenDirectHandle(*name));
  Local<
### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
}
    return Just(true);
  }
  ENTER_V8_NO_SCRIPT(i_isolate, context, ArrayBuffer, Detach, i::HandleScope);
  if (!key.IsEmpty()) {
    auto i_key = Utils::OpenHandle(*key);
    constexpr bool kForceForWasmMemory = false;
    has_exception =
        i::JSArrayBuffer::Detach(obj, kForceForWasmMemory, i_key).IsNothing();
  } else {
    has_exception = i::JSArrayBuffer::Detach(obj).IsNothing();
  }
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

void v8::ArrayBuffer::Detach() { Detach(Local<Value>()).Check(); }

void v8::ArrayBuffer::SetDetachKey(v8::Local<v8::Value> key) {
  auto obj = Utils::OpenDirectHandle(this);
  auto i_key = Utils::OpenDirectHandle(*key);
  obj->set_detach_key(*i_key);
}

size_t v8::ArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::ArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

namespace {
i::InitializedFlag GetInitializedFlag(
    BackingStoreInitializationMode initialization_mode) {
  switch (initialization_mode) {
    case BackingStoreInitializationMode::kUninitialized:
      return i::InitializedFlag::kUninitialized;
    case BackingStoreInitializationMode::kZeroInitialized:
      return i::InitializedFlag::kZeroInitialized;
  }
  UNREACHABLE();
}
}  // namespace

MaybeLocal<ArrayBuffer> v8::ArrayBuffer::MaybeNew(
    Isolate* isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, MaybeNew);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    return MaybeLocal<ArrayBuffer>();
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::ArrayBuffer::New");
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(
      ToInternal(std::move(backing_store)));
  Utils::ApiCheck(
      !i_backing_store->is_shared(), "v8_ArrayBuffer_New",
      "Cannot construct ArrayBuffer with a BackingStore of SharedArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocal(obj);
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, NewBackingStore);
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length,
                                i::SharedFlag::kNotShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::ArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
#ifdef V8_ENABLE_SANDBOX
  Utils::ApiCheck(!data || i::GetProcessWideSandbox()->Contains(data),
                  "v8_ArrayBuffer_NewBackingStore",
                  "When the V8 Sandbox is enabled, ArrayBuffer backing stores "
                  "must be allocated inside the sandbox address space. Please "
                  "use an appropriate ArrayBuffer::Allocator to allocate these "
                  "buffers, or disable the sandbox.");
#endif  // V8_ENABLE_SANDBOX

  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kNotShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

// static
std::unique_ptr<BackingStore> v8::ArrayBuffer::NewResizableBackingStore(
    size_t byte_length, size_t max_byte_length) {
  Utils::ApiCheck(byte_length <= max_byte_length,
                  "v8::ArrayBuffer::NewResizableBackingStore",
                  "Cannot construct resizable ArrayBuffer, byte_length must be "
                  "<= max_byte_length");
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::ArrayBuffer::NewResizableBackingStore",
      "Cannot construct resizable ArrayBuffer, requested length is too big");

  size_t page_size, initial_pages, max_pages;
  if (i::JSArrayBuffer::GetResizableBackingStorePageConfiguration(
          nullptr, byte_length, max_byte_length, i::kDontThrow, &page_size,
          &initial_pages, &max_pages)
          .IsNothing()) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::TryAllocateAndPartiallyCommitMemory(
          nullptr, byte_length, max_byte_length, page_size, initial_pages,
          max_pages, i::WasmMemoryFlag::kNotWasm, i::SharedFlag::kNotShared);
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<ArrayBuffer> v8::ArrayBufferView::Buffer() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  if (i::IsJSDataView(*obj)) {
    i::DirectHandle<i::JSDataView> data_view(i::Cast<i::JSDataView>(*obj),
                                             i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else if (i::IsJSRabGsabDataView(*obj)) {
    i::DirectHandle<i::JSRabGsabDataView> data_view(
        i::Cast<i::JSRabGsabDataView>(*obj), i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else {
    DCHECK(IsJSTypedArray(*obj));
    return Utils::ToLocal(i::Cast<i::JSTypedArray>(*obj)->GetBuffer());
  }
}

size_t v8::ArrayBufferView::CopyContents(void* dest, size_t byte_length) {
  auto self = Utils::OpenDirectHandle(this);
  size_t bytes_to_copy = std::min(byte_length, self->byte_length());
  if (bytes_to_copy) {
    i::DisallowGarbageCollection no_gc;
    const char* source;
    if (i::IsJSTypedArray(*self)) {
      i::Tagged<i::JSTypedArray> array = i::Cast<i::JSTypedArray>(*self);
      source = reinterpret_cast<char*>(array->DataPtr());
    } else {
      DCHECK(i::IsJSDataView(*self) || i::IsJSRabGsabDataView(*self));
      i::Tagged<i::JSDataViewOrRabGsabDataView> data_view =
          i::Cast<i::JSDataViewOrRabGsabDataView>(*self);
      source = reinterpret_cast<char*>(data_view->data_pointer());
    }
    memcpy(dest, source, bytes_to_copy);
  }
  return bytes_to_copy;
}

v8::MemorySpan<uint8_t> v8::ArrayBufferView::GetContents(
    v8::MemorySpan<uint8_t> storage) {
  internal::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  if (self->WasDetached()) {
    return {};
  }
  if (internal::IsJSTypedArray(*self)) {
    i::Tagged<i::JSTypedArray> typed_array = i::Cast<i::JSTypedArray>(*self);
    if (typed_array->is_on_heap()) {
      // The provided storage does not have enough capacity for the content of
      // the TypedArray.
      size_t bytes_to_copy = self->byte_length();
      CHECK_LE(bytes_to_copy, storage.size());
      const uint8_t* source =
          reinterpret_cast<uint8_t*>(typed_array->DataPtr());
      memcpy(reinterpret_cast<void*>(storage.data()), source, bytes_to_copy);
      return {storage.data(), bytes_to_copy};
    }
    // The TypedArray already has off-heap storage, just return a view on it.
    return {reinterpret_cast<uint8_t*>(typed_array->DataPtr()),
            typed_array->GetByteLength()};
  }
  if (i::IsJSDataView(*self)) {
    i::Tagged<i::JSDataView> data_view = i::Cast<i::JSDataView>(*self);
    return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
            data_view->byte_length()};
  }
  // Other types of ArrayBufferView always have an off-heap storage.
  DCHECK(i::IsJSRabGsabDataView(*self));
  i::Tagged<i::JSRabGsabDataView> data_view =
      i::Cast<i::JSRabGsabDataView>(*self);
  return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
          data_view->GetByteLength()};
}

bool v8::ArrayBufferView::HasBuffer() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSTypedArray(*self)) return true;
  auto typed_array = i::Cast<i::JSTypedArray>(self);
  return !typed_array->is_on_heap();
}

size_t v8::ArrayBufferView::ByteOffset() {
  auto obj = Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->byte_offset();
}

size_t v8::ArrayBufferView::ByteLength() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSArrayBufferView> obj = *Utils::OpenDirectHandle(this);
  if (obj->WasDetached()) {
    return 0;
  }
  if (i::IsJSTypedArray(obj)) {
    return i::Cast<i::JSTypedArray>(obj)->GetByteLength();
  }
  if (i::IsJSDataView(obj)) {
    return i::Cast<i::JSDataView>(obj)->byte_length();
  }
  return i::Cast<i::JSRabGsabDataView>(obj)->GetByteLength();
}

size_t v8::TypedArray::Length() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSTypedArray> obj = *Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->GetLength();
}

static_assert(v8::TypedArray::kMaxByteLength == i::JSTypedArray::kMaxByteLength,
              "v8::TypedArray::kMaxByteLength must match "
              "i::JSTypedArray::kMaxByteLength");

#define TYPED_ARRAY_NEW(Type, type, TYPE, ctype)                            \
  Local<Type##Array> Type##Array::New(Local<ArrayBuffer> array_buffer,      \
                                      size_t byte_offset, size_t length) {  \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*array_buffer)->GetIsolate();               \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(length <= kMaxLength,                              \
                         "v8::" #Type                                       \
                         "Array::New(Local<ArrayBuffer>, size_t, size_t)",  \
                         "length exceeds max allowed value")) {             \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*array_buffer);                         \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }                                                                         \
  Local<Type##Array> Type##Array::New(                                      \
      Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,     \
      size_t length) {                                                      \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();        \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(                                                   \
            length <= kMaxLength,                                           \
            "v8::" #Type                                                    \
            "Array::New(Local<SharedArrayBuffer>, size_t, size_t)",         \
            "length exceeds max allowed value")) {                          \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*shared_array_buffer);                  \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }

TYPED_ARRAYS_BASE(TYPED_ARRAY_NEW)
#undef TYPED_ARRAY_NEW

Local<Float16Array> Float16Array::New(Local<ArrayBuffer> array_buffer,
                                      size_t byte_offset, size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<ArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}
Local<Float16Array> Float16Array::New(
    Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,
    size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate =
      Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<SharedArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}

// TODO(v8:11111): Support creating length tracking DataViews via the API.
Local<DataView> DataView::New(Local<ArrayBuffer> array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

Local<DataView> DataView::New(Local<SharedArrayBuffer> shared_array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

size_t v8::SharedArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::SharedArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  std::unique_ptr<i::BackingStore> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));

  if (!backing_store) {
    // TODO(jbroman): It may be useful in the future to provide a MaybeLocal
    // version that throws an exception or otherwise does not crash.
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::SharedArrayBuffer::New");
  }

  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store));
  return Utils::ToLocalShared(obj);
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(ToInternal(backing_store));
  Utils::ApiCheck(
      i_backing_store->is_shared(), "v8::SharedArrayBuffer::New",
      "Cannot construct SharedArrayBuffer with BackingStore of ArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocalShared(obj);
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, NewBackingStore);
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::SharedArrayBuffer::NewBackingStore",
      "Cannot construct SharedArrayBuffer, requested length is too big");
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::SharedArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<Symbol> v8::Symbol::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Symbol, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> result = i_isolate->factory()->NewSymbol();
  if (!name.IsEmpty()) result->set_description(*Utils::OpenDirectHandle(*name));
  return Utils::ToLocal(result);
}

Local<Symbol> v8::Symbol::For(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kPublicSymbolTable, i_name, false));
}

Local<Symbol> v8::Symbol::ForApi(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kApiSymbolTable, i_name, false));
}

#define WELL_KNOWN_SYMBOLS(V)                 \
  V(AsyncIterator, async_iterator)            \
  V(HasInstance, has_instance)                \
  V(IsConcatSpreadable, is_concat_spreadable) \
  V(Iterator, iterator)                       \
  V(Match, match)                             \
  V(Replace, replace)                         \
  V(Search, search)                           \
  V(Split, split)                             \
  V(ToPrimitive, to_primitive)                \
  V(ToStringTag, to_string_tag)               \
  V(Unscopables, unscopables)

#define SYMBOL_GETTER(Name, name)                                      \
  Local<Symbol> v8::Symbol::Get##Name(Isolate* v8_isolate) {           \
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate); \
    return Utils::ToLocal(i_isolate->factory()->name##_symbol());      \
  }

WELL_KNOWN_SYMBOLS(SYMBOL_GETTER)

#undef SYMBOL_GETTER
#undef WELL_KNOWN_SYMBOLS

Local<Private> v8::Private::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Private, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> symbol = i_isolate->factory()->NewPrivateSymbol();
  if (!name.IsEmpty()) symbol->set_description(*Utils::OpenDirectHandle(*name));
  Local<Symbol> result = Utils::ToLocal(symbol);
  return result.UnsafeAs<Private>();
}

Local<Private> v8::Private::ForApi(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  Local<Symbol> result = Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kApiPrivateSymbolTable, i_name, true));
  return result.UnsafeAs<Private>();
}

Local<Number> v8::Number::New(Isolate* v8_isolate, double value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (std::isnan(value)) {
    // Introduce only canonical NaN value into the VM, to avoid signaling NaNs.
    value = std::numeric_limits<double>::quiet_NaN();
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::NumberToLocal(result);
}

Local<Integer> v8::Integer::New(Isolate* v8_isolate, int32_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::Smi::IsValid(value)) {
    return Utils::IntegerToLocal(
        i::Handle<i::Object>(i::Smi::FromInt(value), i_isolate));
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::IntegerToLocal(result);
}

Local<Integer> v8::Integer::NewFromUnsigned(Isolate* v8_isolate,
                                            uint32_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  bool fits_into_int32_t = (value & (1 << 31)) == 0;
  if (fits_into_int32_t) {
    return Integer::New(v8_isolate, static_cast<int32_t>(value));
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::IntegerToLocal(result);
}

Local<BigInt> v8::BigInt::New(Isolate* v8_isolate, int64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::BigInt> result = i::BigInt::FromInt64(i_isolate, value);
  return Utils::ToLocal(result);
}

Local<BigInt> v8::BigInt::NewFromUnsigned(Isolate* v8_isolate, uint64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::BigInt> result = i::BigInt::FromUint64(i_isolate, value);
  return Utils::ToLocal(result);
}

MaybeLocal<BigInt> v8::BigInt::NewFromWords(Local<Context> context,
                                            int sign_bit, int word_count,
                                            const uint64_t* words) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, BigInt, NewFromWords,
                     InternalEscapableScope);
  i::MaybeHandle<i::BigInt> result =
      i::BigInt::FromWords64(i_isolate, sign_bit, word_count, words);
  has_exception = result.is_null();
  RETURN_ON_FAILED_EXECUTION(BigInt);
  RETURN_ESCAPED(Utils::ToLocal(result.ToHandleChecked()));
}

uint64_t v8::BigInt::Uint64Value(bool* lossless) const {
  return Utils::OpenDirectHandle(this)->AsUint64(lossless);
}

int64_t v8::BigInt::Int64Value(bool* lossless) const {
  return Utils::OpenDirectHandle(this)->AsInt64(lossless);
}

int BigInt::WordCount() const {
  return Utils::OpenDirectHandle(this)->Words64Count();
}

void BigInt::ToWordsArray(int* sign_bit, int* word_count,
                          uint64_t* words) const {
  // TODO(saelo): consider migrating the public API to also use uint32_t or
  // size_t for length and count values.
  uint32_t unsigned_word_count = *word_count;
  Utils::OpenDirectHandle(this)->ToWordsArray64(sign_bit, &unsigned_word_count,
                                                words);
  *word_count = base::checked_cast<int>(unsigned_word_count);
}

void Isolate::HandleExternalMemoryInterrupt() {
  i::Heap* heap = reinterpret_cast<i::Isolate*>(this)->heap();
  if (heap->gc_state() != i::Heap::NOT_IN_GC) return;
  heap->HandleExternalMemoryInterrupt();
}

HeapProfiler* Isolate::GetHeapProfiler() {
  i::HeapProfiler* heap_profiler =
      reinterpret_cast<i::Isolate*>(this)->heap_profiler();
  return reinterpret_cast<HeapProfiler*>(heap_profiler);
}

void Isolate::SetIdle(bool is_idle) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetIdle(is_idle);
}

ArrayBuffer::Allocator* Isolate::GetArrayBufferAllocator() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->array_buffer_allocator();
}

bool Isolate::InContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return !i_isolate->context().is_null();
}

void Isolate::ClearKeptObjects() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->ClearKeptObjects();
}

v8::Local<v8::Context> Isolate::GetCurrentContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Tagged<i::Context> context = i_isolate->context();
  if (context.is_null()) return Local<Context>();
  i::Tagged<i::NativeContext> native_context = context->native_context();
  return Utils::ToLocal(i::direct_handle(native_context, i_isolate));
}

// TODO(ishell): rename back to GetEnteredContext().
v8::Local<v8::Context> Isolate::GetEnteredOrMicrotaskContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::NativeContext> last =
      i_isolate->handle_scope_implementer()->LastEnteredContext();
  if (last.is_null()) return Local<Context>();
  return Utils::ToLocal(last);
}

v8::Local<v8::Context> Isolate::GetIncumbentContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::NativeContext> context = i_isolate->GetIncumbentContext();
  return Utils::ToLocal(context);
}

v8::MaybeLocal<v8::Data> Isolate::GetCurrentHostDefinedOptions() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::Script> script;
  if (!i_isolate->CurrentReferrerScript().ToHandle(&script)) {
    return MaybeLocal<v8::Data>();
  }
  return ToApiHandle<Data>(
      i::direct_handle(script->host_defined_options(), i_isolate));
}

v8::Local<Value> Isolate::ThrowError(v8::Local<v8::String> message) {
  return ThrowException(v8::Exception::Error(message));
}

v8::Local<Value> Isolate::ThrowException(v8::Local<v8::Value> value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_BASIC(i_isolate);
  i_isolate->clear_internal_exception();
  // If we're passed an empty handle, we throw an undefined exception
  // to deal more gracefully with out of memory situations.
  if (value.IsEmpty()) {
    i_isolate->Throw(i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    i_isolate->Throw(*Utils::OpenDirectHandle(*value));
  }
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
}

bool Isolate::HasPendingException() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i_isolate->has_exception()) {
    return true;
  }
  v8::TryCatch* try_catch_handler =
      i_isolate->thread_local_top()->try_catch_handler_;
  return try_catch_handler && try_catch_handler->HasCaught();
}

void Isolate::AddGCPrologueCallback(GCCallbackWithData callback, void* data,
                                    GCType gc_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddGCPrologueCallback(callback, gc_type, data);
}

void Isolate::RemoveGCPrologueCallback(GCCallbackWithData callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveGCPrologueCallback(callback, data);
}

void Isolate::AddGCEpilogueCallback(GCCallbackWithData callback, void* data,
                                    GCType gc_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddGCEpilogueCallback(callback, gc_type, data);
}

void Isolate::RemoveGCEpilogueCallback(GCCallbackWithData callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveGCEpilogueCallback(callback, data);
}

static void CallGCCallbackWithoutData(Isolate* v8_isolate, GCType type,
                                      GCCallbackFlags flags, void* data) {
  reinterpret_cast<Isolate::GCCallback>(data)(v8_isolate, type, flags);
}

void Isolate::AddGCPrologueCallback(GCCallback callback, GCType gc_type) {
  void* data = reinterpret_cast<void*>(callback);
  AddGCPrologueCallback(CallGCCallbackWithoutData, data, gc_type);
}

void Isolate::RemoveGCPrologueCallback(GCCallback callback) {
  void* data = reinterpret_cast<void*>(callback);
  RemoveGCPrologueCallback(CallGCCallbackWithoutData, data);
}

void Isolate::AddGCEpilogueCallback(GCCallback callback, GCType gc_type) {
  void* data = reinterpret_cast<void*>(callback);
  AddGCEpilogueCallback(CallGCCallbackWithoutData, data, gc_type);
}

void Isolate::RemoveGCEpilogueCallback(GCCallback callback) {
  void* data = reinterpret_cast<void*>(callback);
  RemoveGCEpilogueCallback(CallGCCallbackWithoutData, data);
}

void Isolate::SetEmbedderRootsHandler(EmbedderRootsHandler* handler) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->SetEmbedderRootsHandler(handler);
}

void Isolate::AttachCppHeap(CppHeap* cpp_heap) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isol
```