Response:
Let's break down the thought process for analyzing the `v8-array-buffer.h` header file.

**1. Initial Scan and Identification of Key Entities:**

The first step is to quickly scan the code for major classes and concepts. Keywords like `class`, `enum`, `struct`, and `using` are good starting points. I see:

* `BackingStore`: This seems fundamental, dealing with raw memory.
* `ArrayBuffer`:  Likely the core JavaScript `ArrayBuffer` object in V8.
* `ArrayBuffer::Allocator`:  Handles memory allocation for `ArrayBuffer`.
* `ArrayBufferView`: A base class for views on `ArrayBuffer` (like TypedArrays).
* `DataView`: A specific type of `ArrayBufferView`.
* `SharedArrayBuffer`:  Deals with shared memory.

**2. Understanding the Relationship between Entities:**

Next, I try to understand how these classes relate to each other. The comments are helpful here.

* `BackingStore` is "a wrapper around the backing store (i.e. the raw memory) of an array buffer."  This means `ArrayBuffer` *uses* a `BackingStore`.
* `ArrayBufferView` is a "base class for an instance of one of 'views' over ArrayBuffer." This establishes an inheritance relationship. `DataView` inherits from `ArrayBufferView`.
* The `ArrayBuffer::Allocator` is specifically responsible for allocating memory for `ArrayBuffer`.

**3. Analyzing Each Class in Detail:**

Now, I go through each class and examine its members (methods, data members, nested types).

* **`BackingStore`:**
    * Focus on methods like `Data()`, `ByteLength()`, `MaxByteLength()`, `IsShared()`, `IsResizableByUserJavaScript()`. These tell me about the properties of the underlying memory.
    * The `Reallocate` method is deprecated, which is important to note.
    * The `DeleterCallback` and `EmptyDeleter` suggest ways to manage the lifetime of the backing memory, especially for externally managed memory.

* **`ArrayBuffer`:**
    * The `Allocator` nested class is crucial for memory management. Its virtual methods (`Allocate`, `AllocateUninitialized`, `Free`, `Reallocate`) define the allocation interface.
    * The `MaybeNew` and `New` static methods are how `ArrayBuffer` instances are created. They take size and initialization mode as arguments, or a `BackingStore`.
    * `NewBackingStore` methods allow creating a standalone `BackingStore`.
    * Methods like `IsDetachable()`, `WasDetached()`, and `Detach()` relate to detaching the buffer.
    * `GetBackingStore()` provides access to the underlying `BackingStore`.

* **`ArrayBufferView`:**
    * `Buffer()`, `ByteOffset()`, and `ByteLength()` are fundamental properties of a view.
    * `CopyContents()` and `GetContents()` are for accessing the data.

* **`DataView`:**
    *  Has `New` methods that take either `ArrayBuffer` or `SharedArrayBuffer`. This confirms it can view both.

* **`SharedArrayBuffer`:**
    * Similar structure to `ArrayBuffer` but specifically for shared memory. It also has `New` and `NewBackingStore` methods.

**4. Connecting to JavaScript:**

With an understanding of the C++ structure, I can connect it to JavaScript concepts.

* `ArrayBuffer` in C++ directly corresponds to the `ArrayBuffer` object in JavaScript.
* `SharedArrayBuffer` in C++ corresponds to the `SharedArrayBuffer` object in JavaScript.
* `ArrayBufferView` is the base for JavaScript TypedArray types (`Uint8Array`, `Int32Array`, etc.) and `DataView`.
* The `byteLength` property in JavaScript maps to the `ByteLength()` methods.

**5. Considering `.tq` Files:**

The prompt mentions `.tq` files (Torque). I know Torque is a V8-specific language for writing built-in functions. If the file *were* a `.tq` file, it would mean the code inside directly implements some of the JavaScript functionality related to ArrayBuffers. Since this is a `.h` file, it's just the *interface* (declarations), not the implementation.

**6. Generating Examples and Error Scenarios:**

Now I can construct JavaScript examples to illustrate the functionality. I also think about common errors developers might make:

* Incorrectly managing `BackingStore` lifetime.
* Trying to access a detached `ArrayBuffer`.
* Providing invalid offsets or lengths when creating views.
* Not understanding the difference between `ArrayBuffer` and `SharedArrayBuffer`.

**7. Review and Refinement:**

Finally, I review my analysis, ensuring clarity, accuracy, and completeness. I double-check the connections between C++ and JavaScript and make sure the examples are relevant and easy to understand. I also ensure I've addressed all parts of the prompt (functionality, `.tq`, JavaScript examples, assumptions, errors).

This iterative process of scanning, understanding relationships, detailed analysis, connecting to JavaScript, and generating examples allows me to effectively dissect and explain the functionality of the `v8-array-buffer.h` file.
This header file, `v8/include/v8-array-buffer.h`, defines the C++ interface for V8's representation of JavaScript ArrayBuffer and related concepts like SharedArrayBuffer and ArrayBufferView. Let's break down its functionalities:

**Core Functionality:**

1. **Representing Raw Memory:** At its heart, this file defines how V8 manages raw blocks of memory that can be accessed from JavaScript. This is the core purpose of `ArrayBuffer` and `SharedArrayBuffer`.

2. **`BackingStore` Class:** This class is a crucial abstraction representing the underlying raw memory of an array buffer. It manages:
   - **Data Pointer:**  Provides access to the start of the memory block (`Data()`).
   - **Byte Length:**  Stores the current size of the memory block (`ByteLength()`).
   - **Maximum Byte Length:** For resizable buffers, this indicates the maximum allowed size (`MaxByteLength()`).
   - **Shared Status:**  Indicates if the backing store is for a `SharedArrayBuffer` (`IsShared()`).
   - **Resizability:**  Indicates if the buffer can be resized from JavaScript (`IsResizableByUserJavaScript()`).
   - **Memory Management:**  Includes mechanisms for allocation (`ArrayBuffer::Allocator`) and deallocation (`DeleterCallback`).

3. **`ArrayBuffer` Class:** This class represents the JavaScript `ArrayBuffer` object. It provides:
   - **Creation:** Static methods (`New`, `MaybeNew`, `NewBackingStore`) to create `ArrayBuffer` instances, either allocating new memory or wrapping existing memory.
   - **Size Information:** Access to the buffer's `ByteLength()` and `MaxByteLength()`.
   - **Detachment:**  Methods (`IsDetachable()`, `WasDetached()`, `Detach()`, `SetDetachKey()`) to detach the buffer, making its memory inaccessible. This is important for security and resource management.
   - **Backing Store Access:**  Provides `GetBackingStore()` to retrieve the associated `BackingStore` object.
   - **Data Access:**  Offers a shortcut `Data()` to get the raw memory pointer (valid while the `ArrayBuffer` is alive).

4. **`SharedArrayBuffer` Class:** This class represents the JavaScript `SharedArrayBuffer` object, allowing memory to be shared between different JavaScript execution contexts (e.g., web workers). Its functionality is similar to `ArrayBuffer` but with the key difference being its shared nature.

5. **`ArrayBufferView` Class:** This is an abstract base class for "views" into an `ArrayBuffer` or `SharedArrayBuffer`. This includes:
   - **Typed Arrays:** (like `Uint8Array`, `Int32Array`, etc. - although their specific classes are defined elsewhere)
   - **`DataView`:** Provides methods for reading and writing data at specific byte offsets with control over endianness.
   - **Common Properties:** It provides access to the underlying `Buffer()`, the `ByteOffset()` within the buffer, and the `ByteLength()` of the view.
   - **Data Copying:** Offers `CopyContents()` to copy data to an external memory location.
   - **Content Retrieval:** Provides `GetContents()` to get a `MemorySpan` of the underlying data.

6. **`DataView` Class:**  A concrete implementation of `ArrayBufferView` that allows for reading and writing data with specific formats (e.g., `getInt32`, `setFloat64`).

7. **`ArrayBuffer::Allocator` Class:** Defines an interface for allocating and freeing memory used by `ArrayBuffer` objects. This allows embedders (the applications using V8) to customize memory management.

**Is `v8/include/v8-array-buffer.h` a Torque source file?**

No, the filename ends with `.h`, which is the standard convention for C++ header files. Torque source files typically end with `.tq`.

**Relationship with JavaScript Functionality and Examples:**

Yes, this header file directly relates to the JavaScript `ArrayBuffer`, `SharedArrayBuffer`, and Typed Array/DataView functionality.

**JavaScript Examples:**

```javascript
// Creating an ArrayBuffer
const buffer = new ArrayBuffer(16); // Creates a 16-byte buffer

// Creating a Typed Array view
const uint8View = new Uint8Array(buffer);
uint8View[0] = 42;
console.log(uint8View[0]); // Output: 42

// Creating a DataView
const dataView = new DataView(buffer);
dataView.setInt32(4, 12345, true); // Write an integer at offset 4 (little-endian)
console.log(dataView.getInt32(4, true)); // Output: 12345

// Creating a SharedArrayBuffer
const sharedBuffer = new SharedArrayBuffer(32);

// Detaching an ArrayBuffer (requires externalization)
// (Note: Directly detaching a newly created ArrayBuffer isn't typical,
//  it's often used with buffers obtained from external sources)
let detachableBuffer = new ArrayBuffer(8);
// In a real scenario, detachableBuffer would likely be associated with
// external memory managed by the embedder.
// ... some logic to externalize the buffer ...
// detachableBuffer.detach(); // This would detach the buffer
```

**Code Logic Reasoning (with Assumptions):**

Let's consider the `ArrayBuffer::NewBackingStore` function:

**Assumptions:**

* `isolate` is a valid pointer to a V8 isolate.
* `byte_length` is a non-negative integer representing the desired size in bytes.
* `BackingStoreInitializationMode::kZeroInitialized` is used.

**Input:** `isolate`, `byte_length` (e.g., 1024), `BackingStoreInitializationMode::kZeroInitialized`

**Logic:**

1. V8 will attempt to use the `ArrayBuffer::Allocator` associated with the `isolate` to allocate `byte_length` bytes of memory.
2. Since `kZeroInitialized` is specified, the allocated memory will be filled with zeros.
3. A new `BackingStore` object will be created, wrapping this allocated memory.
4. A `std::unique_ptr<BackingStore>` will be returned, managing the lifetime of the `BackingStore` and the underlying memory.

**Output:** A `std::unique_ptr<BackingStore>` pointing to a `BackingStore` object that holds a 1024-byte block of zero-initialized memory.

**User-Common Programming Errors:**

1. **Accessing Detached Buffers:**

   ```javascript
   const buffer = new ArrayBuffer(10);
   // ... some logic to detach the buffer ...
   const view = new Uint8Array(buffer);
   console.log(view[0]); // Potential error: Accessing a detached buffer
   ```
   **Error:**  After detaching an `ArrayBuffer`, any attempts to access it or its views will result in a runtime error.

2. **Incorrect Offset or Length in Views:**

   ```javascript
   const buffer = new ArrayBuffer(16);
   const view = new Int32Array(buffer, 8, 8); // Error: Length is too large
   ```
   **Error:** When creating views, the `byteOffset` and `length` must be within the bounds of the underlying `ArrayBuffer`. In this example, an `Int32Array` of length 8 starting at offset 8 would require 8 * 4 = 32 bytes, but the remaining buffer size is only 8 bytes.

3. **Mixing `ArrayBuffer` and `SharedArrayBuffer` incorrectly:**

   ```javascript
   const buffer1 = new ArrayBuffer(10);
   const buffer2 = new SharedArrayBuffer(10);

   // Error: Cannot create a Shared Int32 Array on a regular ArrayBuffer
   const sharedView = new Int32Array.Shared(buffer1);

   // Error: Cannot create a regular Int32 Array on a SharedArrayBuffer (in some contexts)
   const regularView = new Int32Array(buffer2);
   ```
   **Error:**  You need to use the appropriate constructors for creating views on `ArrayBuffer` and `SharedArrayBuffer`. `Int32Array.Shared` is for `SharedArrayBuffer`, and `Int32Array` is typically for `ArrayBuffer`.

4. **Memory Leaks (when using custom allocators):** If you provide a custom `ArrayBuffer::Allocator`, you must ensure that the `Free` method correctly releases the allocated memory to prevent memory leaks.

5. **Data Races with `SharedArrayBuffer`:**  When working with `SharedArrayBuffer` across multiple threads or workers, you need to be very careful about data races. Use synchronization primitives (like Atomics) to ensure data integrity.

In summary, `v8/include/v8-array-buffer.h` is a fundamental header file defining the C++ interface for managing raw memory buffers in V8, directly supporting the `ArrayBuffer` and related features in JavaScript. Understanding this header provides insight into how V8 handles memory at a lower level.

### 提示词
```
这是目录为v8/include/v8-array-buffer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-array-buffer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_ARRAY_BUFFER_H_
#define INCLUDE_V8_ARRAY_BUFFER_H_

#include <stddef.h>

#include <memory>

#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-memory-span.h"   // NOLINT(build/include_directory)
#include "v8-object.h"        // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class SharedArrayBuffer;

#ifndef V8_ARRAY_BUFFER_INTERNAL_FIELD_COUNT
// Defined using gn arg `v8_array_buffer_internal_field_count`.
#define V8_ARRAY_BUFFER_INTERNAL_FIELD_COUNT 2
#endif

enum class ArrayBufferCreationMode { kInternalized, kExternalized };
enum class BackingStoreInitializationMode { kZeroInitialized, kUninitialized };

/**
 * A wrapper around the backing store (i.e. the raw memory) of an array buffer.
 * See a document linked in http://crbug.com/v8/9908 for more information.
 *
 * The allocation and destruction of backing stores is generally managed by
 * V8. Clients should always use standard C++ memory ownership types (i.e.
 * std::unique_ptr and std::shared_ptr) to manage lifetimes of backing stores
 * properly, since V8 internal objects may alias backing stores.
 *
 * This object does not keep the underlying |ArrayBuffer::Allocator| alive by
 * default. Use Isolate::CreateParams::array_buffer_allocator_shared when
 * creating the Isolate to make it hold a reference to the allocator itself.
 */
class V8_EXPORT BackingStore : public v8::internal::BackingStoreBase {
 public:
  ~BackingStore();

  /**
   * Return a pointer to the beginning of the memory block for this backing
   * store. The pointer is only valid as long as this backing store object
   * lives.
   */
  void* Data() const;

  /**
   * The length (in bytes) of this backing store.
   */
  size_t ByteLength() const;

  /**
   * The maximum length (in bytes) that this backing store may grow to.
   *
   * If this backing store was created for a resizable ArrayBuffer or a growable
   * SharedArrayBuffer, it is >= ByteLength(). Otherwise it is ==
   * ByteLength().
   */
  size_t MaxByteLength() const;

  /**
   * Indicates whether the backing store was created for an ArrayBuffer or
   * a SharedArrayBuffer.
   */
  bool IsShared() const;

  /**
   * Indicates whether the backing store was created for a resizable ArrayBuffer
   * or a growable SharedArrayBuffer, and thus may be resized by user JavaScript
   * code.
   */
  bool IsResizableByUserJavaScript() const;

  /**
   * Prevent implicit instantiation of operator delete with size_t argument.
   * The size_t argument would be incorrect because ptr points to the
   * internal BackingStore object.
   */
  void operator delete(void* ptr) { ::operator delete(ptr); }

  /**
   * Wrapper around ArrayBuffer::Allocator::Reallocate that preserves IsShared.
   * Assumes that the backing_store was allocated by the ArrayBuffer allocator
   * of the given isolate.
   */
  V8_DEPRECATED(
      "Reallocate is unsafe, please do not use. Please allocate a new "
      "BackingStore and copy instead.")
  static std::unique_ptr<BackingStore> Reallocate(
      v8::Isolate* isolate, std::unique_ptr<BackingStore> backing_store,
      size_t byte_length);

  /**
   * This callback is used only if the memory block for a BackingStore cannot be
   * allocated with an ArrayBuffer::Allocator. In such cases the destructor of
   * the BackingStore invokes the callback to free the memory block.
   */
  using DeleterCallback = void (*)(void* data, size_t length,
                                   void* deleter_data);

  /**
   * If the memory block of a BackingStore is static or is managed manually,
   * then this empty deleter along with nullptr deleter_data can be passed to
   * ArrayBuffer::NewBackingStore to indicate that.
   *
   * The manually managed case should be used with caution and only when it
   * is guaranteed that the memory block freeing happens after detaching its
   * ArrayBuffer.
   */
  static void EmptyDeleter(void* data, size_t length, void* deleter_data);

 private:
  /**
   * See [Shared]ArrayBuffer::GetBackingStore and
   * [Shared]ArrayBuffer::NewBackingStore.
   */
  BackingStore();
};

#if !defined(V8_IMMINENT_DEPRECATION_WARNINGS)
// Use v8::BackingStore::DeleterCallback instead.
using BackingStoreDeleterCallback = void (*)(void* data, size_t length,
                                             void* deleter_data);

#endif

/**
 * An instance of the built-in ArrayBuffer constructor (ES6 draft 15.13.5).
 */
class V8_EXPORT ArrayBuffer : public Object {
 public:
  /**
   * A thread-safe allocator that V8 uses to allocate |ArrayBuffer|'s memory.
   * The allocator is a global V8 setting. It has to be set via
   * Isolate::CreateParams.
   *
   * Memory allocated through this allocator by V8 is accounted for as external
   * memory by V8. Note that V8 keeps track of the memory for all internalized
   * |ArrayBuffer|s. Responsibility for tracking external memory (using
   * Isolate::AdjustAmountOfExternalAllocatedMemory) is handed over to the
   * embedder upon externalization and taken over upon internalization (creating
   * an internalized buffer from an existing buffer).
   *
   * Note that it is unsafe to call back into V8 from any of the allocator
   * functions.
   */
  class V8_EXPORT Allocator {
   public:
    virtual ~Allocator() = default;

    /**
     * Allocate |length| bytes. Return nullptr if allocation is not successful.
     * Memory should be initialized to zeroes.
     */
    virtual void* Allocate(size_t length) = 0;

    /**
     * Allocate |length| bytes. Return nullptr if allocation is not successful.
     * Memory does not have to be initialized.
     */
    virtual void* AllocateUninitialized(size_t length) = 0;

    /**
     * Free the memory block of size |length|, pointed to by |data|.
     * That memory is guaranteed to be previously allocated by |Allocate|.
     */
    virtual void Free(void* data, size_t length) = 0;

    /**
     * Reallocate the memory block of size |old_length| to a memory block of
     * size |new_length| by expanding, contracting, or copying the existing
     * memory block. If |new_length| > |old_length|, then the new part of
     * the memory must be initialized to zeros. Return nullptr if reallocation
     * is not successful.
     *
     * The caller guarantees that the memory block was previously allocated
     * using Allocate or AllocateUninitialized.
     *
     * The default implementation allocates a new block and copies data.
     */
    V8_DEPRECATED(
        "Reallocate is unsafe, please do not use. Please allocate new memory "
        "and copy instead.")
    virtual void* Reallocate(void* data, size_t old_length, size_t new_length);

    /**
     * ArrayBuffer allocation mode. kNormal is a malloc/free style allocation,
     * while kReservation is for larger allocations with the ability to set
     * access permissions.
     */
    enum class AllocationMode { kNormal, kReservation };

    /**
     * Convenience allocator.
     *
     * When the sandbox is enabled, this allocator will allocate its backing
     * memory inside the sandbox. Otherwise, it will rely on malloc/free.
     *
     * Caller takes ownership, i.e. the returned object needs to be freed using
     * |delete allocator| once it is no longer in use.
     */
    static Allocator* NewDefaultAllocator();
  };

  /**
   * Data length in bytes.
   */
  size_t ByteLength() const;

  /**
   * Maximum length in bytes.
   */
  size_t MaxByteLength() const;

  /**
   * Attempt to create a new ArrayBuffer. Allocate |byte_length| bytes.
   * Allocated memory will be owned by a created ArrayBuffer and
   * will be deallocated when it is garbage-collected,
   * unless the object is externalized. If allocation fails, the Maybe
   * returned will be empty.
   */
  static MaybeLocal<ArrayBuffer> MaybeNew(
      Isolate* isolate, size_t byte_length,
      BackingStoreInitializationMode initialization_mode =
          BackingStoreInitializationMode::kZeroInitialized);

  /**
   * Create a new ArrayBuffer. Allocate |byte_length| bytes, which are either
   * zero-initialized or uninitialized. Allocated memory will be owned by a
   * created ArrayBuffer and will be deallocated when it is garbage-collected,
   * unless the object is externalized.
   */
  static Local<ArrayBuffer> New(
      Isolate* isolate, size_t byte_length,
      BackingStoreInitializationMode initialization_mode =
          BackingStoreInitializationMode::kZeroInitialized);

  /**
   * Create a new ArrayBuffer with an existing backing store.
   * The created array keeps a reference to the backing store until the array
   * is garbage collected. Note that the IsExternal bit does not affect this
   * reference from the array to the backing store.
   *
   * In future IsExternal bit will be removed. Until then the bit is set as
   * follows. If the backing store does not own the underlying buffer, then
   * the array is created in externalized state. Otherwise, the array is created
   * in internalized state. In the latter case the array can be transitioned
   * to the externalized state using Externalize(backing_store).
   */
  static Local<ArrayBuffer> New(Isolate* isolate,
                                std::shared_ptr<BackingStore> backing_store);

  /**
   * Returns a new standalone BackingStore that is allocated using the array
   * buffer allocator of the isolate. The allocation can either be zero
   * intialized, or uninitialized. The result can be later passed to
   * ArrayBuffer::New.
   *
   * If the allocator returns nullptr, then the function may cause GCs in the
   * given isolate and re-try the allocation. If GCs do not help, then the
   * function will crash with an out-of-memory error.
   */
  static std::unique_ptr<BackingStore> NewBackingStore(
      Isolate* isolate, size_t byte_length,
      BackingStoreInitializationMode initialization_mode =
          BackingStoreInitializationMode::kZeroInitialized);
  /**
   * Returns a new standalone BackingStore that takes over the ownership of
   * the given buffer. The destructor of the BackingStore invokes the given
   * deleter callback.
   *
   * The result can be later passed to ArrayBuffer::New. The raw pointer
   * to the buffer must not be passed again to any V8 API function.
   */
  static std::unique_ptr<BackingStore> NewBackingStore(
      void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
      void* deleter_data);

  /**
   * Returns a new resizable standalone BackingStore that is allocated using the
   * array buffer allocator of the isolate. The result can be later passed to
   * ArrayBuffer::New.
   *
   * |byte_length| must be <= |max_byte_length|.
   *
   * This function is usable without an isolate. Unlike |NewBackingStore| calls
   * with an isolate, GCs cannot be triggered, and there are no
   * retries. Allocation failure will cause the function to crash with an
   * out-of-memory error.
   */
  static std::unique_ptr<BackingStore> NewResizableBackingStore(
      size_t byte_length, size_t max_byte_length);

  /**
   * Returns true if this ArrayBuffer may be detached.
   */
  bool IsDetachable() const;

  /**
   * Returns true if this ArrayBuffer has been detached.
   */
  bool WasDetached() const;

  /**
   * Detaches this ArrayBuffer and all its views (typed arrays).
   * Detaching sets the byte length of the buffer and all typed arrays to zero,
   * preventing JavaScript from ever accessing underlying backing store.
   * ArrayBuffer should have been externalized and must be detachable.
   */
  V8_DEPRECATED(
      "Use the version which takes a key parameter (passing a null handle is "
      "ok).")
  void Detach();

  /**
   * Detaches this ArrayBuffer and all its views (typed arrays).
   * Detaching sets the byte length of the buffer and all typed arrays to zero,
   * preventing JavaScript from ever accessing underlying backing store.
   * ArrayBuffer should have been externalized and must be detachable. Returns
   * Nothing if the key didn't pass the [[ArrayBufferDetachKey]] check,
   * Just(true) otherwise.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> Detach(v8::Local<v8::Value> key);

  /**
   * Sets the ArrayBufferDetachKey.
   */
  void SetDetachKey(v8::Local<v8::Value> key);

  /**
   * Get a shared pointer to the backing store of this array buffer. This
   * pointer coordinates the lifetime management of the internal storage
   * with any live ArrayBuffers on the heap, even across isolates. The embedder
   * should not attempt to manage lifetime of the storage through other means.
   *
   * The returned shared pointer will not be empty, even if the ArrayBuffer has
   * been detached. Use |WasDetached| to tell if it has been detached instead.
   */
  std::shared_ptr<BackingStore> GetBackingStore();

  /**
   * More efficient shortcut for
   * GetBackingStore()->IsResizableByUserJavaScript().
   */
  bool IsResizableByUserJavaScript() const;

  /**
   * More efficient shortcut for GetBackingStore()->Data(). The returned pointer
   * is valid as long as the ArrayBuffer is alive.
   */
  void* Data() const;

  V8_INLINE static ArrayBuffer* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<ArrayBuffer*>(value);
  }

  static constexpr int kInternalFieldCount =
      V8_ARRAY_BUFFER_INTERNAL_FIELD_COUNT;
  static constexpr int kEmbedderFieldCount = kInternalFieldCount;

 private:
  ArrayBuffer();
  static void CheckCast(Value* obj);
};

#ifndef V8_ARRAY_BUFFER_VIEW_INTERNAL_FIELD_COUNT
// Defined using gn arg `v8_array_buffer_view_internal_field_count`.
#define V8_ARRAY_BUFFER_VIEW_INTERNAL_FIELD_COUNT 2
#endif

/**
 * A base class for an instance of one of "views" over ArrayBuffer,
 * including TypedArrays and DataView (ES6 draft 15.13).
 */
class V8_EXPORT ArrayBufferView : public Object {
 public:
  /**
   * Returns underlying ArrayBuffer.
   */
  Local<ArrayBuffer> Buffer();
  /**
   * Byte offset in |Buffer|.
   */
  size_t ByteOffset();
  /**
   * Size of a view in bytes.
   */
  size_t ByteLength();

  /**
   * Copy the contents of the ArrayBufferView's buffer to an embedder defined
   * memory without additional overhead that calling ArrayBufferView::Buffer
   * might incur.
   *
   * Will write at most min(|byte_length|, ByteLength) bytes starting at
   * ByteOffset of the underlying buffer to the memory starting at |dest|.
   * Returns the number of bytes actually written.
   */
  size_t CopyContents(void* dest, size_t byte_length);

  /**
   * Returns the contents of the ArrayBufferView's buffer as a MemorySpan. If
   * the contents are on the V8 heap, they get copied into `storage`. Otherwise
   * a view into the off-heap backing store is returned. The provided storage
   * should be at least as large as the maximum on-heap size of a TypedArray,
   * was defined in gn with `typed_array_max_size_in_heap`. The default value is
   * 64 bytes.
   */
  v8::MemorySpan<uint8_t> GetContents(v8::MemorySpan<uint8_t> storage);

  /**
   * Returns true if ArrayBufferView's backing ArrayBuffer has already been
   * allocated.
   */
  bool HasBuffer() const;

  V8_INLINE static ArrayBufferView* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<ArrayBufferView*>(value);
  }

  static constexpr int kInternalFieldCount =
      V8_ARRAY_BUFFER_VIEW_INTERNAL_FIELD_COUNT;
  static const int kEmbedderFieldCount = kInternalFieldCount;

 private:
  ArrayBufferView();
  static void CheckCast(Value* obj);
};

/**
 * An instance of DataView constructor (ES6 draft 15.13.7).
 */
class V8_EXPORT DataView : public ArrayBufferView {
 public:
  static Local<DataView> New(Local<ArrayBuffer> array_buffer,
                             size_t byte_offset, size_t length);
  static Local<DataView> New(Local<SharedArrayBuffer> shared_array_buffer,
                             size_t byte_offset, size_t length);
  V8_INLINE static DataView* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<DataView*>(value);
  }

 private:
  DataView();
  static void CheckCast(Value* obj);
};

/**
 * An instance of the built-in SharedArrayBuffer constructor.
 */
class V8_EXPORT SharedArrayBuffer : public Object {
 public:
  /**
   * Data length in bytes.
   */
  size_t ByteLength() const;

  /**
   * Maximum length in bytes.
   */
  size_t MaxByteLength() const;

  /**
   * Create a new SharedArrayBuffer. Allocate |byte_length| bytes, which are
   * either zero-initialized or uninitialized. Allocated memory will be owned by
   * a created SharedArrayBuffer and will be deallocated when it is
   * garbage-collected, unless the object is externalized.
   */
  static Local<SharedArrayBuffer> New(
      Isolate* isolate, size_t byte_length,
      BackingStoreInitializationMode initialization_mode =
          BackingStoreInitializationMode::kZeroInitialized);

  /**
   * Create a new SharedArrayBuffer with an existing backing store.
   * The created array keeps a reference to the backing store until the array
   * is garbage collected. Note that the IsExternal bit does not affect this
   * reference from the array to the backing store.
   *
   * In future IsExternal bit will be removed. Until then the bit is set as
   * follows. If the backing store does not own the underlying buffer, then
   * the array is created in externalized state. Otherwise, the array is created
   * in internalized state. In the latter case the array can be transitioned
   * to the externalized state using Externalize(backing_store).
   */
  static Local<SharedArrayBuffer> New(
      Isolate* isolate, std::shared_ptr<BackingStore> backing_store);

  /**
   * Returns a new standalone BackingStore that is allocated using the array
   * buffer allocator of the isolate. The allocation can either be zero
   * intialized, or uninitialized. The result can be later passed to
   * SharedArrayBuffer::New.
   *
   * If the allocator returns nullptr, then the function may cause GCs in the
   * given isolate and re-try the allocation. If GCs do not help, then the
   * function will crash with an out-of-memory error.
   */
  static std::unique_ptr<BackingStore> NewBackingStore(
      Isolate* isolate, size_t byte_length,
      BackingStoreInitializationMode initialization_mode =
          BackingStoreInitializationMode::kZeroInitialized);
  /**
   * Returns a new standalone BackingStore that takes over the ownership of
   * the given buffer. The destructor of the BackingStore invokes the given
   * deleter callback.
   *
   * The result can be later passed to SharedArrayBuffer::New. The raw pointer
   * to the buffer must not be passed again to any V8 functions.
   */
  static std::unique_ptr<BackingStore> NewBackingStore(
      void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
      void* deleter_data);

  /**
   * Get a shared pointer to the backing store of this array buffer. This
   * pointer coordinates the lifetime management of the internal storage
   * with any live ArrayBuffers on the heap, even across isolates. The embedder
   * should not attempt to manage lifetime of the storage through other means.
   */
  std::shared_ptr<BackingStore> GetBackingStore();

  /**
   * More efficient shortcut for GetBackingStore()->Data(). The returned pointer
   * is valid as long as the ArrayBuffer is alive.
   */
  void* Data() const;

  V8_INLINE static SharedArrayBuffer* Cast(Value* value) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(value);
#endif
    return static_cast<SharedArrayBuffer*>(value);
  }

  static constexpr int kInternalFieldCount =
      V8_ARRAY_BUFFER_INTERNAL_FIELD_COUNT;

 private:
  SharedArrayBuffer();
  static void CheckCast(Value* obj);
};

}  // namespace v8

#endif  // INCLUDE_V8_ARRAY_BUFFER_H_
```