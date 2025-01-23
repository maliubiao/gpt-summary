Response:
Let's break down the thought process for analyzing the `js-array-buffer.h` file.

1. **Understanding the Context:** The first thing to recognize is the file path: `v8/src/objects/js-array-buffer.h`. This immediately tells us it's part of the V8 JavaScript engine, specifically dealing with the representation of JavaScript ArrayBuffers within the engine's internal object model. The `.h` extension signifies a header file in C++, meaning it defines classes and their members.

2. **Initial Scan for Keywords and Structure:** Quickly scan the file for important keywords and structural elements:
    * `Copyright`: Confirms it's a V8 project file.
    * `#ifndef`, `#define`, `#endif`:  Standard include guards to prevent multiple inclusions.
    * `#include`:  Indicates dependencies on other V8 internal headers (`v8-array-buffer.h`, `v8-typed-array.h`, etc.). This hints at relationships between different V8 concepts.
    * `namespace v8 { namespace internal { ... } }`:  Confirms the namespace.
    * `class`: The core building block. Identify the main classes: `JSArrayBuffer`, `ArrayBufferExtension`, `JSArrayBufferView`, `JSTypedArray`, `JSDataViewOrRabGsabDataView`, `JSDataView`, `JSRabGsabDataView`.
    * `public:`, `private:`: Access modifiers defining the interface and implementation details.
    * `DECL_PRIMITIVE_ACCESSORS`, `DECL_GETTER`, `DECL_BOOLEAN_ACCESSORS`, `DECL_ACCESSORS`: Macros that suggest auto-generated accessor functions for object properties. These are crucial for understanding how to interact with the objects.
    * `static constexpr`: Constants defined at compile time. Look for `kMaxByteLength`.
    * `V8_EXPORT_PRIVATE`:  Indicates functions intended for internal V8 use but might be exposed for specific purposes.
    * `TQ_OBJECT_CONSTRUCTORS`: A macro likely related to object construction, and the `tq` hints at Torque.
    * Comments (`//`): Look for high-level explanations.

3. **Focusing on the Core Class: `JSArrayBuffer`:**  Since the file is named `js-array-buffer.h`, start by deeply analyzing the `JSArrayBuffer` class.
    * **Purpose:** The name itself suggests it represents the JavaScript `ArrayBuffer` object in V8.
    * **Inheritance:** It inherits from `TorqueGeneratedJSArrayBuffer` and `JSAPIObjectWithEmbedderSlots`. This tells us about its ancestry and likely its connection to V8's API and potentially Torque code generation.
    * **Key Properties (Members):** Go through each member defined by the `DECL_*` macros. Understand what each property represents:
        * `byte_length`: The current size of the buffer.
        * `max_byte_length`: The maximum allowed size.
        * `backing_store`: The actual memory where the data is stored.
        * `extension`: A pointer to an `ArrayBufferExtension` object (more on this later).
        * `bit_field`:  Flags for various states. Look for the `DEFINE_TORQUE_GENERATED_JS_ARRAY_BUFFER_FLAGS()` macro to see the specific flags.
        * `is_external`, `is_detachable`, `was_detached`, `is_shared`, `is_resizable_by_js`: Boolean flags describing the buffer's characteristics.
        * `detach_key`: A key used for detaching.
    * **Key Methods:** Analyze the purpose of the important methods:
        * `Setup`:  Initializes the buffer.
        * `Attach`: Attaches a backing store.
        * `Detach`: Detaches the backing store.
        * `GetBackingStore`: Returns the backing store.
        * `EnsureExtension`, `RemoveExtension`: Deal with the `ArrayBufferExtension`.
        * Serialization/deserialization methods.
    * **Constants:**  Note `kMaxByteLength` and its platform-specific definitions.

4. **Understanding Related Classes:** Move on to the other classes and their relationships with `JSArrayBuffer`:
    * **`ArrayBufferExtension`:** The comment block before its definition is crucial. It acts as a container for the backing store and provides metadata for garbage collection. Pay attention to the `Mark`, `YoungMark`, and `accounting_length` members, which are relevant to memory management.
    * **`JSArrayBufferView`:** Represents a view into an `ArrayBuffer`, like `Uint8Array` or `DataView`. It has `byte_offset` and `byte_length`.
    * **`JSTypedArray`:**  Inherits from `JSArrayBufferView` and adds a `length` (in elements) and `base_pointer`. This is the representation for typed arrays like `Uint8Array`.
    * **`JSDataView`, `JSRabGsabDataView`:**  Represent `DataView` objects, which allow reading and writing data at specific byte offsets with different endianness. The "RabGsab" likely refers to Resizable and Growable Shared Array Buffers.

5. **Connecting to JavaScript:**  Once you understand the internal representation, connect it back to the JavaScript concepts. `JSArrayBuffer` directly corresponds to `ArrayBuffer`. `JSTypedArray` corresponds to the various typed array constructors (`Uint8Array`, `Int32Array`, etc.). `JSDataView` corresponds to the `DataView` object. Use simple JavaScript examples to illustrate how these internal classes are used from the JavaScript side.

6. **Torque Considerations:** The presence of `.tq` includes and `TorqueGenerated...` base classes indicates the use of V8's Torque language for generating some of the code. Acknowledge this but don't necessarily need to dive deep into Torque syntax unless explicitly asked. The key takeaway is that some of the implementation is likely generated.

7. **Code Logic and Examples:** For methods like `Detach`, think about the preconditions (e.g., the buffer must be detachable) and the effects (setting length to 0, unregistering the backing store). Create simple hypothetical scenarios with input and expected output.

8. **Common Programming Errors:** Think about how developers typically misuse ArrayBuffers and TypedArrays in JavaScript. Examples include out-of-bounds access, operating on detached buffers, and incorrect type conversions.

9. **Refinement and Organization:**  Structure the answer logically, starting with a high-level overview and then going into details for each class. Use clear headings and bullet points for readability. Ensure accuracy and avoid making assumptions without evidence.

By following this systematic approach, you can effectively analyze a complex C++ header file like `js-array-buffer.h` and extract its key functionalities and relationships to JavaScript.
This header file, `v8/src/objects/js-array-buffer.h`, defines the C++ classes used by the V8 JavaScript engine to represent JavaScript `ArrayBuffer` and related objects like `TypedArray` and `DataView`. Let's break down its functionality:

**Core Functionality:**

* **Represents JavaScript `ArrayBuffer`:** The primary class `JSArrayBuffer` is the core representation of the `ArrayBuffer` object in JavaScript. It manages the underlying memory buffer.
* **Manages Backing Store:** It holds a `backing_store`, which is a pointer to the actual memory allocated for the array buffer. This memory can be managed by V8's garbage collector or externally by the embedder.
* **Tracks Buffer Properties:**  It stores metadata about the `ArrayBuffer`, such as:
    * `byte_length`: The current size of the buffer in bytes.
    * `max_byte_length`: The maximum possible size of the buffer.
    * `is_external`:  Indicates if the backing store is managed externally.
    * `is_detachable`:  Whether the buffer can be detached (its memory released).
    * `was_detached`:  Indicates if the buffer has been detached.
    * `is_shared`:  Whether it's a `SharedArrayBuffer` or `GrowableSharedArrayBuffer`.
    * `is_resizable_by_js`: Whether it's a `ResizableArrayBuffer` or `GrowableSharedArrayBuffer`.
* **Supports Detachment:** Provides methods like `Detach` to release the backing store, making the `ArrayBuffer` unusable.
* **Handles Extensions:**  Uses an `ArrayBufferExtension` class to manage the backing store's lifecycle and assist with garbage collection.
* **Defines Maximum Size:**  Specifies the `kMaxByteLength` constant, which defines the maximum size an `ArrayBuffer` can have in V8. This varies based on the architecture and build configuration.
* **Supports Typed Arrays and DataViews:**  Defines classes `JSTypedArray` and `JSDataView` which represent the JavaScript `TypedArray` (like `Uint8Array`, `Int32Array`) and `DataView` objects, respectively. These objects provide structured access to the data within an `ArrayBuffer`.

**If `v8/src/objects/js-array-buffer.h` ended in `.tq`:**

If the file ended in `.tq`, it would indeed be a **V8 Torque source file**. Torque is a domain-specific language developed by the V8 team for generating efficient C++ code for runtime built-ins and object layouts. In that case, the file would primarily contain Torque code defining the structure and some methods of the `JSArrayBuffer` and related classes, which would then be compiled into C++. The current `.h` file is the generated C++ header from the corresponding `.tq` file (indicated by the include `"torque-generated/src/objects/js-array-buffer-tq.inc"`).

**Relationship to JavaScript and Examples:**

This header file is fundamental to how JavaScript interacts with raw binary data.

* **`ArrayBuffer`:** The `JSArrayBuffer` class directly corresponds to the JavaScript `ArrayBuffer` object. It's a fixed-length raw binary data buffer.

   ```javascript
   // Creating an ArrayBuffer of 16 bytes
   const buffer = new ArrayBuffer(16);
   console.log(buffer.byteLength); // Output: 16
   ```

* **`TypedArray`:** The `JSTypedArray` class corresponds to various JavaScript typed array constructors. They provide a way to interpret the raw bytes in an `ArrayBuffer` as elements of a specific data type.

   ```javascript
   // Creating a Uint8Array view of the buffer
   const uint8Array = new Uint8Array(buffer);
   console.log(uint8Array.length); // Output: 16 (number of 1-byte elements)

   // Setting a value in the typed array
   uint8Array[0] = 255;
   console.log(uint8Array[0]); // Output: 255
   ```

* **`DataView`:** The `JSDataView` class corresponds to the JavaScript `DataView` object. It provides a low-level interface for reading and writing data at arbitrary byte offsets within an `ArrayBuffer`, with control over endianness.

   ```javascript
   // Creating a DataView of the buffer
   const dataView = new DataView(buffer);

   // Writing a 32-bit integer at the beginning of the buffer (big-endian)
   dataView.setInt32(0, 0x12345678, false); // false for big-endian

   // Reading the 32-bit integer back
   console.log(dataView.getInt32(0, false)); // Output: 305419896
   ```

**Code Logic Reasoning with Assumptions:**

Let's consider the `Detach` function and make some assumptions:

**Assumption:** We have a `JSArrayBuffer` object `buffer` that is detachable and not yet detached.

**Input:** `buffer` (a handle to the `JSArrayBuffer` object).

**Code Logic (Simplified Interpretation of `Detach`):**

1. **Check if Detachable:** The function likely checks the `is_detachable` flag of the `buffer`.
2. **Check if Already Detached:** It probably checks the `was_detached` flag.
3. **Unregister Backing Store:** If detachable and not already detached, it unregisters the `backing_store` from V8's tracking mechanisms (to prevent double freeing).
4. **Set Byte Length to 0:** It sets the `byte_length` of the `buffer` to 0.
5. **Set Backing Store to Null (or equivalent):** It sets the internal pointer to the backing store to a null value or a special detached state.
6. **Set `was_detached` to true:** Marks the buffer as detached.

**Output:** The function returns a `Maybe<bool>`, likely indicating success or failure. In this successful case, it would return `Just(true)`.

**User-Visible Effects (in JavaScript):**

After a successful `Detach` operation, any attempt to access the data in the `ArrayBuffer` or its associated `TypedArray`/`DataView` will result in a `TypeError`.

```javascript
const buffer = new ArrayBuffer(8);
const uint8Array = new Uint8Array(buffer);
uint8Array[0] = 10;

// Simulate detachment (V8 internal operation)
// ... (V8's Detach function is called internally)

try {
  console.log(uint8Array[0]); // This will throw a TypeError
} catch (e) {
  console.error(e); // Output: TypeError: Cannot perform操作 on a detached ArrayBuffer
}
```

**Common Programming Errors:**

Users often encounter errors related to `ArrayBuffer` detachment:

1. **Operating on a Detached Buffer:** This is the most common error. After an `ArrayBuffer` is detached (which can happen in scenarios like transferring ownership of the buffer), attempting to read or write to it will throw a `TypeError`.

   ```javascript
   const buffer = new ArrayBuffer(8);
   const uint8Array = new Uint8Array(buffer);

   // Simulate detaching the buffer (e.g., via postMessage transfer)
   // ...

   try {
     console.log(uint8Array[0]); // TypeError: Cannot perform操作 on a detached ArrayBuffer
   } catch (e) {
     console.error(e);
   }
   ```

2. **Not Checking `ArrayBuffer.prototype.detached`:** Before performing operations on an `ArrayBuffer`, especially if it might have been involved in data transfer or asynchronous operations, it's good practice to check the `detached` property.

   ```javascript
   const buffer = new ArrayBuffer(8);
   // ... potential detachment scenario ...

   if (buffer.detached) {
     console.log("Buffer is detached, cannot access.");
   } else {
     const uint8Array = new Uint8Array(buffer);
     console.log(uint8Array[0]);
   }
   ```

3. **Incorrectly Assuming Buffer Size After Resizing (for Resizable ArrayBuffers):** With `ResizableArrayBuffer`, the `byteLength` can change. Users need to be aware of this and potentially re-evaluate views or offsets after resizing.

   ```javascript
   const buffer = new ResizableArrayBuffer(8, 16);
   const uint8Array = new Uint8Array(buffer);
   console.log(uint8Array.length); // 8

   buffer.resize(12);
   console.log(uint8Array.length); // Still 8 (view doesn't automatically resize)
   console.log(buffer.byteLength); // 12
   ```

This header file plays a crucial role in the low-level implementation of JavaScript's binary data handling capabilities within the V8 engine. Understanding its structure and purpose is essential for comprehending how V8 manages memory and represents these fundamental data types.

### 提示词
```
这是目录为v8/src/objects/js-array-buffer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-array-buffer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_JS_ARRAY_BUFFER_H_
#define V8_OBJECTS_JS_ARRAY_BUFFER_H_

#include "include/v8-array-buffer.h"
#include "include/v8-typed-array.h"
#include "src/handles/maybe-handles.h"
#include "src/objects/backing-store.h"
#include "src/objects/js-objects.h"
#include "torque-generated/bit-fields.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

class ArrayBufferExtension;

#include "torque-generated/src/objects/js-array-buffer-tq.inc"

class JSArrayBuffer
    : public TorqueGeneratedJSArrayBuffer<JSArrayBuffer,
                                          JSAPIObjectWithEmbedderSlots> {
 public:
// The maximum length for JSArrayBuffer's supported by V8.
// On 32-bit architectures we limit this to 2GiB, so that
// we can continue to use CheckBounds with the Unsigned31
// restriction for the length.
#if V8_ENABLE_SANDBOX
  static constexpr size_t kMaxByteLength = kMaxSafeBufferSizeForSandbox;
#elif V8_HOST_ARCH_32_BIT
  static constexpr size_t kMaxByteLength = kMaxInt;
#else
  static constexpr size_t kMaxByteLength = kMaxSafeInteger;
#endif

  // [byte_length]: length in bytes
  DECL_PRIMITIVE_ACCESSORS(byte_length, size_t)

  // [max_byte_length]: maximum length in bytes
  DECL_PRIMITIVE_ACCESSORS(max_byte_length, size_t)

  // [backing_store]: backing memory for this array
  // It should not be assumed that this will be nullptr for empty ArrayBuffers.
  DECL_GETTER(backing_store, void*)
  inline void set_backing_store(Isolate* isolate, void* value);

  // [extension]: extension object used for GC
  DECL_PRIMITIVE_ACCESSORS(extension, ArrayBufferExtension*)
  inline void init_extension();

  // [bit_field]: boolean flags
  DECL_PRIMITIVE_ACCESSORS(bit_field, uint32_t)

  // Clear uninitialized padding space. This ensures that the snapshot content
  // is deterministic. Depending on the V8 build mode there could be no padding.
  V8_INLINE void clear_padding();

  // Bit positions for [bit_field].
  DEFINE_TORQUE_GENERATED_JS_ARRAY_BUFFER_FLAGS()

  // [is_external]: true indicates that the embedder is in charge of freeing the
  // backing_store, while is_external == false means that v8 will free the
  // memory block once all ArrayBuffers referencing it are collected by the GC.
  DECL_BOOLEAN_ACCESSORS(is_external)

  // [is_detachable]: false => this buffer cannot be detached.
  DECL_BOOLEAN_ACCESSORS(is_detachable)

  // [was_detached]: true => the buffer was previously detached.
  DECL_BOOLEAN_ACCESSORS(was_detached)

  // [is_shared]: true if this is a SharedArrayBuffer or a
  // GrowableSharedArrayBuffer.
  DECL_BOOLEAN_ACCESSORS(is_shared)

  // [is_resizable_by_js]: true if this is a ResizableArrayBuffer or a
  // GrowableSharedArrayBuffer.
  DECL_BOOLEAN_ACCESSORS(is_resizable_by_js)

  // An ArrayBuffer is empty if its BackingStore is empty or if there is none.
  // An empty ArrayBuffer will have a byte_length of zero but not necessarily a
  // nullptr backing_store. An ArrayBuffer with a byte_length of zero may not
  // necessarily be empty though, as it may be a GrowableSharedArrayBuffer.
  // An ArrayBuffer with a size greater than zero is never empty.
  DECL_GETTER(IsEmpty, bool)

  DECL_ACCESSORS(detach_key, Tagged<Object>)

  // Initializes the fields of the ArrayBuffer. The provided backing_store can
  // be nullptr. If it is not nullptr, then the function registers it with
  // src/heap/array-buffer-tracker.h.
  V8_EXPORT_PRIVATE void Setup(SharedFlag shared, ResizableFlag resizable,
                               std::shared_ptr<BackingStore> backing_store,
                               Isolate* isolate);

  // Attaches the backing store to an already constructed empty ArrayBuffer.
  // This is intended to be used only in ArrayBufferConstructor builtin.
  V8_EXPORT_PRIVATE void Attach(std::shared_ptr<BackingStore> backing_store);
  // Detach the backing store from this array buffer if it is detachable.
  // This sets the internal pointer and length to 0 and unregisters the backing
  // store from the array buffer tracker. If the array buffer is not detachable,
  // this is a nop.
  //
  // Array buffers that wrap wasm memory objects are special in that they
  // are normally not detachable, but can become detached as a side effect
  // of growing the underlying memory object. The {force_for_wasm_memory} flag
  // is used by the implementation of Wasm memory growth in order to bypass the
  // non-detachable check.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> Detach(
      DirectHandle<JSArrayBuffer> buffer, bool force_for_wasm_memory = false,
      Handle<Object> key = Handle<Object>());

  // Get a reference to backing store of this array buffer, if there is a
  // backing store. Returns nullptr if there is no backing store (e.g. detached
  // or a zero-length array buffer).
  inline std::shared_ptr<BackingStore> GetBackingStore() const;

  inline size_t GetByteLength() const;

  static size_t GsabByteLength(Isolate* isolate, Address raw_array_buffer);

  static Maybe<bool> GetResizableBackingStorePageConfiguration(
      Isolate* isolate, size_t byte_length, size_t max_byte_length,
      ShouldThrow should_throw, size_t* page_size, size_t* initial_pages,
      size_t* max_pages);

  // Allocates an ArrayBufferExtension for this array buffer, unless it is
  // already associated with an extension.
  V8_EXPORT_PRIVATE ArrayBufferExtension* EnsureExtension();

  // Frees the associated ArrayBufferExtension and returns its backing store.
  std::shared_ptr<BackingStore> RemoveExtension();

  // Marks ArrayBufferExtension
  void MarkExtension();
  void YoungMarkExtension();
  void YoungMarkExtensionPromoted();

  //
  // Serializer/deserializer support.
  //

  // Backing stores are serialized/deserialized separately. During serialization
  // the backing store reference is stored in the backing store field and upon
  // deserialization it is converted back to actual external (off-heap) pointer
  // value.
  inline uint32_t GetBackingStoreRefForDeserialization() const;
  inline void SetBackingStoreRefForSerialization(uint32_t ref);

  // Dispatched behavior.
  DECL_PRINTER(JSArrayBuffer)
  DECL_VERIFIER(JSArrayBuffer)

  static constexpr int kSizeWithEmbedderFields =
      kHeaderSize +
      v8::ArrayBuffer::kEmbedderFieldCount * kEmbedderDataSlotSize;
  static constexpr bool kContainsEmbedderFields =
      v8::ArrayBuffer::kEmbedderFieldCount > 0;

  class BodyDescriptor;

 private:
  void DetachInternal(bool force_for_wasm_memory, Isolate* isolate);

#if V8_COMPRESS_POINTERS
  // When pointer compression is enabled, the pointer to the extension is
  // stored in the external pointer table and the object itself only contains a
  // 32-bit external pointer handles. This simplifies alignment requirements
  // and is also necessary for the sandbox.
  inline ExternalPointerHandle* extension_handle_location() const;
#else
  inline ArrayBufferExtension** extension_location() const;
#endif  // V8_COMPRESS_POINTERS

  TQ_OBJECT_CONSTRUCTORS(JSArrayBuffer)
};

// Each JSArrayBuffer (with a backing store) has a corresponding native-heap
// allocated ArrayBufferExtension for GC purposes and storing the backing store.
// When marking a JSArrayBuffer, the GC also marks the native
// extension-object. The GC periodically iterates all extensions concurrently
// and frees unmarked ones.
// https://docs.google.com/document/d/1-ZrLdlFX1nXT3z-FAgLbKal1gI8Auiaya_My-a0UJ28/edit
class ArrayBufferExtension final
#ifdef V8_COMPRESS_POINTERS
    : public ExternalPointerTable::ManagedResource {
#else
    : public Malloced {
#endif  // V8_COMPRESS_POINTERS
  static constexpr uint64_t kAgeMask = 1;
  static constexpr uint64_t kAccountingLengthBitOffset = 1;

 public:
  enum class Age : uint8_t { kYoung = 0, kOld = 1 };

  // Packs `accounting_length` and `age` into a single integer for consistent
  // accounting, allowing resize while concurrently sweeping.
  struct AccountingState {
    size_t accounting_length() const {
      DCHECK_LE(value >> kAccountingLengthBitOffset,
                std::numeric_limits<size_t>::max());
      return static_cast<size_t>(value >> kAccountingLengthBitOffset);
    }
    Age age() const { return static_cast<Age>(value & kAgeMask); }

    uint64_t value;
  };

  ArrayBufferExtension() : backing_store_(std::shared_ptr<BackingStore>()) {}
  explicit ArrayBufferExtension(std::shared_ptr<BackingStore> backing_store)
      : backing_store_(backing_store) {}

  void Mark() { marked_.store(true, std::memory_order_relaxed); }
  void Unmark() { marked_.store(false, std::memory_order_relaxed); }
  bool IsMarked() const { return marked_.load(std::memory_order_relaxed); }

  void YoungMark() { set_young_gc_state(GcState::Copied); }
  void YoungMarkPromoted() { set_young_gc_state(GcState::Promoted); }
  void YoungUnmark() { set_young_gc_state(GcState::Dead); }
  bool IsYoungMarked() const { return young_gc_state() != GcState::Dead; }

  bool IsYoungPromoted() const { return young_gc_state() == GcState::Promoted; }

  std::shared_ptr<BackingStore> backing_store() { return backing_store_; }
  BackingStore* backing_store_raw() { return backing_store_.get(); }

  size_t accounting_length() const {
    return AccountingState{accounting_state_.load(std::memory_order_relaxed)}
        .accounting_length();
  }
  void set_accounting_state(size_t accounting_length, Age age) {
    accounting_state_.store((static_cast<uint64_t>(accounting_length)
                             << kAccountingLengthBitOffset) |
                                static_cast<uint8_t>(age),
                            std::memory_order_relaxed);
  }

  // Applies `delta` to `accounting_length` and returns the AccountingState
  // before the update.
  AccountingState UpdateAccountingLength(int64_t delta) {
    return {accounting_state_.fetch_add(delta << kAccountingLengthBitOffset,
                                        std::memory_order_relaxed)};
  }

  // Clears `accounting_length` and returns the AccountingState before the
  // update.
  AccountingState ClearAccountingLength() {
    return {accounting_state_.fetch_and(kAgeMask, std::memory_order_relaxed)};
  }

  std::shared_ptr<BackingStore> RemoveBackingStore() {
    return std::move(backing_store_);
  }

  void set_backing_store(std::shared_ptr<BackingStore> backing_store) {
    backing_store_ = std::move(backing_store);
  }

  void reset_backing_store() { backing_store_.reset(); }

  ArrayBufferExtension* next() const { return next_; }
  void set_next(ArrayBufferExtension* extension) { next_ = extension; }

  Age age() const {
    return AccountingState{accounting_state_.load(std::memory_order_relaxed)}
        .age();
  }
  // Updates `age` and returns the AccountingState before the update.
  AccountingState SetOld() {
    return {accounting_state_.fetch_or(kAgeMask, std::memory_order_relaxed)};
  }
  AccountingState SetYoung() {
    return {accounting_state_.fetch_and(~kAgeMask, std::memory_order_relaxed)};
  }

 private:
  enum class GcState : uint8_t { Dead = 0, Copied, Promoted };

  std::atomic<bool> marked_{false};
  std::atomic<GcState> young_gc_state_{GcState::Dead};
  std::shared_ptr<BackingStore> backing_store_;
  ArrayBufferExtension* next_ = nullptr;
  std::atomic<uint64_t> accounting_state_{kAgeMask};

  GcState young_gc_state() const {
    return young_gc_state_.load(std::memory_order_relaxed);
  }

  void set_young_gc_state(GcState value) {
    young_gc_state_.store(value, std::memory_order_relaxed);
  }
};

class JSArrayBufferView
    : public TorqueGeneratedJSArrayBufferView<JSArrayBufferView,
                                              JSAPIObjectWithEmbedderSlots> {
 public:
  class BodyDescriptor;

  // [byte_offset]: offset of typed array in bytes.
  DECL_PRIMITIVE_ACCESSORS(byte_offset, size_t)

  // [byte_length]: length of typed array in bytes.
  DECL_PRIMITIVE_ACCESSORS(byte_length, size_t)

  DECL_VERIFIER(JSArrayBufferView)

  // Bit positions for [bit_field].
  DEFINE_TORQUE_GENERATED_JS_ARRAY_BUFFER_VIEW_FLAGS()

  inline bool WasDetached() const;

  DECL_BOOLEAN_ACCESSORS(is_length_tracking)
  DECL_BOOLEAN_ACCESSORS(is_backed_by_rab)
  inline bool IsVariableLength() const;

  static_assert(IsAligned(kRawByteOffsetOffset, kUIntptrSize));
  static_assert(IsAligned(kRawByteLengthOffset, kUIntptrSize));

  TQ_OBJECT_CONSTRUCTORS(JSArrayBufferView)
};

class JSTypedArray
    : public TorqueGeneratedJSTypedArray<JSTypedArray, JSArrayBufferView> {
 public:
  static constexpr size_t kMaxByteLength = JSArrayBuffer::kMaxByteLength;
  static_assert(kMaxByteLength == v8::TypedArray::kMaxByteLength);

  // [length]: length of typed array in elements.
  DECL_PRIMITIVE_GETTER(length, size_t)

  DECL_GETTER(base_pointer, Tagged<Object>)
  DECL_ACQUIRE_GETTER(base_pointer, Tagged<Object>)

  // ES6 9.4.5.3
  V8_WARN_UNUSED_RESULT static Maybe<bool> DefineOwnProperty(
      Isolate* isolate, Handle<JSTypedArray> o, Handle<Object> key,
      PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw);

  ExternalArrayType type();
  V8_EXPORT_PRIVATE size_t element_size() const;

  V8_EXPORT_PRIVATE Handle<JSArrayBuffer> GetBuffer();

  // The `DataPtr` is `base_ptr + external_pointer`, and `base_ptr` is nullptr
  // for off-heap typed arrays.
  static constexpr bool kOffHeapDataPtrEqualsExternalPointer = true;

  // Use with care: returns raw pointer into heap.
  inline void* DataPtr();

  inline void SetOffHeapDataPtr(Isolate* isolate, void* base, Address offset);

  // Whether the buffer's backing store is on-heap or off-heap.
  inline bool is_on_heap() const;
  inline bool is_on_heap(AcquireLoadTag tag) const;

  // Only valid to call when IsVariableLength() is true.
  size_t GetVariableLengthOrOutOfBounds(bool& out_of_bounds) const;

  inline size_t GetLengthOrOutOfBounds(bool& out_of_bounds) const;
  inline size_t GetLength() const;
  inline size_t GetByteLength() const;
  inline bool IsOutOfBounds() const;
  inline bool IsDetachedOrOutOfBounds() const;

  static inline void ForFixedTypedArray(ExternalArrayType array_type,
                                        size_t* element_size,
                                        ElementsKind* element_kind);

  static size_t LengthTrackingGsabBackedTypedArrayLength(Isolate* isolate,
                                                         Address raw_array);

  // Note: this is a pointer compression specific optimization.
  // Normally, on-heap typed arrays contain HeapObject value in |base_pointer|
  // field and an offset in |external_pointer|.
  // When pointer compression is enabled we want to combine decompression with
  // the offset addition. In order to do that we add an isolate root to the
  // |external_pointer| value and therefore the data pointer computation can
  // is a simple addition of a (potentially sign-extended) |base_pointer| loaded
  // as Tagged_t value and an |external_pointer| value.
  // For full-pointer mode the compensation value is zero.
  static inline Address ExternalPointerCompensationForOnHeapArray(
      PtrComprCageBase cage_base);

  //
  // Serializer/deserializer support.
  //

  // External backing stores are serialized/deserialized separately.
  // During serialization the backing store reference is stored in the typed
  // array object and upon deserialization it is converted back to actual
  // external (off-heap) pointer value.
  // The backing store reference is stored in the external_pointer field.
  inline uint32_t GetExternalBackingStoreRefForDeserialization() const;
  inline void SetExternalBackingStoreRefForSerialization(uint32_t ref);

  // Subtracts external pointer compensation from the external pointer value.
  inline void RemoveExternalPointerCompensationForSerialization(
      Isolate* isolate);
  // Adds external pointer compensation to the external pointer value.
  inline void AddExternalPointerCompensationForDeserialization(
      Isolate* isolate);

  static inline MaybeHandle<JSTypedArray> Validate(Isolate* isolate,
                                                   Handle<Object> receiver,
                                                   const char* method_name);

  // Dispatched behavior.
  DECL_PRINTER(JSTypedArray)
  DECL_VERIFIER(JSTypedArray)

  // TODO(v8:9287): Re-enable when GCMole stops mixing 32/64 bit configs.
  // static_assert(IsAligned(kLengthOffset, kTaggedSize));
  // static_assert(IsAligned(kExternalPointerOffset, kTaggedSize));

  static constexpr int kSizeWithEmbedderFields =
      kHeaderSize +
      v8::ArrayBufferView::kEmbedderFieldCount * kEmbedderDataSlotSize;
  static constexpr bool kContainsEmbedderFields =
      v8::ArrayBufferView::kEmbedderFieldCount > 0;

  class BodyDescriptor;

#ifdef V8_TYPED_ARRAY_MAX_SIZE_IN_HEAP
  static constexpr size_t kMaxSizeInHeap = V8_TYPED_ARRAY_MAX_SIZE_IN_HEAP;
#else
  static constexpr size_t kMaxSizeInHeap = 64;
#endif

 private:
  template <typename IsolateT>
  friend class Deserializer;
  friend class Factory;

  DECL_PRIMITIVE_SETTER(length, size_t)
  // Reads the "length" field, doesn't assert the TypedArray is not RAB / GSAB
  // backed.
  inline size_t LengthUnchecked() const;

  DECL_GETTER(external_pointer, Address)

  DECL_SETTER(base_pointer, Tagged<Object>)
  DECL_RELEASE_SETTER(base_pointer, Tagged<Object>)

  inline void set_external_pointer(Isolate* isolate, Address value);

  TQ_OBJECT_CONSTRUCTORS(JSTypedArray)
};

class JSDataViewOrRabGsabDataView
    : public TorqueGeneratedJSDataViewOrRabGsabDataView<
          JSDataViewOrRabGsabDataView, JSArrayBufferView> {
 public:
  // [data_pointer]: pointer to the actual data.
  DECL_GETTER(data_pointer, void*)
  inline void set_data_pointer(Isolate* isolate, void* value);

  // TODO(v8:9287): Re-enable when GCMole stops mixing 32/64 bit configs.
  // static_assert(IsAligned(kDataPointerOffset, kTaggedSize));

  static constexpr int kSizeWithEmbedderFields =
      kHeaderSize +
      v8::ArrayBufferView::kEmbedderFieldCount * kEmbedderDataSlotSize;
  static constexpr bool kContainsEmbedderFields =
      v8::ArrayBufferView::kEmbedderFieldCount > 0;

  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(JSDataViewOrRabGsabDataView)
};

class JSDataView
    : public TorqueGeneratedJSDataView<JSDataView,
                                       JSDataViewOrRabGsabDataView> {
 public:
  // Dispatched behavior.
  DECL_PRINTER(JSDataView)
  DECL_VERIFIER(JSDataView)

  TQ_OBJECT_CONSTRUCTORS(JSDataView)
};

class JSRabGsabDataView
    : public TorqueGeneratedJSRabGsabDataView<JSRabGsabDataView,
                                              JSDataViewOrRabGsabDataView> {
 public:
  // Dispatched behavior.
  DECL_PRINTER(JSRabGsabDataView)
  DECL_VERIFIER(JSRabGsabDataView)

  inline size_t GetByteLength() const;
  inline bool IsOutOfBounds() const;

  TQ_OBJECT_CONSTRUCTORS(JSRabGsabDataView)
};

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_JS_ARRAY_BUFFER_H_
```