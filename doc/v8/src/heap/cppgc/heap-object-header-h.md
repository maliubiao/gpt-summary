Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Identification of Purpose:**

* The filename `heap-object-header.h` immediately suggests it's about the header structure of objects within a heap. The `cppgc` namespace further indicates it's related to the C++ garbage collector in V8.
* The comment at the top confirms this: "HeapObjectHeader contains meta data per object and is prepended to each object." This is the core function.

**2. Deconstructing the Structure (the `HeapObjectHeader` class):**

* **Data Members and their meanings:**  I look at the private data members (`padding_`, `encoded_high_`, `encoded_low_`) and the bitfield structures (`FullyConstructedField`, `UnusedField1`, etc.). The comments describing the bit layout are crucial here. I note the specific fields: `GCInfoIndex`, `unused`, `in construction`, `size`, `mark bit`. I try to understand what each bit likely represents in the context of garbage collection and object management.
* **Public Methods and their purpose:** I go through each public method, reading the name and any accompanying comments. I try to infer what each method does. For example:
    * `FromObject`:  Likely retrieves the header given an object's address.
    * `ObjectStart`/`ObjectEnd`:  Determine the boundaries of the object in memory.
    * `GetGCInfoIndex`:  Retrieves information about the object's type for GC.
    * `AllocatedSize`/`ObjectSize`:  Return the size of the allocated memory and the user-visible object, respectively. The difference suggests the header is included in `AllocatedSize`.
    * `IsLargeObject`:  Detects if the object is managed differently due to its size.
    * `IsInConstruction`/`MarkAsFullyConstructed`: Indicate the object's initialization state.
    * `IsMarked`/`Unmark`/`TryMarkAtomic`/`MarkNonAtomic`:  Related to the garbage collection marking phase. The atomic versions suggest concurrency is involved.
    * `IsYoung`/`IsFree`:  Indicate object lifecycle stages for garbage collection.
    * `IsFinalizable`/`Finalize`:  Related to object cleanup before deallocation.
    * `GetName`:  Retrieves a name associated with the object, useful for debugging or introspection.
    * `Trace`:  A method used by the garbage collector to traverse the object's references.
* **Static Constants:** I pay attention to constants like `kSizeLog2`, `kMaxSize`, `kLargeObjectSizeInHeader`, as they define limits and special values.

**3. Identifying Key Concepts and Relationships:**

* **Garbage Collection:** The presence of `GCInfoIndex`, "mark bit", "finalizable", and `Trace` strongly links this header to garbage collection.
* **Object Lifecycle:** The "in construction", "young", "free" states point to different stages in an object's lifetime managed by the collector.
* **Memory Layout:** The diagram and methods like `ObjectStart` and `ObjectEnd` are crucial for understanding how the header sits in memory relative to the object.
* **Atomicity:** The `std::atomic` usage and methods like `TryMarkAtomic` indicate the need for thread-safe operations, likely due to concurrent garbage collection.
* **Caged Heap:** The `#ifdef CPPGC_CAGED_HEAP` sections signal a specific memory management strategy being conditionally applied.

**4. Addressing Specific Questions in the Prompt:**

* **Functionality Listing:**  Based on the analysis of methods and data members, I summarize the key functions.
* **`.tq` Extension:** I check for the `.tq` extension in the filename. Since it's `.h`, I conclude it's not a Torque file.
* **JavaScript Relationship:** I consider how this low-level C++ code relates to JavaScript. The garbage collection functionality is the primary connection. I then try to construct a simple JavaScript example that *implicitly* relies on this header's functionality (object creation and garbage collection).
* **Code Logic Inference:** I look for methods with clear logic and potential inputs/outputs. `FromObject` is a good example. I consider a hypothetical address and how the header address is calculated.
* **Common Programming Errors:** I think about common mistakes related to memory management, especially in the context of garbage collection. Use-after-free is a prime candidate. I try to construct a scenario where incorrect manual memory management (if possible in this context) could lead to issues. Given this is a managed heap, the focus shifts to *misunderstanding* the GC's behavior or lifecycle.

**5. Refining and Organizing the Output:**

* I group the functionalities logically.
* I provide clear explanations for each point.
* I ensure the JavaScript example is simple and illustrative.
* I present the code logic inference with a clear assumption and output.
* I make the explanation of common errors understandable even for those not deeply familiar with V8 internals.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on individual bitfields without understanding the broader context. I would then step back and consider how these fields contribute to the overall garbage collection process.
* I might have initially struggled to connect the C++ code directly to JavaScript. The realization that the GC *itself* is the connection is key.
* I might have initially thought about more complex code logic scenarios, but then simplified them to focus on the core functionality of the header.
* I realized that directly demonstrating errors related to *this specific header* from a JavaScript perspective is difficult because it's internal. The error example focuses on the *consequences* of the GC, which this header helps facilitate.

By following these steps, I can systematically analyze the C++ header file and address all the points raised in the prompt.
This C++ header file, `v8/src/heap/cppgc/heap-object-header.h`, defines the structure and basic operations for the header that is prepended to every object managed by the `cppgc` (C++ garbage collector) in V8. Let's break down its functionality:

**Core Functionality:**

1. **Metadata Storage:** The primary function is to store essential metadata about each heap-allocated object. This metadata is crucial for the garbage collector to manage the object's lifecycle, including allocation, marking, and eventual reclamation.

2. **Memory Layout Information:** It defines the layout of the header in memory, including the size and position of various fields. This allows the garbage collector and other V8 components to efficiently access this metadata.

3. **Garbage Collection Information:**  It stores information directly used by the garbage collector:
    * **`GCInfoIndex`:**  An index into a global table (`GCInfoTable`) that describes the object's type and how to traverse its members during garbage collection. This is how the garbage collector knows what fields within an object are pointers to other managed objects.
    * **`mark bit`:**  A single bit used during the marking phase of garbage collection to track which objects are reachable and thus should be kept alive.
    * **`in construction`:** A bit indicating whether the object is still being initialized. This is important to prevent the garbage collector from prematurely visiting an incompletely constructed object, which could lead to errors.

4. **Object Size:** It stores the allocated size of the object. This is used by the garbage collector for various calculations and to determine the boundaries of the object in memory. It distinguishes between regular and large objects.

5. **Finalization Support (Conditional):**  If `CPPGC_CAGED_HEAP` is defined, it includes a field (`next_unfinalized_`) to manage a linked list of objects that need finalization. Finalization is the process of running user-defined cleanup code before an object is deallocated.

6. **Access Methods:**  It provides inline methods to access and manipulate these metadata fields in an efficient and controlled manner. It also considers atomicity for certain operations to ensure thread safety during concurrent garbage collection.

7. **Debugging and Verification:**  The `GetName` method allows retrieving a name associated with the object, which is helpful for debugging and introspection. `CheckApiConstants` suggests internal consistency checks.

**Is `v8/src/heap/cppgc/heap-object-header.h` a Torque source file?**

No, the file extension is `.h`, which indicates a standard C++ header file. If it were a V8 Torque source file, its extension would be `.tq`.

**Relationship with JavaScript and Example:**

This header file is fundamental to how V8 manages memory for JavaScript objects. While you don't directly interact with `HeapObjectHeader` in JavaScript code, it's the underlying mechanism that enables garbage collection, which is crucial for JavaScript's automatic memory management.

Here's how it relates and a conceptual JavaScript example:

* **JavaScript Object Creation:** When you create an object in JavaScript, the V8 engine allocates memory on the heap. A `HeapObjectHeader` is prepended to this memory block to store the metadata.
* **Garbage Collection:**  When the garbage collector runs, it uses the information in the `HeapObjectHeader` (specifically `GCInfoIndex` and the `mark bit`) to traverse the object graph and determine which objects are no longer reachable and can be freed.

**JavaScript Example (Conceptual):**

```javascript
// When this object is created, behind the scenes, V8 will allocate
// memory and prepend a HeapObjectHeader to it.
let myObject = {
  name: "Example",
  data: [1, 2, 3]
};

// Later, if 'myObject' is no longer referenced by any reachable code,
// the garbage collector will use the HeapObjectHeader associated with
// this object to identify it as garbage and reclaim the memory.
myObject = null; // Make the object unreachable.

// The garbage collector (cppgc) will eventually run. During its
// marking phase, it will:
// 1. Start from the "roots" (global objects, stack variables, etc.).
// 2. Traverse reachable objects.
// 3. For each visited object, it will likely set the 'mark bit' in its
//    HeapObjectHeader.
// 4. Objects without the 'mark bit' set are considered garbage.

// The 'GCInfoIndex' in the HeapObjectHeader tells the collector how to
// find the 'name' property (likely a string, which is also a managed object)
// and the 'data' property (likely an array, also managed). This allows
// the collector to recursively traverse the object graph.
```

**Code Logic Inference (Example: `FromObject`):**

**Assumption:** We have the memory address of an object that was allocated by `cppgc`.

**Input:** `objectAddress` (a pointer to the start of the object's data).

**Code Logic:** The `FromObject` method calculates the address of the `HeapObjectHeader` by subtracting the size of the header from the object's address:

```c++
// static
HeapObjectHeader& HeapObjectHeader::FromObject(void* object) {
  return *reinterpret_cast<HeapObjectHeader*>(static_cast<Address>(object) -
                                              sizeof(HeapObjectHeader));
}
```

**Output:** A reference to the `HeapObjectHeader` that precedes the object at `objectAddress`.

**Example:**

Let's say:
* `sizeof(HeapObjectHeader)` is 32 bytes.
* `objectAddress` is `0x1000`.

Then, `HeapObjectHeader::FromObject(reinterpret_cast<void*>(0x1000))` would:

1. Cast `0x1000` to `Address` (likely a `uintptr_t`).
2. Subtract `sizeof(HeapObjectHeader)` (32) from `0x1000`, resulting in `0xFC0`.
3. `reinterpret_cast` `0xFC0` to a `HeapObjectHeader*`.
4. Return a reference to the `HeapObjectHeader` located at memory address `0xFC0`.

**Common Programming Errors (Related to the Concepts):**

While you don't directly manipulate `HeapObjectHeader` in typical C++ code using `cppgc`, understanding its role helps avoid errors related to memory management and garbage collection:

1. **Use-After-Free (Indirectly related):**  If you have raw pointers to objects managed by `cppgc` and you try to access them after the garbage collector has freed the object, you'll encounter a use-after-free error. The `HeapObjectHeader` is no longer valid at that memory location. `cppgc` aims to prevent this for objects it manages directly, but issues can arise when interacting with native code or using raw pointers incorrectly.

   **Example (Conceptual C++ with `cppgc`):**

   ```c++
   #include "include/cppgc/garbage-collected.h"
   #include "include/cppgc/heap.h"

   class MyObject : public cppgc::GarbageCollected<MyObject> {
    public:
     int value;
   };

   int main() {
     cppgc::Heap:: এলাহাবাদ allocator;
     MyObject* obj = allocator.new_object<MyObject>();
     obj->value = 42;

     // Simulate a scenario where 'obj' might become unreachable later
     // (e.g., it was stored in a data structure that gets cleared).

     // Incorrectly trying to access 'obj' after it might have been collected.
     // This is where a use-after-free could occur if the GC ran in between.
     // (cppgc is designed to prevent this, but imagine if you had a raw pointer
     //  and lost track of its validity).
     // std::cout << obj->value << std::endl;

     return 0;
   }
   ```

2. **Incorrectly Implementing `Trace` Methods:**  For custom garbage-collected classes, you need to define a `Trace` method that tells the garbage collector how to find all the pointers to other managed objects within your class. If this `Trace` method is incomplete or incorrect, the garbage collector might fail to mark some reachable objects, leading to premature garbage collection and potential crashes. The `GCInfoIndex` in the `HeapObjectHeader` points to the information that includes the correct `Trace` function for the object's type.

3. **Memory Leaks (Less Common with `cppgc`):** While `cppgc` helps prevent most memory leaks, you can still have logical leaks where objects are technically reachable but no longer needed, preventing them from being collected. This isn't directly related to the `HeapObjectHeader`'s structure, but understanding how the garbage collector uses it can help diagnose such issues.

In summary, `v8/src/heap/cppgc/heap-object-header.h` is a critical low-level component of V8's `cppgc`. It defines the fundamental metadata structure that enables automatic memory management for C++ objects within the engine, which indirectly supports JavaScript's garbage collection.

### 提示词
```
这是目录为v8/src/heap/cppgc/heap-object-header.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/heap-object-header.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_CPPGC_HEAP_OBJECT_HEADER_H_
#define V8_HEAP_CPPGC_HEAP_OBJECT_HEADER_H_

#include <stdint.h>

#include <atomic>

#include "include/cppgc/allocation.h"
#include "include/cppgc/internal/gc-info.h"
#include "include/cppgc/internal/member-storage.h"
#include "include/cppgc/internal/name-trait.h"
#include "src/base/atomic-utils.h"
#include "src/base/bit-field.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/heap/cppgc/gc-info-table.h"
#include "src/heap/cppgc/globals.h"

#if defined(CPPGC_CAGED_HEAP)
#include "src/heap/cppgc/caged-heap.h"
#endif  // defined(CPPGC_CAGED_HEAP)

namespace cppgc {

class Visitor;

namespace internal {

// HeapObjectHeader contains meta data per object and is prepended to each
// object.
//
// +-----------------+------+------------------------------------------+
// | name            | bits |                                          |
// +-----------------+------+------------------------------------------+
// | padding         |   32 | Only present on 64-bit platform.         |
// +-----------------+------+------------------------------------------+
// | GCInfoIndex     |   14 |                                          |
// | unused          |    1 |                                          |
// | in construction |    1 | In construction encoded as |false|.      |
// +-----------------+------+------------------------------------------+
// | size            |   15 | 17 bits because allocations are aligned. |
// | mark bit        |    1 |                                          |
// +-----------------+------+------------------------------------------+
//
// Notes:
// - See |GCInfoTable| for constraints on GCInfoIndex.
// - |size| for regular objects is encoded with 15 bits but can actually
//   represent sizes up to |kBlinkPageSize| (2^17) because allocations are
//   always 4 byte aligned (see kAllocationGranularity) on 32bit. 64bit uses
//   8 byte aligned allocations which leaves 1 bit unused.
// - |size| for large objects is encoded as 0. The size of a large object is
//   stored in |LargeObjectPage::PayloadSize()|.
// - |mark bit| and |in construction| bits are located in separate 16-bit halves
//    to allow potentially accessing them non-atomically.
class HeapObjectHeader {
 public:
  static constexpr size_t kSizeLog2 = 17;
  static constexpr size_t kMaxSize = (size_t{1} << kSizeLog2) - 1;
  static constexpr uint16_t kLargeObjectSizeInHeader = 0;

  inline static HeapObjectHeader& FromObject(void* address);
  inline static const HeapObjectHeader& FromObject(const void* address);

  inline HeapObjectHeader(size_t size, GCInfoIndex gc_info_index);

  // The object starts directly after the HeapObjectHeader.
  inline Address ObjectStart() const;
  template <AccessMode mode = AccessMode::kNonAtomic>
  inline Address ObjectEnd() const;

  template <AccessMode mode = AccessMode::kNonAtomic>
  inline GCInfoIndex GetGCInfoIndex() const;

  template <AccessMode mode = AccessMode::kNonAtomic>
  inline size_t AllocatedSize() const;
  inline void SetAllocatedSize(size_t size);

  template <AccessMode mode = AccessMode::kNonAtomic>
  inline size_t ObjectSize() const;

  template <AccessMode mode = AccessMode::kNonAtomic>
  inline bool IsLargeObject() const;

  template <AccessMode = AccessMode::kNonAtomic>
  bool IsInConstruction() const;
  inline void MarkAsFullyConstructed();
  // Use MarkObjectAsFullyConstructed() to mark an object as being constructed.

  template <AccessMode = AccessMode::kNonAtomic>
  bool IsMarked() const;
  template <AccessMode = AccessMode::kNonAtomic>
  void Unmark();
  inline bool TryMarkAtomic();

  inline void MarkNonAtomic();

  template <AccessMode = AccessMode::kNonAtomic>
  bool IsYoung() const;

  template <AccessMode = AccessMode::kNonAtomic>
  bool IsFree() const;

  inline bool IsFinalizable() const;
  void Finalize();

#if defined(CPPGC_CAGED_HEAP)
  inline void SetNextUnfinalized(HeapObjectHeader* next);
  inline HeapObjectHeader* GetNextUnfinalized(uintptr_t cage_base) const;
#endif  // defined(CPPGC_CAGED_HEAP)

  // Default version will retrieve `HeapObjectNameForUnnamedObject` as it is
  // configured at runtime.
  V8_EXPORT_PRIVATE HeapObjectName GetName() const;
  // Override for verifying and testing where we always want to pass the naming
  // option explicitly.
  V8_EXPORT_PRIVATE HeapObjectName
      GetName(HeapObjectNameForUnnamedObject) const;

  template <AccessMode = AccessMode::kNonAtomic>
  void Trace(Visitor*) const;

 private:
  enum class EncodedHalf : uint8_t { kLow, kHigh };

  // Used in |encoded_high_|.
  using FullyConstructedField = v8::base::BitField16<bool, 0, 1>;
  using UnusedField1 = FullyConstructedField::Next<bool, 1>;
  using GCInfoIndexField = UnusedField1::Next<GCInfoIndex, 14>;
  // Used in |encoded_low_|.
  using MarkBitField = v8::base::BitField16<bool, 0, 1>;
  using SizeField =
      MarkBitField::Next<size_t, 15>;  // Use EncodeSize/DecodeSize instead.

  static constexpr size_t DecodeSize(uint16_t encoded) {
    // Essentially, gets optimized to << 1.
    return SizeField::decode(encoded) * kAllocationGranularity;
  }

  static constexpr uint16_t EncodeSize(size_t size) {
    // Essentially, gets optimized to >> 1.
    return SizeField::encode(size / kAllocationGranularity);
  }

  V8_EXPORT_PRIVATE void CheckApiConstants();

  template <AccessMode, EncodedHalf part,
            std::memory_order memory_order = std::memory_order_seq_cst>
  inline uint16_t LoadEncoded() const;
  template <AccessMode mode, EncodedHalf part,
            std::memory_order memory_order = std::memory_order_seq_cst>
  inline void StoreEncoded(uint16_t bits, uint16_t mask);

#if defined(V8_HOST_ARCH_64_BIT)
  // If cage is enabled, to save on space required by sweeper metadata, we store
  // the list of to-be-finalized objects inlined in HeapObjectHeader.
#if defined(CPPGC_CAGED_HEAP)
  uint32_t next_unfinalized_ = 0;
#else   // !defined(CPPGC_CAGED_HEAP)
  uint32_t padding_ = 0;
#endif  // !defined(CPPGC_CAGED_HEAP)
#endif  // defined(V8_HOST_ARCH_64_BIT)
  uint16_t encoded_high_;
  uint16_t encoded_low_;
};

static_assert(kAllocationGranularity == sizeof(HeapObjectHeader),
              "sizeof(HeapObjectHeader) must match allocation granularity to "
              "guarantee alignment");

// static
HeapObjectHeader& HeapObjectHeader::FromObject(void* object) {
  return *reinterpret_cast<HeapObjectHeader*>(static_cast<Address>(object) -
                                              sizeof(HeapObjectHeader));
}

// static
const HeapObjectHeader& HeapObjectHeader::FromObject(const void* object) {
  return *reinterpret_cast<const HeapObjectHeader*>(
      static_cast<ConstAddress>(object) - sizeof(HeapObjectHeader));
}

HeapObjectHeader::HeapObjectHeader(size_t size, GCInfoIndex gc_info_index) {
#if defined(V8_HOST_ARCH_64_BIT) && !defined(CPPGC_CAGED_HEAP)
  USE(padding_);
#endif  // defined(V8_HOST_ARCH_64_BIT) && !defined(CPPGC_CAGED_HEAP)
  DCHECK_LT(gc_info_index, GCInfoTable::kMaxIndex);
  DCHECK_EQ(0u, size & (sizeof(HeapObjectHeader) - 1));
  DCHECK_GE(kMaxSize, size);
  encoded_low_ = EncodeSize(size);
  // Objects may get published to the marker without any other synchronization
  // (e.g., write barrier) in which case the in-construction bit is read
  // concurrently which requires reading encoded_high_ atomically. It is ok if
  // this write is not observed by the marker, since the sweeper  sets the
  // in-construction bit to 0 and we can rely on that to guarantee a correct
  // answer when checking if objects are in-construction.
  v8::base::AsAtomicPtr(&encoded_high_)
      ->store(GCInfoIndexField::encode(gc_info_index),
              std::memory_order_relaxed);
  DCHECK(IsInConstruction());
#ifdef DEBUG
  CheckApiConstants();
#endif  // DEBUG
}

Address HeapObjectHeader::ObjectStart() const {
  return reinterpret_cast<Address>(const_cast<HeapObjectHeader*>(this)) +
         sizeof(HeapObjectHeader);
}

template <AccessMode mode>
Address HeapObjectHeader::ObjectEnd() const {
  DCHECK(!IsLargeObject<mode>());
  return reinterpret_cast<Address>(const_cast<HeapObjectHeader*>(this)) +
         AllocatedSize<mode>();
}

template <AccessMode mode>
GCInfoIndex HeapObjectHeader::GetGCInfoIndex() const {
  const uint16_t encoded =
      LoadEncoded<mode, EncodedHalf::kHigh, std::memory_order_acquire>();
  return GCInfoIndexField::decode(encoded);
}

template <AccessMode mode>
size_t HeapObjectHeader::AllocatedSize() const {
  // Size is immutable after construction while either marking or sweeping
  // is running so relaxed load (if mode == kAtomic) is enough.
  uint16_t encoded_low_value =
      LoadEncoded<mode, EncodedHalf::kLow, std::memory_order_relaxed>();
  const size_t size = DecodeSize(encoded_low_value);
  return size;
}

void HeapObjectHeader::SetAllocatedSize(size_t size) {
#if !defined(CPPGC_YOUNG_GENERATION)
  // With sticky bits, marked objects correspond to old objects.
  // TODO(bikineev:1029379): Consider disallowing old/marked objects to be
  // resized.
  DCHECK(!IsMarked());
#endif
  // The object may be marked (i.e. old, in case young generation is enabled).
  // Make sure to not overwrite the mark bit.
  encoded_low_ &= ~SizeField::encode(SizeField::kMax);
  encoded_low_ |= EncodeSize(size);
}

template <AccessMode mode>
size_t HeapObjectHeader::ObjectSize() const {
  // The following DCHECK also fails for large objects.
  DCHECK_GT(AllocatedSize<mode>(), sizeof(HeapObjectHeader));
  return AllocatedSize<mode>() - sizeof(HeapObjectHeader);
}

template <AccessMode mode>
bool HeapObjectHeader::IsLargeObject() const {
  return AllocatedSize<mode>() == kLargeObjectSizeInHeader;
}

template <AccessMode mode>
bool HeapObjectHeader::IsInConstruction() const {
  const uint16_t encoded =
      LoadEncoded<mode, EncodedHalf::kHigh, std::memory_order_acquire>();
  return !FullyConstructedField::decode(encoded);
}

void HeapObjectHeader::MarkAsFullyConstructed() {
  MakeGarbageCollectedTraitInternal::MarkObjectAsFullyConstructed(
      ObjectStart());
}

template <AccessMode mode>
bool HeapObjectHeader::IsMarked() const {
  const uint16_t encoded =
      LoadEncoded<mode, EncodedHalf::kLow, std::memory_order_relaxed>();
  return MarkBitField::decode(encoded);
}

template <AccessMode mode>
void HeapObjectHeader::Unmark() {
  DCHECK(IsMarked<mode>());
  StoreEncoded<mode, EncodedHalf::kLow, std::memory_order_relaxed>(
      MarkBitField::encode(false), MarkBitField::kMask);
}

bool HeapObjectHeader::TryMarkAtomic() {
  auto* atomic_encoded = v8::base::AsAtomicPtr(&encoded_low_);
  uint16_t old_value = atomic_encoded->load(std::memory_order_relaxed);
  const uint16_t new_value = old_value | MarkBitField::encode(true);
  if (new_value == old_value) {
    return false;
  }
  return atomic_encoded->compare_exchange_strong(old_value, new_value,
                                                 std::memory_order_relaxed);
}

void HeapObjectHeader::MarkNonAtomic() {
  DCHECK(!IsMarked<AccessMode::kNonAtomic>());
  encoded_low_ |= MarkBitField::encode(true);
}

template <AccessMode mode>
bool HeapObjectHeader::IsYoung() const {
  return !IsMarked<mode>();
}

template <AccessMode mode>
bool HeapObjectHeader::IsFree() const {
  return GetGCInfoIndex<mode>() == kFreeListGCInfoIndex;
}

bool HeapObjectHeader::IsFinalizable() const {
  const GCInfo& gc_info = GlobalGCInfoTable::GCInfoFromIndex(GetGCInfoIndex());
  return gc_info.finalize;
}

#if defined(CPPGC_CAGED_HEAP)
void HeapObjectHeader::SetNextUnfinalized(HeapObjectHeader* next) {
#if defined(CPPGC_POINTER_COMPRESSION)
  next_unfinalized_ = CompressedPointer::Compress(next);
#else   // !defined(CPPGC_POINTER_COMPRESSION)
  next_unfinalized_ = CagedHeap::OffsetFromAddress<uint32_t>(next);
#endif  // !defined(CPPGC_POINTER_COMPRESSION)
}

HeapObjectHeader* HeapObjectHeader::GetNextUnfinalized(
    uintptr_t cage_base_or_mask) const {
  DCHECK(cage_base_or_mask);
#if defined(CPPGC_POINTER_COMPRESSION)
  DCHECK_EQ(
      api_constants::kCagedHeapReservationAlignment - 1,
      CagedHeap::OffsetFromAddress(reinterpret_cast<void*>(cage_base_or_mask)));
  return reinterpret_cast<HeapObjectHeader*>(
      CompressedPointer::Decompress(next_unfinalized_, cage_base_or_mask));
#else   // !defined(CPPGC_POINTER_COMPRESSION)
  DCHECK_EQ(0, CagedHeap::OffsetFromAddress(
                   reinterpret_cast<void*>(cage_base_or_mask)));
  return next_unfinalized_ ? reinterpret_cast<HeapObjectHeader*>(
                                 cage_base_or_mask + next_unfinalized_)
                           : nullptr;
#endif  // !defined(CPPGC_POINTER_COMPRESSION)
}
#endif  // defined(CPPGC_CAGED_HEAP)

template <AccessMode mode>
void HeapObjectHeader::Trace(Visitor* visitor) const {
  const GCInfo& gc_info =
      GlobalGCInfoTable::GCInfoFromIndex(GetGCInfoIndex<mode>());
  return gc_info.trace(visitor, ObjectStart());
}

template <AccessMode mode, HeapObjectHeader::EncodedHalf part,
          std::memory_order memory_order>
uint16_t HeapObjectHeader::LoadEncoded() const {
  const uint16_t& half =
      part == EncodedHalf::kLow ? encoded_low_ : encoded_high_;
  if (mode == AccessMode::kNonAtomic) return half;
  return v8::base::AsAtomicPtr(&half)->load(memory_order);
}

template <AccessMode mode, HeapObjectHeader::EncodedHalf part,
          std::memory_order memory_order>
void HeapObjectHeader::StoreEncoded(uint16_t bits, uint16_t mask) {
  // Caveat: Not all changes to HeapObjectHeader's bitfields go through
  // StoreEncoded. The following have their own implementations and need to be
  // kept in sync:
  // - HeapObjectHeader::TryMarkAtomic
  // - MarkObjectAsFullyConstructed (API)
  DCHECK_EQ(0u, bits & ~mask);
  uint16_t& half = part == EncodedHalf::kLow ? encoded_low_ : encoded_high_;
  if (mode == AccessMode::kNonAtomic) {
    half = (half & ~mask) | bits;
    return;
  }
  // We don't perform CAS loop here assuming that only none of the info that
  // shares the same encoded halfs change at the same time.
  auto* atomic_encoded = v8::base::AsAtomicPtr(&half);
  uint16_t value = atomic_encoded->load(std::memory_order_relaxed);
  value = (value & ~mask) | bits;
  atomic_encoded->store(value, memory_order);
}

}  // namespace internal
}  // namespace cppgc

#endif  // V8_HEAP_CPPGC_HEAP_OBJECT_HEADER_H_
```