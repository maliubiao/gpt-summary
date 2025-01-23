Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Scan and Keyword Recognition:** The first step is a quick scan for keywords and structural elements. I'd look for:
    * `#ifndef`, `#define`, `#endif`:  Indicates a header file and include guards.
    * `class`, `struct`:  Definitions of data structures.
    * `namespace`:  Namespace organization.
    * `using`:  Type aliases.
    * `template`:  Generic programming.
    * `static`, `constexpr`:  Static and compile-time constants/functions.
    * `public`, `private`, `protected`:  Access modifiers.
    * `FRIEND_TEST`:  Indicates testing infrastructure.
    * `V8_EXPORT_PRIVATE`:  Likely a macro related to visibility and export within the V8 project.
    * Comments: Providing high-level explanations.

2. **Identify Core Data Structures:**  The names of classes are crucial. "PossiblyEmptyBuckets", "SlotSet", and "TypedSlots"/"TypedSlotSet" immediately stand out as the primary actors.

3. **Analyze `PossiblyEmptyBuckets`:**
    * The name suggests its purpose: tracking buckets that *might* be empty.
    * It uses a bitmap (`bitmap_`) for efficiency. The logic handles the case where the initial bitmap is too small and needs to allocate a larger one on the heap.
    * Key methods: `Insert`, `Contains`, `IsEmpty`, `Release`. These suggest operations for adding, checking, and managing potentially empty buckets.

4. **Analyze `SlotSet`:**
    * Inherits from `BasicSlotSet`. This implies it builds upon a more fundamental slot management mechanism.
    * `kBucketsRegularPage`: A constant related to page size and bucket organization, hinting at memory management.
    * `Allocate`:  A static method for creating `SlotSet` instances.
    * `Iterate`:  Crucial for processing slots within the set. The template with `access_mode` suggests handling concurrency. The callback mechanism is important. The overload with `PossiblyEmptyBuckets` ties it to the previous class.
    * `CheckPossiblyEmptyBuckets`:  Confirms the purpose of `PossiblyEmptyBuckets` – verifying and freeing truly empty buckets.
    * `Merge`:  An operation for combining `SlotSet` instances.

5. **Analyze `TypedSlots` and `TypedSlotSet`:**
    * `SlotType`: An enum defining different types of slots, likely based on the kind of data they hold.
    * `TypedSlots`: Appears to be a base class for managing slots with specific types. The `Chunk` structure suggests a linked-list-like approach for storing typed slot information. The `Insert` and `Merge` methods indicate basic manipulation.
    * `TypedSlotSet`: Inherits from `TypedSlots`. The `FreeRangesMap` and `IterationMode` enum point to features related to removing invalid slots.
    * `Iterate` (in `TypedSlotSet`): Similar to `SlotSet::Iterate`, but tailored for typed slots. The callback provides `SlotType`.
    * `ClearInvalidSlots`:  Specifically designed to remove slots within specified memory ranges.

6. **Infer Functionality and Relationships:** Based on the analysis of individual components, I can start to infer the overall purpose: managing slots (memory locations) within the V8 heap, particularly for garbage collection and memory management purposes. The classes seem to work together:
    * `SlotSet` provides a basic mechanism for tracking slots.
    * `PossiblyEmptyBuckets` optimizes the process by tracking potential empty buckets.
    * `TypedSlots`/`TypedSlotSet` handles slots with specific type information, likely used for code objects and internal V8 structures.

7. **Address Specific Questions in the Prompt:**  Now, I go through the prompt's requirements:

    * **Functionality Listing:**  Summarize the inferred functionalities of each class.
    * **Torque:** Check the file extension. If `.tq`, mention it's Torque.
    * **JavaScript Relationship:** Think about how these internal mechanisms might relate to observable JavaScript behavior. Garbage collection and memory management are key areas.
    * **JavaScript Examples:**  Create simple JavaScript examples that indirectly demonstrate the concepts (e.g., creating objects that would lead to slot allocation and garbage collection).
    * **Code Logic Inference:**  Focus on the `PossiblyEmptyBuckets` logic for bitmap manipulation and the iteration logic in `SlotSet` and `TypedSlotSet`. Provide example inputs and how the bitmaps/iteration would change.
    * **Common Programming Errors:**  Consider how a user might misuse or misunderstand these concepts if they were exposed (though they are internal). Memory leaks due to improper deallocation or corruption due to incorrect pointer handling are possibilities.

8. **Refine and Structure:** Organize the findings into a clear and structured answer, addressing each point in the prompt. Use clear language and provide context. For example, explain *why* these internal mechanisms are important (garbage collection, performance, etc.).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `SlotSet` is just about storing pointers."
* **Correction:**  The presence of `PossiblyEmptyBuckets` and the different `Iterate` overloads suggest it's not just about storing, but also about efficiently managing and processing these slots, especially during garbage collection.
* **Initial thought:** "How does `TypedSlotSet` relate to JavaScript?"
* **Correction:** Realize that `TypedSlotSet` likely deals with internal V8 structures like compiled code, which are not directly manipulated by JavaScript but are essential for its execution. The connection is more indirect.
* **Initial thought:**  "Can I give a direct JavaScript example of manipulating a slot?"
* **Correction:** These are internal V8 structures. Direct manipulation isn't possible. The JavaScript examples need to be about actions that *trigger* the underlying slot management.

By following this structured approach, combining keyword recognition, analysis of data structures and methods, and then addressing the specific points in the prompt, I can arrive at a comprehensive and accurate understanding of the C++ header file's purpose.
This header file `v8/src/heap/slot-set.h` defines data structures and functionalities for managing memory slots within the V8 JavaScript engine's heap. These slots are fundamental units of memory allocation and are crucial for garbage collection and efficient memory management.

Here's a breakdown of its functionality:

**1. `PossiblyEmptyBuckets` Class:**

* **Functionality:**  This class efficiently tracks memory buckets that *might* be empty. In V8's heap, memory is often divided into buckets. The garbage collector (scavenger) might find buckets that appear empty. However, due to concurrent operations (other threads, object promotion), these buckets might become non-empty later. This class uses a bitmap to remember these potentially empty buckets so they can be revisited later to confirm their status.
* **Implementation Details:**
    * It starts with a word-sized bitmap for small numbers of buckets.
    * If the number of buckets exceeds the capacity of the initial bitmap, it dynamically allocates a larger bitmap on the heap.
    * It provides methods to `Insert` (mark a bucket as potentially empty), `Contains` (check if a bucket is marked), `IsEmpty` (check if any buckets are marked), and `Release` (free the allocated bitmap if needed).
* **Purpose:** Optimizes garbage collection by avoiding unnecessary checks of all buckets.

**2. `SlotSet` Class:**

* **Functionality:**  This class represents a set of slots within a memory page. It's used to track which slots in a page contain pointers to other objects. This information is essential for garbage collection to trace object references and prevent dangling pointers. `SlotSet` inherits from `BasicSlotSet`, suggesting it builds upon a more fundamental implementation.
* **Key Features:**
    * **Bucket-based organization:**  Slots are grouped into buckets for efficiency.
    * **Allocation:**  Provides a static `Allocate` method to create `SlotSet` instances.
    * **Iteration:**  Offers various `Iterate` methods to traverse the slots within a specified range of buckets. These methods accept a callback function that's executed for each slot.
        *  The `Iterate` methods can handle different access modes (atomic or non-atomic), useful for concurrent operations.
        *  One `Iterate` overload takes a `PossiblyEmptyBuckets` object to track potentially empty buckets during iteration.
    * **`CheckPossiblyEmptyBuckets`:**  Verifies if the buckets marked as potentially empty are truly empty and releases them if they are.
    * **`Merge`:**  Allows merging another `SlotSet` into the current one.
* **Purpose:**  Provides a structured way to manage and iterate over slots within a memory page, vital for garbage collection and maintaining heap integrity.

**3. `SlotType` Enum:**

* **Functionality:** Defines different types of slots, indicating the kind of data the slot holds. This is particularly relevant for code objects, where slots can point to embedded objects, code entry points, or other data.
* **Types:** Includes `kEmbeddedObjectFull`, `kEmbeddedObjectCompressed`, `kCodeEntry`, `kConstPoolEmbeddedObjectFull`, `kConstPoolEmbeddedObjectCompressed`, `kConstPoolCodeEntry`, and `kCleared`. The "Full" and "Compressed" suffixes likely refer to whether the pointer is a full 64-bit address or a compressed (tagged) address. "ConstPool" indicates slots within the constant pool of a code object. `kCleared` signifies a slot that has been cleared but not yet removed from the set.

**4. `TypedSlots` Class:**

* **Functionality:**  Manages a list of typed slots within a page. This is primarily used for Code objects, which contain various internal pointers that need to be tracked.
* **Implementation:** Uses a chain of `Chunk` structures, where each chunk holds an array of `TypedSlot` entries. Each `TypedSlot` stores the `SlotType` and the offset of the slot within the page.
* **Key Methods:**
    * `Insert`: Adds a new typed slot to the list.
    * `Merge`: Combines another `TypedSlots` instance into the current one.
* **Purpose:** Provides a mechanism to specifically track different types of pointers within Code objects.

**5. `TypedSlotSet` Class:**

* **Functionality:**  A multiset of per-page typed slots that allows concurrent iteration and clearing of invalid slots. It inherits from `TypedSlots`.
* **Key Features:**
    * **Concurrency support:** Designed to allow concurrent iteration and clearing operations.
    * **`Iterate`:**  Iterates over the typed slots and allows a callback to process each slot. The callback can indicate whether to `KEEP_SLOT` or `REMOVE_SLOT`.
    * **`ClearInvalidSlots`:**  Removes slots whose offsets fall within specified invalid ranges. This is likely used during garbage collection when objects are freed, and their associated slots need to be cleared.
    * **`AssertNoInvalidSlots`:**  Used for debugging, asserting that no slots exist within given invalid ranges.
    * **`FreeToBeFreedChunks`:**  Frees empty chunks that were previously marked for deletion.
* **Purpose:**  Provides a thread-safe way to manage and clean up typed slots, crucial for maintaining the integrity of Code objects during garbage collection.

**Is `v8/src/heap/slot-set.h` a v8 torque source file?**

No, it's not a Torque source file. Torque files have the `.tq` extension. This file has the standard C++ header extension `.h`.

**Relationship with JavaScript functionality and JavaScript examples:**

While this header file is part of V8's internal implementation and not directly exposed to JavaScript, its functionality is fundamental to how JavaScript code executes. Here's how it relates and some illustrative (though indirect) JavaScript examples:

* **Memory Management and Garbage Collection:** The core purpose of these classes is to manage memory slots and track object references. This is directly tied to JavaScript's automatic garbage collection. When you create objects in JavaScript, V8 allocates memory for them and uses these slot sets to remember where those objects are and which other objects they reference.

   ```javascript
   // Creating objects in JavaScript will lead to memory allocation
   // and the usage of slot sets internally.
   let obj1 = { name: "Alice" };
   let obj2 = { friend: obj1 };

   // When obj1 is no longer reachable (e.g., by setting the reference to null),
   // the garbage collector will use the information in the slot sets
   // to identify it as garbage and reclaim its memory.
   obj1 = null;
   ```

* **Code Objects and Function Calls:** The `TypedSlots` and `TypedSlotSet` are specifically used for Code objects, which represent compiled JavaScript functions. When you define and call functions:

   ```javascript
   function greet(name) {
     return "Hello, " + name;
   }

   greet("Bob"); // This involves executing the compiled code for the 'greet' function.
   ```

   Internally, V8 creates Code objects for these functions. These Code objects contain pointers to other objects, embedded data, and entry points, which are tracked using the `TypedSlotSet`.

* **Performance Optimizations:** The `PossiblyEmptyBuckets` class demonstrates how V8 optimizes garbage collection. By efficiently tracking potentially empty buckets, it avoids unnecessary work during the scavenging process, contributing to smoother and faster JavaScript execution.

**Code Logic Inference (Example with `PossiblyEmptyBuckets`):**

**Assumption:**  We have a `PossiblyEmptyBuckets` object and are tracking emptiness in buckets. Let's assume `kBitsPerWord` is 64.

**Input:**

1. Initially, the `PossiblyEmptyBuckets` object is created (`bitmap_` is `kNullAddress`).
2. We call `Insert(5, 100)` to mark bucket 5 as potentially empty.
3. We call `Insert(6)` (internally, `Insert(6, 100)`) to mark bucket 6.
4. We call `Insert(65, 100)` to mark bucket 65.

**Output and Reasoning:**

1. After the first `Insert(5, 100)`:
    * `IsAllocated()` is false.
    * `bitmap_` becomes `0b000000100000` (the 6th bit is set, representing bucket index 5 + 1).

2. After the second `Insert(6)`:
    * `IsAllocated()` is false.
    * `bitmap_` becomes `0b000001100000` (the 6th and 7th bits are set).

3. After the third `Insert(65, 100)`:
    * Since `65 + 1 >= kBitsPerWord`, `Allocate(100)` is called.
    * A memory block is allocated to hold the bitmap. Let's say the allocated address is `0x1000`.
    * `ptr[0]` is set to the previous `bitmap_` value shifted right by 1: `0b000000110000`.
    * `ptr[1]` (for the second word) is initialized to 0.
    * The bit for bucket 65 is set in `ptr[1]`: `ptr[1]` becomes `0b0000000000000000000000000000001000000000000000000000000000000000`.
    * `bitmap_` becomes `0x1001` (the address of the allocated memory + the `kPointerTag`).
    * `IsAllocated()` is now true.

4. Calling `Contains(5)` would return `true` because the corresponding bit is set in the initial bitmap (now in `ptr[0]`).
5. Calling `Contains(65)` would return `true` because the corresponding bit is set in the allocated bitmap (in `ptr[1]`).
6. Calling `Contains(10)` would return `false`.

**User-Common Programming Errors (Relating to concepts in the header):**

While users don't directly interact with these classes, understanding the underlying concepts can help avoid performance pitfalls and memory-related issues in JavaScript. Here are some analogies:

1. **Creating too many short-lived objects:**  If a JavaScript program creates a large number of temporary objects, it puts pressure on the garbage collector. Internally, this means the `SlotSet` and related structures need to be frequently updated as slots are allocated and deallocated. This can lead to performance overhead if not managed carefully.

    ```javascript
    // Avoid creating excessive temporary objects in loops if possible
    function processData(data) {
      let results = [];
      for (let i = 0; i < data.length; i++) {
        // Inefficient: creating a new object in each iteration
        results.push({ index: i, value: data[i] * 2 });
      }
      return results;
    }
    ```

2. **Holding onto object references unnecessarily:** If objects are no longer needed but are still referenced, the garbage collector cannot reclaim their memory. This can lead to memory leaks. The `SlotSet` would continue to track these references.

    ```javascript
    let largeData = [];
    for (let i = 0; i < 1000000; i++) {
      largeData.push({ value: i });
    }

    // If 'globalReference' persists even after 'largeData' is no longer used,
    // the memory occupied by 'largeData' won't be freed.
    globalReference = largeData;
    ```

3. **Understanding the implications of closures:** Closures can inadvertently keep references to variables and objects alive longer than expected, impacting garbage collection.

    ```javascript
    function createCounter() {
      let count = 0;
      return function() {
        count++;
        console.log(count);
      };
    }

    const counter = createCounter();
    // The 'counter' function keeps a reference to the 'count' variable,
    // even after 'createCounter' has finished executing.
    ```

In summary, `v8/src/heap/slot-set.h` defines essential data structures and functionalities for managing memory within the V8 engine. While users don't directly interact with these classes, understanding their purpose provides insight into how JavaScript's memory management and garbage collection work, which can help in writing more performant and memory-efficient JavaScript code.

### 提示词
```
这是目录为v8/src/heap/slot-set.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/slot-set.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_SLOT_SET_H_
#define V8_HEAP_SLOT_SET_H_

#include <map>
#include <memory>
#include <stack>
#include <vector>

#include "src/base/bit-field.h"
#include "src/heap/base/basic-slot-set.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/slots.h"
#include "src/utils/allocation.h"
#include "src/utils/utils.h"
#include "testing/gtest/include/gtest/gtest_prod.h"  // nogncheck

namespace v8 {
namespace internal {

using ::heap::base::KEEP_SLOT;
using ::heap::base::REMOVE_SLOT;
using ::heap::base::SlotCallbackResult;

// Possibly empty buckets (buckets that do not contain any slots) are discovered
// by the scavenger. Buckets might become non-empty when promoting objects later
// or in another thread, so all those buckets need to be revisited.
// Track possibly empty buckets within a SlotSet in this data structure. The
// class contains a word-sized bitmap, in case more bits are needed the bitmap
// is replaced with a pointer to a malloc-allocated bitmap.
class PossiblyEmptyBuckets {
 public:
  PossiblyEmptyBuckets() = default;
  PossiblyEmptyBuckets(PossiblyEmptyBuckets&& other) V8_NOEXCEPT
      : bitmap_(other.bitmap_) {
    other.bitmap_ = kNullAddress;
  }

  ~PossiblyEmptyBuckets() { Release(); }

  PossiblyEmptyBuckets(const PossiblyEmptyBuckets&) = delete;
  PossiblyEmptyBuckets& operator=(const PossiblyEmptyBuckets&) = delete;

  void Release() {
    if (IsAllocated()) {
      AlignedFree(BitmapArray());
    }
    bitmap_ = kNullAddress;
    DCHECK(!IsAllocated());
  }

  void Insert(size_t bucket_index, size_t buckets) {
    if (IsAllocated()) {
      InsertAllocated(bucket_index);
    } else if (bucket_index + 1 < kBitsPerWord) {
      bitmap_ |= static_cast<uintptr_t>(1) << (bucket_index + 1);
    } else {
      Allocate(buckets);
      InsertAllocated(bucket_index);
    }
  }

  bool Contains(size_t bucket_index) {
    if (IsAllocated()) {
      size_t word_idx = bucket_index / kBitsPerWord;
      uintptr_t* word = BitmapArray() + word_idx;
      return *word &
             (static_cast<uintptr_t>(1) << (bucket_index % kBitsPerWord));
    } else if (bucket_index + 1 < kBitsPerWord) {
      return bitmap_ & (static_cast<uintptr_t>(1) << (bucket_index + 1));
    } else {
      return false;
    }
  }

  bool IsEmpty() const { return bitmap_ == kNullAddress; }

 private:
  static constexpr Address kPointerTag = 1;
  static constexpr int kWordSize = sizeof(uintptr_t);
  static constexpr int kBitsPerWord = kWordSize * kBitsPerByte;

  bool IsAllocated() { return bitmap_ & kPointerTag; }

  void Allocate(size_t buckets) {
    DCHECK(!IsAllocated());
    size_t words = WordsForBuckets(buckets);
    uintptr_t* ptr = reinterpret_cast<uintptr_t*>(
        AlignedAllocWithRetry(words * kWordSize, kSystemPointerSize));
    ptr[0] = bitmap_ >> 1;

    for (size_t word_idx = 1; word_idx < words; word_idx++) {
      ptr[word_idx] = 0;
    }
    bitmap_ = reinterpret_cast<Address>(ptr) + kPointerTag;
    DCHECK(IsAllocated());
  }

  void InsertAllocated(size_t bucket_index) {
    DCHECK(IsAllocated());
    size_t word_idx = bucket_index / kBitsPerWord;
    uintptr_t* word = BitmapArray() + word_idx;
    *word |= static_cast<uintptr_t>(1) << (bucket_index % kBitsPerWord);
  }

  static size_t WordsForBuckets(size_t buckets) {
    return (buckets + kBitsPerWord - 1) / kBitsPerWord;
  }

  uintptr_t* BitmapArray() {
    DCHECK(IsAllocated());
    return reinterpret_cast<uintptr_t*>(bitmap_ & ~kPointerTag);
  }

  Address bitmap_ = kNullAddress;

  FRIEND_TEST(PossiblyEmptyBucketsTest, WordsForBuckets);
};

static_assert(std::is_standard_layout<PossiblyEmptyBuckets>::value);
static_assert(sizeof(PossiblyEmptyBuckets) == kSystemPointerSize);

class SlotSet final : public ::heap::base::BasicSlotSet<kTaggedSize> {
  using BasicSlotSet = ::heap::base::BasicSlotSet<kTaggedSize>;

 public:
  static const int kBucketsRegularPage =
      (1 << kPageSizeBits) / kTaggedSize / kCellsPerBucket / kBitsPerCell;

  static SlotSet* Allocate(size_t buckets) {
    return static_cast<SlotSet*>(BasicSlotSet::Allocate(buckets));
  }

  template <v8::internal::AccessMode access_mode>
  static constexpr BasicSlotSet::AccessMode ConvertAccessMode() {
    switch (access_mode) {
      case v8::internal::AccessMode::ATOMIC:
        return BasicSlotSet::AccessMode::ATOMIC;
      case v8::internal::AccessMode::NON_ATOMIC:
        return BasicSlotSet::AccessMode::NON_ATOMIC;
    }
  }

  // Similar to BasicSlotSet::Iterate() but Callback takes the parameter of type
  // MaybeObjectSlot.
  template <
      v8::internal::AccessMode access_mode = v8::internal::AccessMode::ATOMIC,
      typename Callback>
  size_t Iterate(Address chunk_start, size_t start_bucket, size_t end_bucket,
                 Callback callback, EmptyBucketMode mode) {
    return BasicSlotSet::Iterate<ConvertAccessMode<access_mode>()>(
        chunk_start, start_bucket, end_bucket,
        [&callback](Address slot) { return callback(MaybeObjectSlot(slot)); },
        [this, mode](size_t bucket_index) {
          if (mode == EmptyBucketMode::FREE_EMPTY_BUCKETS) {
            ReleaseBucket(bucket_index);
          }
        });
  }

  // Similar to SlotSet::Iterate() but marks potentially empty buckets
  // internally. Stores true in empty_bucket_found in case a potentially empty
  // bucket was found. Assumes that the possibly empty-array was already cleared
  // by CheckPossiblyEmptyBuckets.
  template <typename Callback>
  size_t IterateAndTrackEmptyBuckets(
      Address chunk_start, size_t start_bucket, size_t end_bucket,
      Callback callback, PossiblyEmptyBuckets* possibly_empty_buckets) {
    return BasicSlotSet::Iterate(
        chunk_start, start_bucket, end_bucket,
        [&callback](Address slot) { return callback(MaybeObjectSlot(slot)); },
        [possibly_empty_buckets, end_bucket](size_t bucket_index) {
          possibly_empty_buckets->Insert(bucket_index, end_bucket);
        });
  }

  // Check whether possibly empty buckets are really empty. Empty buckets are
  // freed and the possibly empty state is cleared for all buckets.
  bool CheckPossiblyEmptyBuckets(size_t buckets,
                                 PossiblyEmptyBuckets* possibly_empty_buckets) {
    bool empty = true;
    for (size_t bucket_index = 0; bucket_index < buckets; bucket_index++) {
      Bucket* bucket = LoadBucket<AccessMode::NON_ATOMIC>(bucket_index);
      if (bucket) {
        if (possibly_empty_buckets->Contains(bucket_index)) {
          if (bucket->IsEmpty()) {
            ReleaseBucket<AccessMode::NON_ATOMIC>(bucket_index);
          } else {
            empty = false;
          }
        } else {
          empty = false;
        }
      } else {
        // Unfortunately we cannot DCHECK here that the corresponding bit in
        // possibly_empty_buckets is not set. After scavenge, the
        // MergeOldToNewRememberedSets operation might remove a recorded bucket.
      }
    }

    possibly_empty_buckets->Release();

    return empty;
  }

  void Merge(SlotSet* other, size_t buckets) {
    for (size_t bucket_index = 0; bucket_index < buckets; bucket_index++) {
      Bucket* other_bucket =
          other->LoadBucket<AccessMode::NON_ATOMIC>(bucket_index);
      if (!other_bucket) continue;
      Bucket* bucket = LoadBucket<AccessMode::NON_ATOMIC>(bucket_index);
      if (bucket == nullptr) {
        other->StoreBucket<AccessMode::NON_ATOMIC>(bucket_index, nullptr);
        StoreBucket<AccessMode::NON_ATOMIC>(bucket_index, other_bucket);
      } else {
        for (int cell_index = 0; cell_index < kCellsPerBucket; cell_index++) {
          bucket->SetCellBits<AccessMode::NON_ATOMIC>(
              cell_index,
              other_bucket->LoadCell<AccessMode::NON_ATOMIC>(cell_index));
        }
      }
    }
  }
};

static_assert(std::is_standard_layout<SlotSet>::value);
static_assert(std::is_standard_layout<SlotSet::Bucket>::value);

enum class SlotType : uint8_t {
  // Full pointer sized slot storing an object start address.
  // RelocInfo::target_object/RelocInfo::set_target_object methods are used for
  // accessing. Used when pointer is stored in the instruction stream.
  kEmbeddedObjectFull,

  // Tagged sized slot storing an object start address.
  // RelocInfo::target_object/RelocInfo::set_target_object methods are used for
  // accessing. Used when pointer is stored in the instruction stream.
  kEmbeddedObjectCompressed,

  // Full pointer sized slot storing instruction start of Code object.
  // RelocInfo::target_address/RelocInfo::set_target_address methods are used
  // for accessing. Used when pointer is stored in the instruction stream.
  kCodeEntry,

  // Raw full pointer sized slot. Slot is accessed directly. Used when pointer
  // is stored in constant pool.
  kConstPoolEmbeddedObjectFull,

  // Raw tagged sized slot. Slot is accessed directly. Used when pointer is
  // stored in constant pool.
  kConstPoolEmbeddedObjectCompressed,

  // Raw full pointer sized slot storing instruction start of Code object. Slot
  // is accessed directly. Used when pointer is stored in constant pool.
  kConstPoolCodeEntry,

  // Slot got cleared but has not been removed from the slot set.
  kCleared,

  kLast = kCleared
};

// Data structure for maintaining a list of typed slots in a page.
// Typed slots can only appear in Code objects, so
// the maximum possible offset is limited by the
// LargePageMetadata::kMaxCodePageSize. The implementation is a chain of chunks,
// where each chunk is an array of encoded (slot type, slot offset) pairs. There
// is no duplicate detection and we do not expect many duplicates because typed
// slots contain V8 internal pointers that are not directly exposed to JS.
class V8_EXPORT_PRIVATE TypedSlots {
 public:
  static const int kMaxOffset = 1 << 29;
  TypedSlots() = default;
  virtual ~TypedSlots();
  void Insert(SlotType type, uint32_t offset);
  void Merge(TypedSlots* other);

 protected:
  using OffsetField = base::BitField<int, 0, 29>;
  using TypeField = base::BitField<SlotType, 29, 3>;
  struct TypedSlot {
    uint32_t type_and_offset;
  };
  struct Chunk {
    Chunk* next;
    std::vector<TypedSlot> buffer;
  };
  static const size_t kInitialBufferSize = 100;
  static const size_t kMaxBufferSize = 16 * KB;
  static size_t NextCapacity(size_t capacity) {
    return std::min({kMaxBufferSize, capacity * 2});
  }
  Chunk* EnsureChunk();
  Chunk* NewChunk(Chunk* next, size_t capacity);
  Chunk* head_ = nullptr;
  Chunk* tail_ = nullptr;
};

// A multiset of per-page typed slots that allows concurrent iteration
// clearing of invalid slots.
class V8_EXPORT_PRIVATE TypedSlotSet : public TypedSlots {
 public:
  using FreeRangesMap = std::map<uint32_t, uint32_t>;

  enum IterationMode { FREE_EMPTY_CHUNKS, KEEP_EMPTY_CHUNKS };

  explicit TypedSlotSet(Address page_start) : page_start_(page_start) {}

  // Iterate over all slots in the set and for each slot invoke the callback.
  // If the callback returns REMOVE_SLOT then the slot is removed from the set.
  // Returns the new number of slots.
  //
  // Sample usage:
  // Iterate([](SlotType slot_type, Address slot_address) {
  //    if (good(slot_type, slot_address)) return KEEP_SLOT;
  //    else return REMOVE_SLOT;
  // });
  // This can run concurrently to ClearInvalidSlots().
  template <typename Callback>
  int Iterate(Callback callback, IterationMode mode) {
    static_assert(static_cast<uint8_t>(SlotType::kLast) < 8);
    Chunk* chunk = head_;
    Chunk* previous = nullptr;
    int new_count = 0;
    while (chunk != nullptr) {
      bool empty = true;
      for (TypedSlot& slot : chunk->buffer) {
        SlotType type = TypeField::decode(slot.type_and_offset);
        if (type != SlotType::kCleared) {
          uint32_t offset = OffsetField::decode(slot.type_and_offset);
          Address addr = page_start_ + offset;
          if (callback(type, addr) == KEEP_SLOT) {
            new_count++;
            empty = false;
          } else {
            slot = ClearedTypedSlot();
          }
        }
      }
      Chunk* next = chunk->next;
      if (mode == FREE_EMPTY_CHUNKS && empty) {
        // We remove the chunk from the list but let it still point its next
        // chunk to allow concurrent iteration.
        if (previous) {
          StoreNext(previous, next);
        } else {
          StoreHead(next);
        }

        delete chunk;
      } else {
        previous = chunk;
      }
      chunk = next;
    }
    return new_count;
  }

  // Clears all slots that have the offset in the specified ranges.
  // This can run concurrently to Iterate().
  void ClearInvalidSlots(const FreeRangesMap& invalid_ranges);

  // Asserts that there are no recorded slots in the specified ranges.
  void AssertNoInvalidSlots(const FreeRangesMap& invalid_ranges);

  // Frees empty chunks accumulated by PREFREE_EMPTY_CHUNKS.
  void FreeToBeFreedChunks();

 private:
  template <typename Callback>
  void IterateSlotsInRanges(Callback callback,
                            const FreeRangesMap& invalid_ranges);

  // Atomic operations used by Iterate and ClearInvalidSlots;
  Chunk* LoadNext(Chunk* chunk) {
    return base::AsAtomicPointer::Relaxed_Load(&chunk->next);
  }
  void StoreNext(Chunk* chunk, Chunk* next) {
    return base::AsAtomicPointer::Relaxed_Store(&chunk->next, next);
  }
  Chunk* LoadHead() { return base::AsAtomicPointer::Relaxed_Load(&head_); }
  void StoreHead(Chunk* chunk) {
    base::AsAtomicPointer::Relaxed_Store(&head_, chunk);
  }
  static TypedSlot ClearedTypedSlot() {
    return TypedSlot{TypeField::encode(SlotType::kCleared) |
                     OffsetField::encode(0)};
  }

  Address page_start_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_SLOT_SET_H_
```