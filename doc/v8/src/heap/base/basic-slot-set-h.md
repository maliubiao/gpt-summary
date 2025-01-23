Response:
My thought process to analyze the `BasicSlotSet` code and generate the requested information would go something like this:

1. **Understand the Core Purpose:** The first thing I'd do is read the initial comments and the class name. "Data structure for maintaining a set of slots" and "BasicSlotSet" immediately tell me this is about storing and managing a collection of something called "slots". The "bitmap" mention hints at an efficient way to represent presence/absence.

2. **Deconstruct the Data Structure:** I'd then look at the internal structure. The nested `Bucket` class and the array of `Bucket*` strongly suggest a two-level structure, as the comments confirm. I'd visualize this as an array of "buckets," where each bucket contains a bitmap to track individual slots.

3. **Analyze Key Methods:**  I'd go through the public methods, trying to understand their purpose:
    * `Allocate`: Creates the `BasicSlotSet` structure, including the bucket array. The comment about `kNumBucketsSize` is important.
    * `Delete`: Cleans up the allocated memory.
    * `BucketsForSize`:  Calculates the number of buckets needed for a given size. This links the slot set to some underlying memory region.
    * `BucketForSlot`, `OffsetForBucket`: These are clearly conversion functions between slot offsets and bucket indices.
    * `Insert`: Adds a slot to the set. The logic with `SwapInNewBucket` suggests thread-safety considerations.
    * `Contains`: Checks if a slot is present.
    * `Remove`: Removes a single slot.
    * `RemoveRange`: Removes a range of slots. This looks more complex and likely optimized for bulk removal.
    * `Lookup`: Seems like an alias for `Contains`.
    * `Iterate`:  Crucially, this is about processing each slot in the set, potentially modifying it. The `Callback` parameter is key. The different `AccessMode` and `EmptyBucketMode` are important differentiators.

4. **Connect to V8 Concepts:** I'd think about where this `BasicSlotSet` might be used in V8. The namespace `heap::base` is a strong clue – it's related to memory management within the V8 heap. The term "slot" makes me think of object properties or pointers within objects. The connection to write barriers (mentioned in comments and the friend declaration) solidifies the idea that this is used to track pointers that might need updating during garbage collection.

5. **Consider Torque:** The prompt specifically asks about `.tq` files. I know Torque is V8's internal language for implementing built-in functions. Given that `BasicSlotSet` is a low-level memory management structure, it's *unlikely* to be directly implemented in Torque. Torque typically operates at a higher level of abstraction. Therefore, I'd conclude that `basic-slot-set.h` is C++ and not a Torque file.

6. **JavaScript Relationship:** The key here is understanding the *purpose* of the `BasicSlotSet`. If it's tracking pointers for garbage collection, then it's indirectly related to how JavaScript objects are managed. When JavaScript code creates objects or modifies their properties, the underlying V8 engine uses structures like `BasicSlotSet` to keep track of memory relationships.

7. **Code Logic and Examples:** I'd pick a simple method like `Insert` and `Contains` to illustrate the logic. I'd devise simple input (a slot offset) and trace how the methods would interact with the internal data structures to produce the output (whether the slot is present).

8. **Common Programming Errors:**  Thinking about how a user might misuse this (if they had direct access, which they don't usually), I'd consider things like:
    * Providing unaligned slot offsets.
    * Trying to access slots outside the allocated range.
    * Concurrency issues if not using the `ATOMIC` access mode correctly (though users don't directly interact with this class).

9. **Structure the Output:** Finally, I'd organize my findings into the requested sections: "功能 (Functionality)", "Torque Source Code?", "与 JavaScript 的关系 (Relationship with JavaScript)", "代码逻辑推理 (Code Logic Inference)", and "用户常见的编程错误 (Common User Programming Errors)". I'd use clear language and examples to explain the concepts.

By following this systematic approach, I could accurately analyze the provided C++ header file and generate a comprehensive explanation covering its functionality, relationship to other V8 components, and potential areas of misunderstanding. The key is to combine reading the code with understanding the broader context of V8's memory management.
## v8 源代码 `v8/src/heap/base/basic-slot-set.h` 的功能解析

这个头文件定义了一个模板类 `BasicSlotSet`，用于维护一组**槽位 (slots)**。从代码和注释来看，它采用了一种**两级位图 (2-level bitmap)** 的数据结构来实现高效地存储和操作这些槽位。

**核心功能分解:**

1. **槽位管理:** `BasicSlotSet` 负责记录哪些槽位是已使用的。槽位在这里可以理解为内存中的特定位置，通常用于存储指向其他对象的指针。

2. **两级位图结构:**
   - **Buckets (桶):**  将整个槽位范围划分为多个 "桶"。
   - **Bitmap (位图):** 每个桶内部使用一个位图来表示该桶内的哪些槽位被占用。位图中的每一位对应一个槽位。

3. **内存对齐假设:**  它假设槽位是按照 `SlotGranularity` 对齐的。这意味着槽位的偏移量总是 `SlotGranularity` 的倍数。

4. **原子操作支持:** 提供了 `ATOMIC` 和 `NON_ATOMIC` 两种访问模式，允许在多线程环境下进行安全的插入、删除和迭代操作。

5. **动态分配和释放:**  可以动态地分配和释放 `BasicSlotSet` 实例以及其内部的桶。

6. **范围操作:**  支持批量移除一定范围内的槽位。

7. **迭代功能:**  提供迭代器，可以遍历所有已使用的槽位，并执行回调函数。

8. **性能优化:**  通过两级位图结构，可以有效地进行查找、插入和删除操作，尤其是在处理大量槽位时。

**如果 `v8/src/heap/base/basic-slot-set.h` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用来定义其内置函数和运行时代码的领域特定语言。在这种情况下，`.tq` 文件会包含使用 Torque 语法实现的 `BasicSlotSet` 的逻辑，或者更可能是定义了与 `BasicSlotSet` 交互或使用它的 Torque 代码。

**与 JavaScript 的功能关系:**

`BasicSlotSet` 与 JavaScript 的功能有密切关系，因为它在 V8 引擎的**垃圾回收 (Garbage Collection, GC)** 机制中扮演着重要角色。

在 JavaScript 中，对象之间的引用关系构成了对象图。垃圾回收器需要跟踪这些引用，以确定哪些对象是可达的（live）而哪些是不可达的（dead），从而回收不再使用的内存。

`BasicSlotSet` 可以被用来**记录对象中的指针槽位**。当一个对象包含指向其他对象的指针时，这些指针的地址就可以被记录在 `BasicSlotSet` 中。

在垃圾回收的标记阶段，GC 算法会遍历这些 `BasicSlotSet`，找到所有被引用的对象，并进行标记。

**JavaScript 示例 (概念性):**

虽然 JavaScript 代码不能直接操作 `BasicSlotSet`，但其行为会影响 V8 如何使用它。

```javascript
let obj1 = { value: 1 };
let obj2 = { ref: obj1 }; // obj2 引用了 obj1

// 当创建 obj2 时，V8 内部可能会在某个地方使用 BasicSlotSet
// 来记录 obj2 的某个槽位指向了 obj1 的内存地址。

obj2.ref = null; // 解除引用

// 在垃圾回收过程中，V8 会检查 BasicSlotSet，发现已经没有其他对象
// 强引用 obj1 了（假设没有其他引用），那么 obj1 可能会被回收。
```

**代码逻辑推理:**

**假设输入:**

- `SlotGranularity` 为 8 字节 (常见的指针大小)。
- 创建一个 `BasicSlotSet`，大小足以容纳 128 个槽位 (`BucketsForSize(128 * 8)`)。
- 插入槽位偏移量 16, 32, 64。

**代码执行流程:**

1. **`Insert(16)`:**
   - `BucketForSlot(16)` 计算出对应的桶索引。
   - `SlotToIndices(16, ...)` 计算出桶索引、单元索引和位索引。
   - 如果对应的桶不存在，则分配一个新的 `Bucket`。
   - 在对应桶的位图中，将与槽位偏移量 16 相关的位设置为 1。

2. **`Insert(32)`:** 类似地，将与槽位偏移量 32 相关的位设置为 1。

3. **`Insert(64)`:** 类似地，将与槽位偏移量 64 相关的位设置为 1。

**假设输出 (`Contains` 方法):**

- `Contains(16)` 返回 `true`。
- `Contains(32)` 返回 `true`。
- `Contains(64)` 返回 `true`。
- `Contains(24)` 返回 `false` (因为 24 不是插入的槽位)。

**用户常见的编程错误 (与 V8 内部使用相关):**

由于 `BasicSlotSet` 是 V8 内部使用的低级数据结构，普通 JavaScript 开发者不会直接与之交互，因此直接的编程错误不太可能发生。

但是，理解其背后的原理可以帮助理解与内存管理和性能相关的一些问题：

1. **意外地保持对象引用:**  如果 JavaScript 代码中存在意外的强引用，导致本应被回收的对象仍然被引用，那么 V8 的垃圾回收器会继续扫描这些对象（包括它们 `BasicSlotSet` 中记录的槽位），这会影响垃圾回收的效率。

   ```javascript
   let obj1 = { data: new Array(100000) };
   let cache = {};
   cache['large_object'] = obj1; // 意外地将 obj1 缓存起来了

   obj1 = null; // 期望 obj1 被回收，但它仍然被 cache 引用

   // 垃圾回收器在扫描 `cache` 时，仍然会访问到 `obj1`，
   // 即使开发者认为 `obj1` 已经不再使用了。
   ```

2. **创建过多的临时对象:**  频繁创建和丢弃大量临时对象会导致垃圾回收器更频繁地运行，并且需要扫描更多的槽位，影响性能。

   ```javascript
   function processData(data) {
       for (let i = 0; i < data.length; i++) {
           let temp = { value: data[i] * 2 }; // 频繁创建临时对象
           // ... 对 temp 进行一些操作 ...
       }
   }
   ```

**总结:**

`v8/src/heap/base/basic-slot-set.h` 定义了一个用于高效管理内存槽位的数据结构，它是 V8 垃圾回收机制的关键组成部分。虽然 JavaScript 开发者不直接操作它，但理解其功能有助于理解 V8 的内存管理方式以及如何编写更高效的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/heap/base/basic-slot-set.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/base/basic-slot-set.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_BASE_BASIC_SLOT_SET_H_
#define V8_HEAP_BASE_BASIC_SLOT_SET_H_

#include <cstddef>
#include <memory>

#include "src/base/atomic-utils.h"
#include "src/base/bits.h"
#include "src/base/platform/memory.h"

namespace v8::internal {
class WriteBarrierCodeStubAssembler;
}  // namespace v8::internal

namespace heap {
namespace base {

enum SlotCallbackResult { KEEP_SLOT, REMOVE_SLOT };

// Data structure for maintaining a set of slots.
//
// On a high-level the set implements a 2-level bitmap. The set assumes that the
// slots are `SlotGranularity`-aligned and splits the valid slot offset range
// into buckets. Each bucket is a bitmap with a bit corresponding to a single
// slot offset.
template <size_t SlotGranularity>
class BasicSlotSet {
  static constexpr auto kSystemPointerSize = sizeof(void*);

 public:
  using Address = uintptr_t;

  enum AccessMode : uint8_t {
    ATOMIC,
    NON_ATOMIC,
  };

  enum EmptyBucketMode {
    FREE_EMPTY_BUCKETS,  // An empty bucket will be deallocated immediately.
    KEEP_EMPTY_BUCKETS   // An empty bucket will be kept.
  };

  BasicSlotSet() = delete;

  static BasicSlotSet* Allocate(size_t buckets) {
    //  BasicSlotSet* slot_set --+
    //                           |
    //                           v
    //         +-----------------+-------------------------+
    //         |    num buckets  |     buckets array       |
    //         +-----------------+-------------------------+
    //                size_t          Bucket* buckets
    //
    //
    // The BasicSlotSet pointer points to the beginning of the buckets array for
    // faster access in the write barrier. The number of buckets is maintained
    // for checking bounds for the heap sandbox.
    const size_t buckets_size = buckets * sizeof(Bucket*);
    const size_t size = kNumBucketsSize + buckets_size;
    void* allocation = v8::base::AlignedAlloc(size, kSystemPointerSize);
    CHECK(allocation);
    BasicSlotSet* slot_set = reinterpret_cast<BasicSlotSet*>(
        reinterpret_cast<uint8_t*>(allocation) + kNumBucketsSize);
    DCHECK(
        IsAligned(reinterpret_cast<uintptr_t>(slot_set), kSystemPointerSize));
    slot_set->set_num_buckets(buckets);
    for (size_t i = 0; i < buckets; i++) {
      *slot_set->bucket(i) = nullptr;
    }
    return slot_set;
  }

  static void Delete(BasicSlotSet* slot_set) {
    if (slot_set == nullptr) {
      return;
    }

    for (size_t i = 0; i < slot_set->num_buckets(); i++) {
      slot_set->ReleaseBucket(i);
    }
    v8::base::AlignedFree(reinterpret_cast<uint8_t*>(slot_set) -
                          kNumBucketsSize);
  }

  constexpr static size_t BucketsForSize(size_t size) {
    return (size + (SlotGranularity * kBitsPerBucket) - 1) /
           (SlotGranularity * kBitsPerBucket);
  }

  // Converts the slot offset into bucket index.
  constexpr static size_t BucketForSlot(size_t slot_offset) {
    DCHECK(IsAligned(slot_offset, SlotGranularity));
    return slot_offset / (SlotGranularity * kBitsPerBucket);
  }

  // Converts bucket index into slot offset.
  constexpr static size_t OffsetForBucket(size_t bucket_index) {
    return bucket_index * SlotGranularity * kBitsPerBucket;
  }

  // The slot offset specifies a slot at address page_start_ + slot_offset.
  // AccessMode defines whether there can be concurrent access on the buckets
  // or not.
  template <AccessMode access_mode>
  void Insert(size_t slot_offset) {
    size_t bucket_index;
    int cell_index, bit_index;
    SlotToIndices(slot_offset, &bucket_index, &cell_index, &bit_index);
    Bucket* bucket = LoadBucket<access_mode>(bucket_index);
    if (bucket == nullptr) {
      bucket = new Bucket;
      if (!SwapInNewBucket<access_mode>(bucket_index, bucket)) {
        delete bucket;
        bucket = LoadBucket<access_mode>(bucket_index);
      }
    }
    // Check that monotonicity is preserved, i.e., once a bucket is set we do
    // not free it concurrently.
    DCHECK(bucket != nullptr);
    DCHECK_EQ(bucket->cells(), LoadBucket<access_mode>(bucket_index)->cells());
    uint32_t mask = 1u << bit_index;
    if ((bucket->template LoadCell<access_mode>(cell_index) & mask) == 0) {
      bucket->template SetCellBits<access_mode>(cell_index, mask);
    }
  }

  // The slot offset specifies a slot at address page_start_ + slot_offset.
  // Returns true if the set contains the slot.
  bool Contains(size_t slot_offset) {
    size_t bucket_index;
    int cell_index, bit_index;
    SlotToIndices(slot_offset, &bucket_index, &cell_index, &bit_index);
    Bucket* bucket = LoadBucket(bucket_index);
    if (bucket == nullptr) return false;
    return (bucket->LoadCell(cell_index) & (1u << bit_index)) != 0;
  }

  // The slot offset specifies a slot at address page_start_ + slot_offset.
  void Remove(size_t slot_offset) {
    size_t bucket_index;
    int cell_index, bit_index;
    SlotToIndices(slot_offset, &bucket_index, &cell_index, &bit_index);
    Bucket* bucket = LoadBucket(bucket_index);
    if (bucket != nullptr) {
      uint32_t cell = bucket->LoadCell(cell_index);
      uint32_t bit_mask = 1u << bit_index;
      if (cell & bit_mask) {
        bucket->ClearCellBits(cell_index, bit_mask);
      }
    }
  }

  // The slot offsets specify a range of slots at addresses:
  // [page_start_ + start_offset ... page_start_ + end_offset).
  void RemoveRange(size_t start_offset, size_t end_offset, size_t buckets,
                   EmptyBucketMode mode) {
    CHECK_LE(end_offset, buckets * kBitsPerBucket * SlotGranularity);
    DCHECK_LE(start_offset, end_offset);
    size_t start_bucket;
    int start_cell, start_bit;
    SlotToIndices(start_offset, &start_bucket, &start_cell, &start_bit);
    size_t end_bucket;
    int end_cell, end_bit;
    // SlotToIndices() checks that bucket index is within `size`. Since the API
    // allow for an exclusive end interval, we compute  the inclusive index and
    // then increment the bit again (with overflows).
    SlotToIndices(end_offset - SlotGranularity, &end_bucket, &end_cell,
                  &end_bit);
    if (++end_bit >= kBitsPerCell) {
      end_bit = 0;
      if (++end_cell >= kCellsPerBucket) {
        end_cell = 0;
        end_bucket++;
      }
    }
    uint32_t start_mask = (1u << start_bit) - 1;
    uint32_t end_mask = ~((1u << end_bit) - 1);
    Bucket* bucket;
    if (start_bucket == end_bucket && start_cell == end_cell) {
      bucket = LoadBucket(start_bucket);
      if (bucket != nullptr) {
        bucket->ClearCellBits(start_cell, ~(start_mask | end_mask));
      }
      return;
    }
    size_t current_bucket = start_bucket;
    int current_cell = start_cell;
    bucket = LoadBucket(current_bucket);
    if (bucket != nullptr) {
      bucket->ClearCellBits(current_cell, ~start_mask);
    }
    current_cell++;
    if (current_bucket < end_bucket) {
      if (bucket != nullptr) {
        ClearBucket(bucket, current_cell, kCellsPerBucket);
      }
      // The rest of the current bucket is cleared.
      // Move on to the next bucket.
      current_bucket++;
      current_cell = 0;
    }
    DCHECK(current_bucket == end_bucket ||
           (current_bucket < end_bucket && current_cell == 0));
    while (current_bucket < end_bucket) {
      if (mode == FREE_EMPTY_BUCKETS) {
        ReleaseBucket(current_bucket);
      } else {
        DCHECK(mode == KEEP_EMPTY_BUCKETS);
        bucket = LoadBucket(current_bucket);
        if (bucket != nullptr) {
          ClearBucket(bucket, 0, kCellsPerBucket);
        }
      }
      current_bucket++;
    }
    // All buckets between start_bucket and end_bucket are cleared.
    DCHECK(current_bucket == end_bucket);
    if (current_bucket == buckets) return;
    bucket = LoadBucket(current_bucket);
    DCHECK(current_cell <= end_cell);
    if (bucket == nullptr) return;
    while (current_cell < end_cell) {
      bucket->StoreCell(current_cell, 0);
      current_cell++;
    }
    // All cells between start_cell and end_cell are cleared.
    DCHECK(current_bucket == end_bucket && current_cell == end_cell);
    bucket->ClearCellBits(end_cell, ~end_mask);
  }

  // The slot offset specifies a slot at address page_start_ + slot_offset.
  bool Lookup(size_t slot_offset) {
    size_t bucket_index;
    int cell_index, bit_index;
    SlotToIndices(slot_offset, &bucket_index, &cell_index, &bit_index);
    Bucket* bucket = LoadBucket(bucket_index);
    if (bucket == nullptr) return false;
    return (bucket->LoadCell(cell_index) & (1u << bit_index)) != 0;
  }

  // Iterate over all slots in the set and for each slot invoke the callback.
  // If the callback returns REMOVE_SLOT then the slot is removed from the set.
  // Returns the new number of slots.
  //
  // Iteration can be performed concurrently with other operations that use
  // atomic access mode such as insertion and removal. However there is no
  // guarantee about ordering and linearizability.
  //
  // Sample usage:
  // Iterate([](Address slot) {
  //    if (good(slot)) return KEEP_SLOT;
  //    else return REMOVE_SLOT;
  // });
  //
  // Releases memory for empty buckets with FREE_EMPTY_BUCKETS.
  template <AccessMode access_mode = AccessMode::ATOMIC, typename Callback>
  size_t Iterate(Address chunk_start, size_t start_bucket, size_t end_bucket,
                 Callback callback, EmptyBucketMode mode) {
    return Iterate<access_mode>(
        chunk_start, start_bucket, end_bucket, callback,
        [this, mode](size_t bucket_index) {
          if (mode == EmptyBucketMode::FREE_EMPTY_BUCKETS) {
            ReleaseBucket(bucket_index);
          }
        });
  }

  static constexpr int kCellsPerBucket = 32;
  static constexpr int kCellsPerBucketLog2 = 5;
  static constexpr int kCellSizeBytesLog2 = 2;
  static constexpr int kCellSizeBytes = 1 << kCellSizeBytesLog2;
  static constexpr int kBitsPerCell = 32;
  static constexpr int kBitsPerCellLog2 = 5;
  static constexpr int kBitsPerBucket = kCellsPerBucket * kBitsPerCell;
  static constexpr int kBitsPerBucketLog2 =
      kCellsPerBucketLog2 + kBitsPerCellLog2;

  class Bucket final {
   public:
    Bucket() = default;

    uint32_t* cells() { return cells_; }
    const uint32_t* cells() const { return cells_; }
    uint32_t* cell(int cell_index) { return cells_ + cell_index; }
    const uint32_t* cell(int cell_index) const { return cells_ + cell_index; }

    template <AccessMode access_mode = AccessMode::ATOMIC>
    uint32_t LoadCell(int cell_index) {
      DCHECK_LT(cell_index, kCellsPerBucket);
      if constexpr (access_mode == AccessMode::ATOMIC)
        return v8::base::AsAtomic32::Acquire_Load(cell(cell_index));
      return *(cell(cell_index));
    }

    template <AccessMode access_mode = AccessMode::ATOMIC>
    void SetCellBits(int cell_index, uint32_t mask) {
      if constexpr (access_mode == AccessMode::ATOMIC) {
        v8::base::AsAtomic32::SetBits(cell(cell_index), mask, mask);
      } else {
        uint32_t* c = cell(cell_index);
        *c = (*c & ~mask) | mask;
      }
    }

    template <AccessMode access_mode = AccessMode::ATOMIC>
    void ClearCellBits(int cell_index, uint32_t mask) {
      if constexpr (access_mode == AccessMode::ATOMIC) {
        v8::base::AsAtomic32::SetBits(cell(cell_index), 0u, mask);
      } else {
        *cell(cell_index) &= ~mask;
      }
    }

    void StoreCell(int cell_index, uint32_t value) {
      v8::base::AsAtomic32::Release_Store(cell(cell_index), value);
    }

    bool IsEmpty() const {
      for (int i = 0; i < kCellsPerBucket; i++) {
        if (cells_[i] != 0) {
          return false;
        }
      }
      return true;
    }

   private:
    uint32_t cells_[kCellsPerBucket] = {0};
  };

  size_t num_buckets() const {
    return *(reinterpret_cast<const size_t*>(this) - 1);
  }

 protected:
  template <AccessMode access_mode = AccessMode::ATOMIC, typename Callback,
            typename EmptyBucketCallback>
  size_t Iterate(Address chunk_start, size_t start_bucket, size_t end_bucket,
                 Callback callback, EmptyBucketCallback empty_bucket_callback) {
    size_t new_count = 0;
    for (size_t bucket_index = start_bucket; bucket_index < end_bucket;
         bucket_index++) {
      Bucket* bucket = LoadBucket<access_mode>(bucket_index);
      if (bucket != nullptr) {
        size_t in_bucket_count = 0;
        size_t cell_offset = bucket_index << kBitsPerBucketLog2;
        for (int i = 0; i < kCellsPerBucket; i++, cell_offset += kBitsPerCell) {
          uint32_t cell = bucket->template LoadCell<access_mode>(i);
          if (cell) {
            uint32_t old_cell = cell;
            uint32_t mask = 0;
            while (cell) {
              int bit_offset = v8::base::bits::CountTrailingZeros(cell);
              uint32_t bit_mask = 1u << bit_offset;
              Address slot = (cell_offset + bit_offset) * SlotGranularity;
              if (callback(chunk_start + slot) == KEEP_SLOT) {
                ++in_bucket_count;
              } else {
                mask |= bit_mask;
              }
              cell ^= bit_mask;
            }
            uint32_t new_cell = old_cell & ~mask;
            if (old_cell != new_cell) {
              bucket->template ClearCellBits<access_mode>(i, mask);
            }
          }
        }
        if (in_bucket_count == 0) {
          empty_bucket_callback(bucket_index);
        }
        new_count += in_bucket_count;
      }
    }
    return new_count;
  }

  bool FreeBucketIfEmpty(size_t bucket_index) {
    Bucket* bucket = LoadBucket<AccessMode::NON_ATOMIC>(bucket_index);
    if (bucket != nullptr) {
      if (bucket->IsEmpty()) {
        ReleaseBucket<AccessMode::NON_ATOMIC>(bucket_index);
      } else {
        return false;
      }
    }

    return true;
  }

  void ClearBucket(Bucket* bucket, int start_cell, int end_cell) {
    DCHECK_GE(start_cell, 0);
    DCHECK_LE(end_cell, kCellsPerBucket);
    int current_cell = start_cell;
    while (current_cell < kCellsPerBucket) {
      bucket->StoreCell(current_cell, 0);
      current_cell++;
    }
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  void ReleaseBucket(size_t bucket_index) {
    Bucket* bucket = LoadBucket<access_mode>(bucket_index);
    StoreBucket<access_mode>(bucket_index, nullptr);
    delete bucket;
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  Bucket* LoadBucket(Bucket** bucket) {
    if (access_mode == AccessMode::ATOMIC)
      return v8::base::AsAtomicPointer::Acquire_Load(bucket);
    return *bucket;
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  Bucket* LoadBucket(size_t bucket_index) {
    return LoadBucket(bucket(bucket_index));
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  void StoreBucket(Bucket** bucket, Bucket* value) {
    if (access_mode == AccessMode::ATOMIC) {
      v8::base::AsAtomicPointer::Release_Store(bucket, value);
    } else {
      *bucket = value;
    }
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  void StoreBucket(size_t bucket_index, Bucket* value) {
    StoreBucket(bucket(bucket_index), value);
  }

  template <AccessMode access_mode = AccessMode::ATOMIC>
  bool SwapInNewBucket(size_t bucket_index, Bucket* value) {
    Bucket** b = bucket(bucket_index);
    if (access_mode == AccessMode::ATOMIC) {
      return v8::base::AsAtomicPointer::Release_CompareAndSwap(
                 b, nullptr, value) == nullptr;
    } else {
      DCHECK_NULL(*b);
      *b = value;
      return true;
    }
  }

  // Converts the slot offset into bucket/cell/bit index.
  void SlotToIndices(size_t slot_offset, size_t* bucket_index, int* cell_index,
                     int* bit_index) {
    DCHECK(IsAligned(slot_offset, SlotGranularity));
    size_t slot = slot_offset / SlotGranularity;
    *bucket_index = slot >> kBitsPerBucketLog2;
    // No SBXCHECK() in base.
    CHECK(*bucket_index < (num_buckets()));
    *cell_index =
        static_cast<int>((slot >> kBitsPerCellLog2) & (kCellsPerBucket - 1));
    *bit_index = static_cast<int>(slot & (kBitsPerCell - 1));
  }

  Bucket** buckets() { return reinterpret_cast<Bucket**>(this); }
  Bucket** bucket(size_t bucket_index) { return buckets() + bucket_index; }

  void set_num_buckets(size_t num_buckets) {
    *(reinterpret_cast<size_t*>(this) - 1) = num_buckets;
  }

  static constexpr int kNumBucketsSize = sizeof(size_t);

  // For kNumBucketsSize.
  friend class v8::internal::WriteBarrierCodeStubAssembler;
};

}  // namespace base
}  // namespace heap

#endif  // V8_HEAP_BASE_BASIC_SLOT_SET_H_
```