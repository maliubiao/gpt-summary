Response:
Let's break down the thought process for analyzing the `heap-page.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the C++ source code, specifically within the context of V8's cppgc (C++ Garbage Collection). Key aspects include:
    * General purpose of the file.
    * Connection to Torque (if the filename ended in `.tq`).
    * Relationship to JavaScript.
    * Examples of code logic and user errors.

2. **Initial Scan and Keyword Recognition:** Read through the code, paying attention to key terms and structures:
    * `#include`:  Identify dependencies like `heap-object-header.h`, `heap-space.h`, `heap.h`, `page-memory.h`, `remembered-set.h`. These hints suggest the file manages memory pages within the heap.
    * `namespace cppgc::internal`:  This confirms it's an internal part of the cppgc system.
    * Class declarations: `BasePage`, `NormalPage`, `LargePage`. This suggests a hierarchy for managing different types of memory pages.
    * Member functions: `PayloadStart`, `PayloadEnd`, `AllocatedSize`, `TryObjectHeaderFromInnerAddress`, `Destroy`, `TryCreate`. These reveal core functionalities related to memory management within pages.
    * Static member functions: Often used for creation or utility functions.
    * `static_assert`:  Indicates compile-time checks, often related to alignment or size constraints.
    * Conditional compilation: `#if defined(CPPGC_YOUNG_GENERATION)`, `#if defined(V8_USE_MEMORY_SANITIZER)`, etc. These point to different build configurations or features.
    * Comments:  Pay attention to comments like "// static" or explanations of specific logic.

3. **Infer Core Functionality (Based on Keywords and Structure):**  From the initial scan, it becomes clear that `heap-page.cc` is responsible for:
    * Defining the structure and behavior of memory pages within the cppgc heap.
    * Differentiating between normal pages and large pages.
    * Managing the start and end of the usable memory within a page (the "payload").
    * Handling allocation and deallocation of pages.
    * Potentially interacting with object headers within these pages.
    * Supporting a remembered set (based on `remembered-set.h`).

4. **Detailed Analysis of Key Classes:**  Focus on the purpose and methods of each class:
    * **`BasePage`:** The abstract base class, providing common functionality for all page types. It handles looking up pages by address, destruction, and accessing the payload boundaries.
    * **`NormalPage`:** Represents a standard-sized memory page. It includes a bitmap for tracking object starts (`object_start_bitmap_`) and likely uses a linear allocation buffer (LAB) for fast allocation.
    * **`LargePage`:** Represents a page dedicated to a single, large object. It has a simpler structure than `NormalPage`.

5. **Identify Key Operations and Logic:**  Examine the implementations of important functions:
    * **`FromInnerAddress`:**  Crucial for mapping an address to the `BasePage` it belongs to.
    * **`Destroy`:** Handles deallocating pages, taking into account whether it's a `NormalPage` or `LargePage`.
    * **`TryCreate` (for both `NormalPage` and `LargePage`):**  Manages the allocation of memory from the `PageBackend`.
    * **`PayloadStart` and `PayloadEnd`:** Define the boundaries of usable memory within a page.
    * **`TryObjectHeaderFromInnerAddress`:**  Attempts to retrieve the header of an object at a given address within a page, verifying it's not free.

6. **Address the Specific Questions in the Request:**

    * **Functionality Listing:**  Summarize the findings from the detailed analysis.
    * **Torque:**  The request explicitly asks about `.tq`. The filename ends in `.cc`, so it's *not* a Torque file.
    * **JavaScript Relationship:**  Consider how memory management in V8 relates to JavaScript. JavaScript objects reside in the heap. This file is a foundational part of that heap management, even if indirectly. Think about how JavaScript object allocation triggers the underlying cppgc mechanisms.
    * **Code Logic (Hypothetical Input/Output):** Choose a simple, illustrative function like `FromInnerAddress`. Create a scenario where an address falls within a specific page and demonstrate how the function would return that page.
    * **Common Programming Errors:**  Think about how developers might misuse or misunderstand memory management concepts. Dangling pointers and memory leaks are prime examples. Relate these to the concepts in the code (e.g., accessing memory after a page is destroyed).

7. **Refine and Structure the Answer:** Organize the information clearly using headings and bullet points. Provide concise explanations and avoid overly technical jargon where possible. Ensure that all aspects of the original request are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the LAB is only for `NormalPage`. *Correction:* Review the `NormalPage::begin()` implementation. It uses the LAB, confirming its usage for normal pages.
* **Initial thought:** Focus only on the C++ code. *Correction:* Remember the request to connect to JavaScript. While the file is C++, its purpose is to support the JavaScript runtime.
* **Initial thought:** Overcomplicate the hypothetical input/output. *Correction:* Choose a simple example that clearly demonstrates the function's purpose without unnecessary complexity.

By following this structured approach, combining code analysis with an understanding of the overall context of V8 and garbage collection, we can arrive at a comprehensive and accurate answer to the request.
This C++ source code file, `v8/src/heap/cppgc/heap-page.cc`, is a core component of the **cppgc**, V8's C++ garbage collection system. It defines the fundamental structure and behavior of **memory pages** within the heap managed by cppgc. These pages are the basic units of memory allocation for C++ objects managed by this garbage collector.

Here's a breakdown of its key functionalities:

**1. Defines the `BasePage` Class:**

*   `BasePage` serves as an abstract base class for all types of memory pages.
*   It stores common information about a page, such as:
    *   A reference to the `HeapBase` (the overall heap).
    *   A pointer to the `BaseSpace` the page belongs to (a logical grouping of pages).
    *   The `PageType` (e.g., normal or large).
*   It provides static methods for:
    *   `FromInnerAddress`:  Given an address within the heap, this method finds the `BasePage` that contains that address. This is crucial for determining the metadata associated with a memory location.
    *   `Destroy`:  Handles the deallocation of a page, distinguishing between `NormalPage` and `LargePage`.
*   It provides virtual methods for accessing payload information (the actual usable memory within the page):
    *   `PayloadStart`: Returns the starting address of the payload.
    *   `PayloadEnd`: Returns the ending address of the payload.
    *   `AllocatedSize`: Returns the total size allocated for the page.
    *   `AllocatedBytesAtLastGC`:  Returns the allocated bytes at the time of the last garbage collection.
    *   `TryObjectHeaderFromInnerAddress`: Attempts to retrieve the `HeapObjectHeader` for an object at a given address within the page.

**2. Defines the `NormalPage` Class:**

*   `NormalPage` represents a standard-sized memory page used for smaller C++ objects.
*   It inherits from `BasePage`.
*   It contains an `ObjectStartBitmap` to efficiently track the starting addresses of objects within the page.
*   It has a static method `TryCreate` to allocate and initialize a new normal page.
*   It has a static method `Destroy` to deallocate a normal page.
*   It includes methods for iterating through the objects within the page (`begin`, `end`). These iterators likely respect the linear allocation buffer used for faster allocation within normal pages.
*   It defines the `PayloadSize` for normal pages (calculated based on page size and header overhead).

**3. Defines the `LargePage` Class:**

*   `LargePage` represents a memory page dedicated to a single, large C++ object.
*   It inherits from `BasePage`.
*   It directly stores the `payload_size_`.
*   It has static methods `TryCreate` and `Destroy` specifically for large pages, handling their potentially larger allocation sizes.
*   It provides methods to get the `ObjectHeader` of the single object on the page.
*   It has a static method `AllocationSize` to calculate the total memory needed for a large page, including the header.

**In summary, `v8/src/heap/cppgc/heap-page.cc` is responsible for the low-level management of memory pages within cppgc, providing the building blocks for allocating and tracking C++ objects.**

**Is `v8/src/heap/cppgc/heap-page.cc` a Torque source file?**

No, the filename ends with `.cc`, which is the standard extension for C++ source files. If it were a Torque file, it would end with `.tq`.

**Does `v8/src/heap/cppgc/heap-page.cc` have a relationship with JavaScript functionality?**

Yes, indirectly, but fundamentally. While this specific file deals with C++ memory management, it's a crucial part of V8, the JavaScript engine. Here's the connection:

1. **cppgc manages memory for V8's internal C++ objects:** V8 itself is written in C++. Many internal structures and components of the engine (like the garbage collector itself, compilers, interpreters, etc.) are C++ objects managed by cppgc.
2. **JavaScript objects indirectly rely on this:** When JavaScript code creates objects, those objects are eventually represented in memory. While JavaScript objects themselves have their own heap managed by V8's JavaScript garbage collector, the underlying infrastructure for allocating memory for V8's internal structures (which enable JavaScript execution) is provided by cppgc. For example, the structures that manage the JavaScript heap might reside in memory pages allocated by the mechanisms defined in this file.

**Example illustrating the indirect relationship (Conceptual JavaScript analogy):**

Imagine you're building a house (your JavaScript application). You need tools and materials (V8's internal C++ objects) to build it. `heap-page.cc` is like the factory that produces the containers (memory pages) to store those tools and materials efficiently. You don't directly interact with the factory when building your house, but it's essential for providing the resources you need.

```javascript
// In JavaScript, you might create objects like this:
let myObject = { name: "Example", value: 42 };
let myArray = [1, 2, 3];

// Behind the scenes, V8 needs to allocate memory for its internal
// representations of these objects and the structures that manage them.
// cppgc, and specifically the concepts in heap-page.cc, are part of
// the system that makes this memory allocation possible for V8's C++ parts.
```

**Code Logic Inference (Hypothetical Input and Output):**

Let's focus on the `BasePage::FromInnerAddress` function.

**Assumption:** We have a `Heap` instance and a memory address that falls within a managed heap page.

**Input:**

*   `heap`: A pointer to a `HeapBase` object.
*   `address`: A `void*` pointing to an address `0x7fff12345678`.

**Scenario:** Let's assume that the `Heap` instance has a `NormalPage` allocated, starting at address `0x7fff12345000` and ending at `0x7fff12346000`. The input `address` `0x7fff12345678` lies within this page's range.

**Logic of `BasePage::FromInnerAddress`:**

The function would likely iterate through the managed memory pages or use a data structure (like a tree or a sorted list) within the `heap->page_backend()` to quickly find the page whose address range contains the input `address`.

**Output:**

The function would return a pointer to the `BasePage` object representing the `NormalPage` that starts at `0x7fff12345000`.

**Hypothetical Code Snippet demonstrating the usage (within V8's internals):**

```c++
// Hypothetical scenario within V8's C++ code
Heap* the_heap = GetCurrentHeap(); // Assume a function to get the current heap
void* some_memory_address = reinterpret_cast<void*>(0x7fff12345678);

const BasePage* page = BasePage::FromInnerAddress(the_heap, some_memory_address);

if (page) {
  // We found the page containing the address
  std::cout << "Address belongs to a page starting at: " << page << std::endl;
} else {
  std::cout << "Address does not belong to a managed page." << std::endl;
}
```

**Common Programming Errors Related to These Concepts:**

While developers usually don't directly interact with `heap-page.cc`, understanding its concepts can help avoid certain errors when working with C++ and memory management in general:

1. **Dangling Pointers:**  A classic error occurs when a pointer points to memory that has been deallocated. If a developer holds a raw pointer to an object on a heap page and that page is deallocated (e.g., during garbage collection), the pointer becomes invalid. Accessing this pointer leads to undefined behavior.

    ```c++
    // C++ Example (illustrative, not directly using heap-page classes in user code)
    class MyObject {
    public:
        int value;
    };

    void someFunction() {
        MyObject* obj = new MyObject();
        obj->value = 10;
        MyObject* dangling_ptr = obj; // Copy the pointer
        delete obj; // Memory is deallocated

        // Error: Accessing dangling_ptr
        std::cout << dangling_ptr->value << std::endl; // Undefined behavior
    }
    ```

    **Connection to `heap-page.cc`:** The `Destroy` methods in `heap-page.cc` are responsible for releasing the memory of the pages. If external code retains pointers to objects on these pages after they are destroyed, those pointers become dangling.

2. **Memory Leaks:** If memory pages are allocated but never properly deallocated, it leads to memory leaks. This can happen if the `Destroy` methods are not called appropriately when objects or data structures are no longer needed.

    ```c++
    // C++ Example (illustrative)
    void anotherFunction() {
        int* data = new int[100];
        // ... data is used ...
        // Forget to delete[] data; // Memory leak!
    }
    ```

    **Connection to `heap-page.cc`:** While cppgc handles garbage collection automatically for managed objects, if there are resources or memory allocated outside of the managed heap (which is less common with cppgc but can happen in complex systems), forgetting to release them can lead to leaks. The `TryCreate` methods in `heap-page.cc` allocate memory, and the `Destroy` methods are crucial for preventing leaks of these pages.

3. **Accessing Memory Outside of Bounds:** While less directly related to the page structure itself, understanding how memory is organized in pages can help visualize potential out-of-bounds access errors. If a pointer incorrectly calculates an offset and tries to access memory beyond the allocated size of an object within a page, it can lead to crashes or data corruption.

**In conclusion, `v8/src/heap/cppgc/heap-page.cc` is a fundamental file in V8's cppgc, defining the structure and management of memory pages. While developers don't directly use these classes in typical application code, understanding their role provides insight into the underlying memory management mechanisms that power the JavaScript engine.**

Prompt: 
```
这是目录为v8/src/heap/cppgc/heap-page.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/heap-page.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/heap-page.h"

#include <algorithm>
#include <cstddef>

#include "include/cppgc/internal/api-constants.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-space.h"
#include "src/heap/cppgc/heap.h"
#include "src/heap/cppgc/memory.h"
#include "src/heap/cppgc/object-start-bitmap.h"
#include "src/heap/cppgc/page-memory.h"
#include "src/heap/cppgc/raw-heap.h"
#include "src/heap/cppgc/remembered-set.h"
#include "src/heap/cppgc/stats-collector.h"

namespace cppgc {
namespace internal {

static_assert(api_constants::kGuardPageSize == kGuardPageSize);

namespace {

Address AlignAddress(Address address, size_t alignment) {
  return reinterpret_cast<Address>(
      RoundUp(reinterpret_cast<uintptr_t>(address), alignment));
}

}  // namespace

HeapBase& BasePage::heap() const {
  return static_cast<HeapBase&>(heap_handle_);
}

// static
BasePage* BasePage::FromInnerAddress(const HeapBase* heap, void* address) {
  return const_cast<BasePage*>(
      FromInnerAddress(heap, const_cast<const void*>(address)));
}

// static
const BasePage* BasePage::FromInnerAddress(const HeapBase* heap,
                                           const void* address) {
  return reinterpret_cast<const BasePage*>(
      heap->page_backend()->Lookup(static_cast<ConstAddress>(address)));
}

// static
void BasePage::Destroy(BasePage* page,
                       FreeMemoryHandling free_memory_handling) {
  if (page->discarded_memory()) {
    page->space()
        .raw_heap()
        ->heap()
        ->stats_collector()
        ->DecrementDiscardedMemory(page->discarded_memory());
  }
  if (page->is_large()) {
    LargePage::Destroy(LargePage::From(page));
  } else {
    NormalPage::Destroy(NormalPage::From(page), free_memory_handling);
  }
}

Address BasePage::PayloadStart() {
  return is_large() ? LargePage::From(this)->PayloadStart()
                    : NormalPage::From(this)->PayloadStart();
}

ConstAddress BasePage::PayloadStart() const {
  return const_cast<BasePage*>(this)->PayloadStart();
}

Address BasePage::PayloadEnd() {
  return is_large() ? LargePage::From(this)->PayloadEnd()
                    : NormalPage::From(this)->PayloadEnd();
}

ConstAddress BasePage::PayloadEnd() const {
  return const_cast<BasePage*>(this)->PayloadEnd();
}

size_t BasePage::AllocatedSize() const {
  return is_large() ? LargePage::PageHeaderSize() +
                          LargePage::From(this)->PayloadSize()
                    : NormalPage::From(this)->PayloadSize() +
                          RoundUp(sizeof(NormalPage), kAllocationGranularity);
}

size_t BasePage::AllocatedBytesAtLastGC() const {
  return is_large() ? LargePage::From(this)->AllocatedBytesAtLastGC()
                    : NormalPage::From(this)->AllocatedBytesAtLastGC();
}

HeapObjectHeader* BasePage::TryObjectHeaderFromInnerAddress(
    void* address) const {
  return const_cast<HeapObjectHeader*>(
      TryObjectHeaderFromInnerAddress(const_cast<const void*>(address)));
}

const HeapObjectHeader* BasePage::TryObjectHeaderFromInnerAddress(
    const void* address) const {
  if (is_large()) {
    if (!LargePage::From(this)->PayloadContains(
            static_cast<ConstAddress>(address)))
      return nullptr;
  } else {
    const NormalPage* normal_page = NormalPage::From(this);
    if (!normal_page->PayloadContains(static_cast<ConstAddress>(address)))
      return nullptr;
    // Check that the space has no linear allocation buffer.
    DCHECK(!NormalPageSpace::From(normal_page->space())
                .linear_allocation_buffer()
                .size());
  }

  // |address| is on the heap, so we FromInnerAddress can get the header.
  const HeapObjectHeader* header =
      ObjectHeaderFromInnerAddressImpl(this, address);
  if (header->IsFree()) return nullptr;
  DCHECK_NE(kFreeListGCInfoIndex, header->GetGCInfoIndex());
  return header;
}

#if defined(CPPGC_YOUNG_GENERATION)
void BasePage::AllocateSlotSet() {
  DCHECK_NULL(slot_set_);
  slot_set_ = decltype(slot_set_)(
      static_cast<SlotSet*>(
          SlotSet::Allocate(SlotSet::BucketsForSize(AllocatedSize()))),
      SlotSetDeleter{AllocatedSize()});
}

void BasePage::SlotSetDeleter::operator()(SlotSet* slot_set) const {
  DCHECK_NOT_NULL(slot_set);
  SlotSet::Delete(slot_set);
}

void BasePage::ResetSlotSet() { slot_set_.reset(); }
#endif  // defined(CPPGC_YOUNG_GENERATION)

BasePage::BasePage(HeapBase& heap, BaseSpace& space, PageType type)
    : BasePageHandle(heap),
      space_(&space),
      type_(type)
#if defined(CPPGC_YOUNG_GENERATION)
      ,
      slot_set_(nullptr, SlotSetDeleter{})
#endif  // defined(CPPGC_YOUNG_GENERATION)
{
  DCHECK_EQ(0u, (reinterpret_cast<uintptr_t>(this) - kGuardPageSize) &
                    kPageOffsetMask);
  DCHECK_EQ(&heap.raw_heap(), space_->raw_heap());
}

void BasePage::ChangeOwner(BaseSpace& space) {
  DCHECK_EQ(space_->raw_heap(), space.raw_heap());
  space_ = &space;
}

// static
NormalPage* NormalPage::TryCreate(PageBackend& page_backend,
                                  NormalPageSpace& space) {
  void* memory = page_backend.TryAllocateNormalPageMemory();
  if (!memory) return nullptr;

  auto* normal_page = new (memory) NormalPage(*space.raw_heap()->heap(), space);
  normal_page->SynchronizedStore();
  normal_page->heap().stats_collector()->NotifyAllocatedMemory(kPageSize);
  // Memory is zero initialized as
  // a) memory retrieved from the OS is zeroed;
  // b) memory retrieved from the page pool was swept and thus is zeroed except
  //    for the first header which will anyways serve as header again.
  //
  // The following is a subset of SetMemoryInaccessible() to establish the
  // invariant that memory is in the same state as it would be after sweeping.
  // This allows to return newly allocated pages to go into that LAB and back
  // into the free list.
  Address begin = normal_page->PayloadStart() + sizeof(HeapObjectHeader);
  const size_t size = normal_page->PayloadSize() - sizeof(HeapObjectHeader);
#if defined(V8_USE_MEMORY_SANITIZER)
  MSAN_ALLOCATED_UNINITIALIZED_MEMORY(begin, size);
#elif defined(V8_USE_ADDRESS_SANITIZER)
  ASAN_POISON_MEMORY_REGION(begin, size);
#elif DEBUG
  cppgc::internal::ZapMemory(begin, size);
#endif  // Release builds.
  CheckMemoryIsInaccessible(begin, size);
  return normal_page;
}

// static
void NormalPage::Destroy(NormalPage* page,
                         FreeMemoryHandling free_memory_handling) {
  DCHECK(page);
  HeapBase& heap = page->heap();
  const BaseSpace& space = page->space();
  DCHECK_EQ(space.end(), std::find(space.begin(), space.end(), page));
  USE(space);
  page->~NormalPage();
  PageBackend* backend = heap.page_backend();
  heap.stats_collector()->NotifyFreedMemory(kPageSize);
  backend->FreeNormalPageMemory(reinterpret_cast<Address>(page),
                                free_memory_handling);
}

NormalPage::NormalPage(HeapBase& heap, BaseSpace& space)
    : BasePage(heap, space, PageType::kNormal), object_start_bitmap_() {
  DCHECK_LT(kLargeObjectSizeThreshold,
            static_cast<size_t>(PayloadEnd() - PayloadStart()));
}

NormalPage::iterator NormalPage::begin() {
  const auto& lab = NormalPageSpace::From(space()).linear_allocation_buffer();
  return iterator(reinterpret_cast<HeapObjectHeader*>(PayloadStart()),
                  lab.start(), lab.size());
}

NormalPage::const_iterator NormalPage::begin() const {
  const auto& lab = NormalPageSpace::From(space()).linear_allocation_buffer();
  return const_iterator(
      reinterpret_cast<const HeapObjectHeader*>(PayloadStart()), lab.start(),
      lab.size());
}

Address NormalPage::PayloadStart() {
  return AlignAddress((reinterpret_cast<Address>(this + 1)),
                      kAllocationGranularity);
}

ConstAddress NormalPage::PayloadStart() const {
  return const_cast<NormalPage*>(this)->PayloadStart();
}

Address NormalPage::PayloadEnd() { return PayloadStart() + PayloadSize(); }

ConstAddress NormalPage::PayloadEnd() const {
  return const_cast<NormalPage*>(this)->PayloadEnd();
}

// static
size_t NormalPage::PayloadSize() {
  const size_t header_size =
      RoundUp(sizeof(NormalPage), kAllocationGranularity);
  return kPageSize - 2 * kGuardPageSize - header_size;
}

LargePage::LargePage(HeapBase& heap, BaseSpace& space, size_t size)
    : BasePage(heap, space, PageType::kLarge), payload_size_(size) {}

// static
size_t LargePage::AllocationSize(size_t payload_size) {
  return PageHeaderSize() + payload_size;
}

// static
LargePage* LargePage::TryCreate(PageBackend& page_backend,
                                LargePageSpace& space, size_t size) {
  // Ensure that the API-provided alignment guarantees does not violate the
  // internally guaranteed alignment of large page allocations.
  static_assert(kGuaranteedObjectAlignment <=
                api_constants::kMaxSupportedAlignment);
  static_assert(
      api_constants::kMaxSupportedAlignment % kGuaranteedObjectAlignment == 0);

  DCHECK_LE(kLargeObjectSizeThreshold, size);
  const size_t allocation_size = AllocationSize(size);

  auto* heap = space.raw_heap()->heap();
  void* memory = page_backend.TryAllocateLargePageMemory(allocation_size);
  if (!memory) return nullptr;

  LargePage* page = new (memory) LargePage(*heap, space, size);
  page->SynchronizedStore();
  page->heap().stats_collector()->NotifyAllocatedMemory(allocation_size);
  return page;
}

// static
void LargePage::Destroy(LargePage* page) {
  DCHECK(page);
  HeapBase& heap = page->heap();
  const size_t payload_size = page->PayloadSize();
#if DEBUG
  const BaseSpace& space = page->space();
  {
    // Destroy() happens on the mutator but another concurrent sweeper task may
    // add add a live object using `BaseSpace::AddPage()` while iterating the
    // pages.
    v8::base::LockGuard<v8::base::Mutex> guard(&space.pages_mutex());
    DCHECK_EQ(space.end(), std::find(space.begin(), space.end(), page));
  }
#endif  // DEBUG
  page->~LargePage();
  PageBackend* backend = heap.page_backend();
  heap.stats_collector()->NotifyFreedMemory(AllocationSize(payload_size));
  backend->FreeLargePageMemory(reinterpret_cast<Address>(page));
}

HeapObjectHeader* LargePage::ObjectHeader() {
  return reinterpret_cast<HeapObjectHeader*>(PayloadStart());
}

const HeapObjectHeader* LargePage::ObjectHeader() const {
  return reinterpret_cast<const HeapObjectHeader*>(PayloadStart());
}

Address LargePage::PayloadStart() {
  return reinterpret_cast<Address>(this) + PageHeaderSize();
}

ConstAddress LargePage::PayloadStart() const {
  return const_cast<LargePage*>(this)->PayloadStart();
}

Address LargePage::PayloadEnd() { return PayloadStart() + PayloadSize(); }

ConstAddress LargePage::PayloadEnd() const {
  return const_cast<LargePage*>(this)->PayloadEnd();
}

}  // namespace internal
}  // namespace cppgc

"""

```