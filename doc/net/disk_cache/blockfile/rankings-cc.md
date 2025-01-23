Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `net/disk_cache/blockfile/rankings.cc` and its potential relationship to JavaScript, along with debugging and error scenarios.

**2. Initial Code Scan and Keyword Identification:**

I'd start by skimming the code, looking for key classes, functions, and data structures. Keywords that immediately jump out are:

* `Rankings` (the main class)
* `CacheRankingsBlock` (likely represents a node in the rankings)
* `LruData` (suggests Least Recently Used logic)
* `Insert`, `Remove`, `UpdateRank` (core LRU operations)
* `heads_`, `tails_` (likely pointers to the beginning and end of lists)
* `Transaction` (implies handling of potentially interrupted operations)
* `CrashLocation`, `GenerateCrash` (related to testing and recovery)
* `UpdateTimes` (timestamp management)
* `Iterator` (for traversing the rankings)
* `SelfCheck`, `SanityCheck` (diagnostic functions)
* `control_data_` (likely persistent data for the rankings)
* `backend_` (interaction with the underlying cache storage)

**3. Deciphering the Core Functionality (LRU and Persistence):**

Based on the keywords and structure, I can deduce that `rankings.cc` implements an LRU (Least Recently Used) eviction policy for the disk cache. The code manages doubly-linked lists of `CacheRankingsBlock` objects. Key operations involve moving entries within these lists to maintain the LRU order.

The `Transaction` class strongly suggests a mechanism for ensuring data integrity even if the program crashes in the middle of an operation (like inserting or removing an item from the LRU list). The `LruData` structure likely stores the persistent state of the LRU lists (heads, tails, and potentially transaction information).

**4. Analyzing Key Functions:**

* **`Insert()`:** Adds a node to the beginning of the specified list. The `Transaction` ensures recovery if a crash occurs during insertion.
* **`Remove()`:** Removes a node from the specified list, also using `Transaction` for crash recovery. It handles cases like removing the head or tail of the list.
* **`UpdateRank()`:** Moves a node to the front of the list, effectively marking it as recently used. It achieves this by removing and then re-inserting the node.
* **`GetNext()` and `GetPrev()`:**  Provide ways to iterate through the linked lists.
* **`SelfCheck()` and `SanityCheck()`:** Crucial for debugging and validating the integrity of the LRU lists. They detect inconsistencies in the linked list structure.
* **`CompleteTransaction()`:**  The heart of the crash recovery mechanism. It examines the `LruData` to see if an operation was interrupted and completes or reverts it.

**5. Considering the JavaScript Relationship (or Lack Thereof):**

While this C++ code is part of the Chromium network stack, it operates at a lower level than JavaScript. JavaScript running in a browser interacts with the network stack through higher-level APIs. The disk cache is a detail that JavaScript is generally unaware of. Therefore, the relationship is indirect. JavaScript's network requests *might* lead to data being cached, which then involves this LRU management. The example of a user browsing a website is a good illustration of this indirect interaction.

**6. Constructing Logic Examples (Hypothetical Input/Output):**

For demonstrating the logic, I focus on the core operations:

* **Insertion:**  Start with an empty list and insert a node. Show how the head and tail pointers are updated.
* **Removal:**  Remove the head, a middle element, and the tail to cover different scenarios. Illustrate how the links are adjusted.
* **UpdateRank:** Show how moving an element to the front changes the list order.

**7. Identifying User/Programming Errors:**

The code itself provides hints through `DCHECK` statements and error handling. Common errors would involve:

* **Data corruption:**  External factors corrupting the cache files.
* **Concurrency issues (though less visible in this single file):** If multiple threads tried to modify the rankings without proper synchronization (though `Transaction` helps here).
* **Incorrect backend implementation:** Issues in how the `BackendImpl` interacts with the rankings.

**8. Tracing User Actions to the Code (Debugging Context):**

To connect user actions to this code, I consider the chain of events:

1. **User action:**  Typing a URL, clicking a link, etc.
2. **Browser request:** The browser's network stack initiates a request.
3. **Cache check:** The network stack checks the disk cache for the resource.
4. **`rankings.cc` involvement:** If the resource is in the cache, this code might be used to update its last used time (`UpdateRank`). If space is needed, it's used to evict old entries (`Remove`).
5. **Debugging clues:** Knowing the user's actions helps narrow down the timeline and the types of cache operations that might be involved in a bug.

**9. Refining and Organizing the Answer:**

Finally, I organize the information into clear sections based on the prompt's requirements: functionality, JavaScript relation, logic examples, errors, and debugging. I use clear language and provide concrete examples to make the explanation understandable. I also ensure that the level of detail is appropriate for the request. For instance, I don't delve into the low-level details of file I/O unless it's directly relevant to the functionality being explained.
This C++ source file, `net/disk_cache/blockfile/rankings.cc`, within the Chromium project's network stack, implements the **ranking and eviction logic for the blockfile-based disk cache**. Think of it as the system that decides which cached items to keep and which to discard when the cache is full or needs to make space. It uses a **Least Recently Used (LRU)** algorithm, along with considerations for modification time, to manage cached data.

Here's a breakdown of its key functionalities:

**Core Functionality:**

1. **Maintaining LRU Lists:**
    *   It manages several doubly-linked lists of `CacheRankingsBlock` objects. Each list represents a different category or priority for cached items (though the specific categories aren't explicitly defined in this snippet).
    *   The `heads_` and `tails_` arrays store the starting and ending points of these lists.
    *   Nodes in these lists are ordered based on their last access time (and potentially modification time). The most recently used items are at the front, and the least recently used are at the back.

2. **Inserting New Entries:**
    *   The `Insert()` function adds a `CacheRankingsBlock` (representing a cached entry) to the front of a specified LRU list. This happens when a new item is cached.
    *   It updates the `heads_` pointer and the `next` and `prev` pointers of the involved nodes.

3. **Removing Entries (Eviction):**
    *   The `Remove()` function removes a `CacheRankingsBlock` from its LRU list. This is the core of the eviction process.
    *   It updates the `tails_` pointer (when removing the last item) and the `next` and `prev` pointers of the neighboring nodes.

4. **Updating Entry Rank (Moving to Front):**
    *   The `UpdateRank()` function moves a `CacheRankingsBlock` to the front of its LRU list. This is done when a cached item is accessed, signifying its recent use.
    *   It essentially removes the node from its current position and then re-inserts it at the head of the list.

5. **Tracking Last Used and Modified Times:**
    *   The `UpdateTimes()` function updates the `last_used` and `last_modified` timestamps within a `CacheRankingsBlock`. These timestamps are crucial for the LRU algorithm.

6. **Crash Recovery (Transactions):**
    *   The `Transaction` class and related logic are designed to handle crashes during list manipulation.
    *   Before modifying the LRU lists, a `Transaction` object is created, recording the operation and the involved node. This information is stored in the `LruData`.
    *   If a crash occurs, the `CompleteTransaction()` function is called during initialization to either finish or revert the interrupted operation, ensuring data consistency.

7. **Iterating Through Lists:**
    *   The `Iterator` class provides a way to traverse the LRU lists.
    *   `GetNext()` and `GetPrev()` functions allow moving forward and backward through a list.

8. **Self-Checking and Sanity Checks:**
    *   `SelfCheck()` performs a comprehensive check of the integrity of the LRU lists, verifying the correctness of the links between nodes.
    *   `SanityCheck()` performs checks on individual `CacheRankingsBlock` objects to ensure their internal consistency.

**Relationship to JavaScript Functionality:**

This C++ code has **no direct functional relationship with JavaScript**. JavaScript running in a web browser interacts with the network stack through higher-level APIs. JavaScript is generally unaware of the low-level details of the disk cache's eviction policy.

**However, there's an *indirect* relationship:**

*   When a user browses a website or a web application, JavaScript code might trigger network requests (e.g., fetching images, scripts, stylesheets, API data).
*   The Chromium network stack (where this C++ code resides) handles these requests.
*   If caching is enabled, the network stack might store the fetched resources in the disk cache.
*   This `rankings.cc` code is responsible for managing the entries in that disk cache, deciding which items to keep based on their usage patterns.

**Example of Indirect Relationship:**

1. **User Action (JavaScript):** A user visits a webpage with many images. The JavaScript code on the page initiates requests for these images.
2. **Network Request:** The browser's network stack fetches the images.
3. **Caching:** The network stack decides to cache some or all of these images on disk.
4. **`rankings.cc` Involvement:**
    *   When a new image is cached, `Insert()` is called to add its corresponding `CacheRankingsBlock` to an LRU list.
    *   If the cache is full and a new image needs to be stored, `Remove()` might be called to evict the least recently used image based on the order maintained by the LRU lists.
    *   When the user revisits the same webpage, and an image is retrieved from the cache, `UpdateRank()` might be called to move the corresponding `CacheRankingsBlock` to the front of the LRU list.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `Insert()` function:

**Hypothetical Input:**

*   `node`: A `CacheRankingsBlock` representing a newly cached image file (let's say `image.png`).
*   `modified`: `true` (assuming the file was just downloaded).
*   `list`: `DEFAULT` (assuming this is the default LRU list for images).
*   Assume the `DEFAULT` list is currently empty (both `heads_[DEFAULT]` and `tails_[DEFAULT]` are 0).

**Processing:**

1. A `Transaction` object is created.
2. Since the list is empty (`my_head` is not initialized), `head.is_initialized()` is false.
3. `node->Data()->next` is set to 0 (the current head).
4. `node->Data()->prev` is set to `node->address().value()` (itself, as it's the only node).
5. `my_head` is set to `node->address().value()`.
6. Since `my_tail` is not initialized, it's also set to `node->address().value()`.
7. `node->Data()->next` is set to `my_tail.value()` (which is the same as `node->address().value()`).
8. `WriteTail(list)` is called to update the persistent tail pointer.
9. `UpdateTimes()` is called to set the `last_used` and `last_modified` timestamps.
10. `node->Store()` is called to write the updated `CacheRankingsBlock` to disk.
11. `WriteHead(list)` is called to update the persistent head pointer.
12. `IncrementCounter(list)` is called to update the list size.
13. `backend_->FlushIndex()` is called to ensure the index is written to disk.

**Hypothetical Output (State of the LRU list after insertion):**

*   `heads_[DEFAULT]` will point to the address of the `image.png` node.
*   `tails_[DEFAULT]` will point to the address of the `image.png` node.
*   The `CacheRankingsBlock` for `image.png` will have:
    *   `next`: its own address.
    *   `prev`: its own address.
    *   `last_used`: the current time.
    *   `last_modified`: the current time.
*   The persistent state of the cache will be updated to reflect these changes.

**User or Programming Common Usage Errors:**

1. **Data Corruption:** If the underlying storage for the cache gets corrupted (e.g., due to disk errors or unexpected shutdowns without proper flushing), the linked list structure can become invalid. The `SelfCheck()` function is designed to detect such issues, and the `SanityCheck()` helps identify problems with individual nodes.

    **Example:** A sudden power outage while the cache is writing data could leave the `heads_`, `tails_`, or node pointers in an inconsistent state.

2. **Incorrect Backend Implementation:** If the `BackendImpl` (which interacts with the file system) doesn't correctly manage the allocation and deallocation of blocks, it could lead to dangling pointers or memory corruption that affects the rankings.

    **Example:** If `BackendImpl` returns an invalid address for a `CacheRankingsBlock`, the `Rankings` class might try to access memory that doesn't belong to it, leading to crashes or undefined behavior.

3. **Concurrency Issues (Less likely in this specific file but possible in the broader cache implementation):** While the `Transaction` class helps with crash consistency, if multiple threads try to modify the LRU lists concurrently without proper locking mechanisms, it can lead to race conditions and corrupted list structures.

    **Example:** Two threads might try to insert different entries into the same LRU list at almost the same time. Without proper synchronization, the `heads_` pointer might be updated incorrectly, leading to lost or incorrectly linked nodes.

**User Operation Steps to Reach This Code (Debugging Clues):**

To debug issues within `rankings.cc`, you would typically investigate scenarios involving cache behavior. Here's how user actions can lead to this code being executed:

1. **First Visit to a Website/Resource:**
    *   User types a URL or clicks a link leading to a new resource (image, script, etc.).
    *   The browser's network stack fetches this resource.
    *   The caching mechanism decides to store this resource in the disk cache.
    *   This triggers the `Insert()` function in `rankings.cc` to add the new entry to an LRU list.

2. **Subsequent Visits to the Same Website/Resource:**
    *   User revisits the same page or requests the same resource.
    *   The browser's network stack checks the disk cache.
    *   If the resource is found in the cache:
        *   `UpdateRank()` in `rankings.cc` might be called to move the entry to the front of the LRU list, indicating recent use.
        *   If the resource's modification time has changed, the cache might need to revalidate or update the cached entry, potentially involving `Remove()` and `Insert()`.

3. **Cache Full/Eviction:**
    *   User continues browsing, and the disk cache reaches its capacity.
    *   When a new resource needs to be cached, the caching mechanism needs to make space.
    *   This triggers the `Remove()` function in `rankings.cc` to evict the least recently used entries from the LRU lists.

4. **Browser Shutdown/Crash:**
    *   User closes the browser or the browser crashes unexpectedly.
    *   During the next startup, the cache might try to recover from any incomplete operations by calling `CompleteTransaction()`, which reads the transaction data and attempts to finalize or revert the operation.

**Debugging Steps (Based on User Actions):**

*   **If the user reports slow loading or missing cached resources after revisiting a website:** This could indicate issues with the LRU logic. You might set breakpoints in `UpdateRank()`, `GetNext()`, and `GetPrev()` to see how the entries are being managed and if the correct entries are being retrieved.
*   **If the user experiences crashes or data corruption related to the cache:** This might point to problems in `Insert()`, `Remove()`, or the crash recovery mechanism (`CompleteTransaction()`). You'd investigate the transaction data and the state of the LRU lists before and after potential crash points (using the `GenerateCrash()` mechanism for testing).
*   **If the user reports the cache not evicting old resources properly:** You would focus on `Remove()` and the logic within `CheckList()` and related sanity checks to ensure the LRU lists are correctly ordered and that the eviction process is working as expected.

By understanding how user actions trigger network requests and caching operations, you can trace the execution flow into `rankings.cc` and use debugging tools to inspect the state of the LRU lists, node pointers, and timestamps to diagnose issues related to the disk cache's ranking and eviction mechanisms.

### 提示词
```
这是目录为net/disk_cache/blockfile/rankings.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/blockfile/rankings.h"

#include <stdint.h>

#include <limits>
#include <memory>

#include "base/memory/raw_ptr.h"
#include "base/process/process.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/net_export.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/disk_format.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/errors.h"
#include "net/disk_cache/blockfile/stress_support.h"

#if BUILDFLAG(IS_WIN)
#include <windows.h>
#endif

using base::Time;
using base::TimeTicks;

namespace disk_cache {
// This is used by crash_cache.exe to generate unit test files.
NET_EXPORT_PRIVATE RankCrashes g_rankings_crash = NO_CRASH;
}

namespace {

enum Operation {
  INSERT = 1,
  REMOVE
};

// This class provides a simple lock for the LRU list of rankings. Whenever an
// entry is to be inserted or removed from the list, a transaction object should
// be created to keep track of the operation. If the process crashes before
// finishing the operation, the transaction record (stored as part of the user
// data on the file header) can be used to finish the operation.
class Transaction {
 public:
  // addr is the cache address of the node being inserted or removed. We want to
  // avoid having the compiler doing optimizations on when to read or write
  // from user_data because it is the basis of the crash detection. Maybe
  // volatile is not enough for that, but it should be a good hint.
  Transaction(volatile disk_cache::LruData* data, disk_cache::Addr addr,
              Operation op, int list);

  Transaction(const Transaction&) = delete;
  Transaction& operator=(const Transaction&) = delete;

  ~Transaction();
 private:
  raw_ptr<volatile disk_cache::LruData> data_;
};

Transaction::Transaction(volatile disk_cache::LruData* data,
                         disk_cache::Addr addr, Operation op, int list)
    : data_(data) {
  DCHECK(!data_->transaction);
  DCHECK(addr.is_initialized());
  data_->operation = op;
  data_->operation_list = list;
  data_->transaction = addr.value();
}

Transaction::~Transaction() {
  DCHECK(data_->transaction);
  data_->transaction = 0;
  data_->operation = 0;
  data_->operation_list = 0;
}

// Code locations that can generate crashes.
enum CrashLocation {
  ON_INSERT_1, ON_INSERT_2, ON_INSERT_3, ON_INSERT_4, ON_REMOVE_1, ON_REMOVE_2,
  ON_REMOVE_3, ON_REMOVE_4, ON_REMOVE_5, ON_REMOVE_6, ON_REMOVE_7, ON_REMOVE_8
};

// Simulates a crash (by exiting the process without graceful shutdown) on debug
// builds, according to the value of g_rankings_crash. This used by
// crash_cache.exe to generate unit-test files.
void GenerateCrash(CrashLocation location) {
#if !defined(NDEBUG) && !BUILDFLAG(IS_IOS)
  if (disk_cache::NO_CRASH == disk_cache::g_rankings_crash)
    return;
  switch (location) {
    case ON_INSERT_1:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::INSERT_ONE_1:
        case disk_cache::INSERT_LOAD_1:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    case ON_INSERT_2:
      if (disk_cache::INSERT_EMPTY_1 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_INSERT_3:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::INSERT_EMPTY_2:
        case disk_cache::INSERT_ONE_2:
        case disk_cache::INSERT_LOAD_2:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    case ON_INSERT_4:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::INSERT_EMPTY_3:
        case disk_cache::INSERT_ONE_3:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    case ON_REMOVE_1:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::REMOVE_ONE_1:
        case disk_cache::REMOVE_HEAD_1:
        case disk_cache::REMOVE_TAIL_1:
        case disk_cache::REMOVE_LOAD_1:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    case ON_REMOVE_2:
      if (disk_cache::REMOVE_ONE_2 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_REMOVE_3:
      if (disk_cache::REMOVE_ONE_3 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_REMOVE_4:
      if (disk_cache::REMOVE_HEAD_2 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_REMOVE_5:
      if (disk_cache::REMOVE_TAIL_2 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_REMOVE_6:
      if (disk_cache::REMOVE_TAIL_3 == disk_cache::g_rankings_crash)
        base::Process::TerminateCurrentProcessImmediately(0);
      break;
    case ON_REMOVE_7:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::REMOVE_ONE_4:
        case disk_cache::REMOVE_LOAD_2:
        case disk_cache::REMOVE_HEAD_3:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    case ON_REMOVE_8:
      switch (disk_cache::g_rankings_crash) {
        case disk_cache::REMOVE_HEAD_4:
        case disk_cache::REMOVE_LOAD_3:
          base::Process::TerminateCurrentProcessImmediately(0);
        default:
          break;
      }
      break;
    default:
      NOTREACHED();
  }
#endif  // NDEBUG
}

// Update the timestamp fields of |node|.
void UpdateTimes(disk_cache::CacheRankingsBlock* node, bool modified) {
  base::Time now = base::Time::Now();
  node->Data()->last_used = now.ToInternalValue();
  if (modified)
    node->Data()->last_modified = now.ToInternalValue();
}

}  // namespace

namespace disk_cache {

Rankings::ScopedRankingsBlock::ScopedRankingsBlock() : rankings_(nullptr) {}

Rankings::ScopedRankingsBlock::ScopedRankingsBlock(Rankings* rankings)
    : rankings_(rankings) {}

Rankings::ScopedRankingsBlock::ScopedRankingsBlock(Rankings* rankings,
                                                   CacheRankingsBlock* node)
    : std::unique_ptr<CacheRankingsBlock>(node), rankings_(rankings) {}

Rankings::Iterator::Iterator() = default;

void Rankings::Iterator::Reset() {
  if (my_rankings) {
    for (auto* node : nodes) {
      ScopedRankingsBlock(my_rankings, node);
    }
  }
  my_rankings = nullptr;
  nodes = {nullptr, nullptr, nullptr};
  list = List::NO_USE;
}

Rankings::Rankings() = default;

Rankings::~Rankings() = default;

bool Rankings::Init(BackendImpl* backend, bool count_lists) {
  DCHECK(!init_);
  if (init_)
    return false;

  backend_ = backend;
  control_data_ = backend_->GetLruData();
  count_lists_ = count_lists;

  ReadHeads();
  ReadTails();

  if (control_data_->transaction)
    CompleteTransaction();

  init_ = true;
  return true;
}

void Rankings::Reset() {
  init_ = false;
  for (int i = 0; i < LAST_ELEMENT; i++) {
    heads_[i].set_value(0);
    tails_[i].set_value(0);
  }
  control_data_ = nullptr;
}

void Rankings::Insert(CacheRankingsBlock* node, bool modified, List list) {
  DCHECK(node->HasData());
  Addr& my_head = heads_[list];
  Addr& my_tail = tails_[list];
  Transaction lock(control_data_, node->address(), INSERT, list);
  CacheRankingsBlock head(backend_->File(my_head), my_head);
  if (my_head.is_initialized()) {
    if (!GetRanking(&head))
      return;

    if (head.Data()->prev != my_head.value() &&  // Normal path.
        head.Data()->prev != node->address().value()) {  // FinishInsert().
      backend_->CriticalError(ERR_INVALID_LINKS);
      return;
    }

    head.Data()->prev = node->address().value();
    head.Store();
    GenerateCrash(ON_INSERT_1);
    UpdateIterators(&head);
  }

  node->Data()->next = my_head.value();
  node->Data()->prev = node->address().value();
  my_head.set_value(node->address().value());

  if (!my_tail.is_initialized() || my_tail.value() == node->address().value()) {
    my_tail.set_value(node->address().value());
    node->Data()->next = my_tail.value();
    WriteTail(list);
    GenerateCrash(ON_INSERT_2);
  }

  UpdateTimes(node, modified);
  node->Store();
  // Make sure other aliased in-memory copies get synchronized.
  UpdateIterators(node);
  GenerateCrash(ON_INSERT_3);

  // The last thing to do is move our head to point to a node already stored.
  WriteHead(list);
  IncrementCounter(list);
  GenerateCrash(ON_INSERT_4);
  backend_->FlushIndex();
}

// If a, b and r are elements on the list, and we want to remove r, the possible
// states for the objects if a crash happens are (where y(x, z) means for object
// y, prev is x and next is z):
// A. One element:
//    1. r(r, r), head(r), tail(r)                    initial state
//    2. r(r, r), head(0), tail(r)                    WriteHead()
//    3. r(r, r), head(0), tail(0)                    WriteTail()
//    4. r(0, 0), head(0), tail(0)                    next.Store()
//
// B. Remove a random element:
//    1. a(x, r), r(a, b), b(r, y), head(x), tail(y)  initial state
//    2. a(x, r), r(a, b), b(a, y), head(x), tail(y)  next.Store()
//    3. a(x, b), r(a, b), b(a, y), head(x), tail(y)  prev.Store()
//    4. a(x, b), r(0, 0), b(a, y), head(x), tail(y)  node.Store()
//
// C. Remove head:
//    1. r(r, b), b(r, y), head(r), tail(y)           initial state
//    2. r(r, b), b(r, y), head(b), tail(y)           WriteHead()
//    3. r(r, b), b(b, y), head(b), tail(y)           next.Store()
//    4. r(0, 0), b(b, y), head(b), tail(y)           prev.Store()
//
// D. Remove tail:
//    1. a(x, r), r(a, r), head(x), tail(r)           initial state
//    2. a(x, r), r(a, r), head(x), tail(a)           WriteTail()
//    3. a(x, a), r(a, r), head(x), tail(a)           prev.Store()
//    4. a(x, a), r(0, 0), head(x), tail(a)           next.Store()
void Rankings::Remove(CacheRankingsBlock* node, List list, bool strict) {
  DCHECK(node->HasData());

  Addr next_addr(node->Data()->next);
  Addr prev_addr(node->Data()->prev);
  if (!next_addr.is_initialized() || next_addr.is_separate_file() ||
      !prev_addr.is_initialized() || prev_addr.is_separate_file()) {
    if (next_addr.is_initialized() || prev_addr.is_initialized()) {
      LOG(ERROR) << "Invalid rankings info.";
      STRESS_NOTREACHED();
    }
    return;
  }

  CacheRankingsBlock next(backend_->File(next_addr), next_addr);
  CacheRankingsBlock prev(backend_->File(prev_addr), prev_addr);
  if (!GetRanking(&next) || !GetRanking(&prev)) {
    STRESS_NOTREACHED();
    return;
  }

  if (!CheckLinks(node, &prev, &next, &list))
    return;

  Transaction lock(control_data_, node->address(), REMOVE, list);
  prev.Data()->next = next.address().value();
  next.Data()->prev = prev.address().value();
  GenerateCrash(ON_REMOVE_1);

  CacheAddr node_value = node->address().value();
  Addr& my_head = heads_[list];
  Addr& my_tail = tails_[list];
  if (node_value == my_head.value() || node_value == my_tail.value()) {
    if (my_head.value() == my_tail.value()) {
      my_head.set_value(0);
      my_tail.set_value(0);

      WriteHead(list);
      GenerateCrash(ON_REMOVE_2);
      WriteTail(list);
      GenerateCrash(ON_REMOVE_3);
    } else if (node_value == my_head.value()) {
      my_head.set_value(next.address().value());
      next.Data()->prev = next.address().value();

      WriteHead(list);
      GenerateCrash(ON_REMOVE_4);
    } else if (node_value == my_tail.value()) {
      my_tail.set_value(prev.address().value());
      prev.Data()->next = prev.address().value();

      WriteTail(list);
      GenerateCrash(ON_REMOVE_5);

      // Store the new tail to make sure we can undo the operation if we crash.
      prev.Store();
      GenerateCrash(ON_REMOVE_6);
    }
  }

  // Nodes out of the list can be identified by invalid pointers.
  node->Data()->next = 0;
  node->Data()->prev = 0;

  // The last thing to get to disk is the node itself, so before that there is
  // enough info to recover.
  next.Store();
  GenerateCrash(ON_REMOVE_7);
  prev.Store();
  GenerateCrash(ON_REMOVE_8);
  node->Store();
  DecrementCounter(list);
  if (strict)
    UpdateIteratorsForRemoved(node_value, &next);

  UpdateIterators(&next);
  UpdateIterators(&prev);
  backend_->FlushIndex();
}

// A crash in between Remove and Insert will lead to a dirty entry not on the
// list. We want to avoid that case as much as we can (as while waiting for IO),
// but the net effect is just an assert on debug when attempting to remove the
// entry. Otherwise we'll need reentrant transactions, which is an overkill.
void Rankings::UpdateRank(CacheRankingsBlock* node, bool modified, List list) {
  Addr& my_head = heads_[list];
  if (my_head.value() == node->address().value()) {
    UpdateTimes(node, modified);
    node->set_modified();
    return;
  }

  Remove(node, list, true);
  Insert(node, modified, list);
}

CacheRankingsBlock* Rankings::GetNext(CacheRankingsBlock* node, List list) {
  ScopedRankingsBlock next(this);
  if (!node) {
    Addr& my_head = heads_[list];
    if (!my_head.is_initialized())
      return nullptr;
    next.reset(new CacheRankingsBlock(backend_->File(my_head), my_head));
  } else {
    if (!node->HasData())
      node->Load();
    Addr& my_tail = tails_[list];
    if (!my_tail.is_initialized())
      return nullptr;
    if (my_tail.value() == node->address().value())
      return nullptr;
    Addr address(node->Data()->next);
    if (address.value() == node->address().value())
      return nullptr;  // Another tail? fail it.
    next.reset(new CacheRankingsBlock(backend_->File(address), address));
  }

  TrackRankingsBlock(next.get(), true);

  if (!GetRanking(next.get()))
    return nullptr;

  ConvertToLongLived(next.get());
  if (node && !CheckSingleLink(node, next.get()))
    return nullptr;

  return next.release();
}

CacheRankingsBlock* Rankings::GetPrev(CacheRankingsBlock* node, List list) {
  ScopedRankingsBlock prev(this);
  if (!node) {
    Addr& my_tail = tails_[list];
    if (!my_tail.is_initialized())
      return nullptr;
    prev.reset(new CacheRankingsBlock(backend_->File(my_tail), my_tail));
  } else {
    if (!node->HasData())
      node->Load();
    Addr& my_head = heads_[list];
    if (!my_head.is_initialized())
      return nullptr;
    if (my_head.value() == node->address().value())
      return nullptr;
    Addr address(node->Data()->prev);
    if (address.value() == node->address().value())
      return nullptr;  // Another head? fail it.
    prev.reset(new CacheRankingsBlock(backend_->File(address), address));
  }

  TrackRankingsBlock(prev.get(), true);

  if (!GetRanking(prev.get()))
    return nullptr;

  ConvertToLongLived(prev.get());
  if (node && !CheckSingleLink(prev.get(), node))
    return nullptr;

  return prev.release();
}

void Rankings::FreeRankingsBlock(CacheRankingsBlock* node) {
  TrackRankingsBlock(node, false);
}

void Rankings::TrackRankingsBlock(CacheRankingsBlock* node,
                                  bool start_tracking) {
  if (!node)
    return;

  IteratorPair current(node->address().value(), node);

  if (start_tracking)
    iterators_.push_back(current);
  else
    iterators_.remove(current);
}

int Rankings::SelfCheck() {
  int total = 0;
  int error = 0;
  for (int i = 0; i < LAST_ELEMENT; i++) {
    int partial = CheckList(static_cast<List>(i));
    if (partial < 0 && !error)
      error = partial;
    else if (partial > 0)
      total += partial;
  }

  return error ? error : total;
}

bool Rankings::SanityCheck(CacheRankingsBlock* node, bool from_list) const {
  if (!node->VerifyHash())
    return false;

  const RankingsNode* data = node->Data();

  if ((!data->next && data->prev) || (data->next && !data->prev))
    return false;

  // Both pointers on zero is a node out of the list.
  if (!data->next && !data->prev && from_list)
    return false;

  List list = NO_USE;  // Initialize it to something.
  if ((node->address().value() == data->prev) && !IsHead(data->prev, &list))
    return false;

  if ((node->address().value() == data->next) && !IsTail(data->next, &list))
    return false;

  if (!data->next && !data->prev)
    return true;

  Addr next_addr(data->next);
  Addr prev_addr(data->prev);
  if (!next_addr.SanityCheck() || next_addr.file_type() != RANKINGS ||
      !prev_addr.SanityCheck() || prev_addr.file_type() != RANKINGS)
    return false;

  return true;
}

bool Rankings::DataSanityCheck(CacheRankingsBlock* node, bool from_list) const {
  const RankingsNode* data = node->Data();
  if (!data->contents)
    return false;

  // It may have never been inserted.
  if (from_list && (!data->last_used || !data->last_modified))
    return false;

  return true;
}

void Rankings::SetContents(CacheRankingsBlock* node, CacheAddr address) {
  node->Data()->contents = address;
  node->Store();
}

void Rankings::ReadHeads() {
  for (int i = 0; i < LAST_ELEMENT; i++)
    heads_[i] = Addr(control_data_->heads[i]);
}

void Rankings::ReadTails() {
  for (int i = 0; i < LAST_ELEMENT; i++)
    tails_[i] = Addr(control_data_->tails[i]);
}

void Rankings::WriteHead(List list) {
  control_data_->heads[list] = heads_[list].value();
}

void Rankings::WriteTail(List list) {
  control_data_->tails[list] = tails_[list].value();
}

bool Rankings::GetRanking(CacheRankingsBlock* rankings) {
  if (!rankings->address().is_initialized())
    return false;

  if (!rankings->Load())
    return false;

  if (!SanityCheck(rankings, true)) {
    backend_->CriticalError(ERR_INVALID_LINKS);
    return false;
  }

  backend_->OnEvent(Stats::OPEN_RANKINGS);

  // Note that if the cache is in read_only mode, open entries are not marked
  // as dirty, except when an entry is doomed. We have to look for open entries.
  if (!backend_->read_only() && !rankings->Data()->dirty)
    return true;

  EntryImpl* entry = backend_->GetOpenEntry(rankings);
  if (!entry) {
    if (backend_->read_only())
      return true;

    // We cannot trust this entry, but we cannot initiate a cleanup from this
    // point (we may be in the middle of a cleanup already). The entry will be
    // deleted when detected from a regular open/create path.
    rankings->Data()->dirty = backend_->GetCurrentEntryId() - 1;
    if (!rankings->Data()->dirty)
      rankings->Data()->dirty--;
    return true;
  }

  // Note that we should not leave this module without deleting rankings first.
  rankings->SetData(entry->rankings()->Data());

  return true;
}

void Rankings::ConvertToLongLived(CacheRankingsBlock* rankings) {
  if (rankings->own_data())
    return;

  // We cannot return a shared node because we are not keeping a reference
  // to the entry that owns the buffer. Make this node a copy of the one that
  // we have, and let the iterator logic update it when the entry changes.
  CacheRankingsBlock temp(nullptr, Addr(0));
  *temp.Data() = *rankings->Data();
  rankings->StopSharingData();
  *rankings->Data() = *temp.Data();
}

void Rankings::CompleteTransaction() {
  Addr node_addr(static_cast<CacheAddr>(control_data_->transaction));
  if (!node_addr.is_initialized() || node_addr.is_separate_file()) {
    NOTREACHED() << "Invalid rankings info.";
  }

  CacheRankingsBlock node(backend_->File(node_addr), node_addr);
  if (!node.Load())
    return;

  node.Store();

  // We want to leave the node inside the list. The entry must me marked as
  // dirty, and will be removed later. Otherwise, we'll get assertions when
  // attempting to remove the dirty entry.
  if (INSERT == control_data_->operation) {
    FinishInsert(&node);
  } else if (REMOVE == control_data_->operation) {
    RevertRemove(&node);
  } else {
    NOTREACHED() << "Invalid operation to recover.";
  }
}

void Rankings::FinishInsert(CacheRankingsBlock* node) {
  control_data_->transaction = 0;
  control_data_->operation = 0;
  Addr& my_head = heads_[control_data_->operation_list];
  Addr& my_tail = tails_[control_data_->operation_list];
  if (my_head.value() != node->address().value()) {
    if (my_tail.value() == node->address().value()) {
      // This part will be skipped by the logic of Insert.
      node->Data()->next = my_tail.value();
    }

    Insert(node, true, static_cast<List>(control_data_->operation_list));
  }

  // Tell the backend about this entry.
  backend_->RecoveredEntry(node);
}

void Rankings::RevertRemove(CacheRankingsBlock* node) {
  Addr next_addr(node->Data()->next);
  Addr prev_addr(node->Data()->prev);
  if (!next_addr.is_initialized() || !prev_addr.is_initialized()) {
    // The operation actually finished. Nothing to do.
    control_data_->transaction = 0;
    return;
  }
  if (next_addr.is_separate_file() || prev_addr.is_separate_file()) {
    NOTREACHED() << "Invalid rankings info.";
  }

  CacheRankingsBlock next(backend_->File(next_addr), next_addr);
  CacheRankingsBlock prev(backend_->File(prev_addr), prev_addr);
  if (!next.Load() || !prev.Load())
    return;

  CacheAddr node_value = node->address().value();
  DCHECK(prev.Data()->next == node_value ||
         prev.Data()->next == prev_addr.value() ||
         prev.Data()->next == next.address().value());
  DCHECK(next.Data()->prev == node_value ||
         next.Data()->prev == next_addr.value() ||
         next.Data()->prev == prev.address().value());

  if (node_value != prev_addr.value())
    prev.Data()->next = node_value;
  if (node_value != next_addr.value())
    next.Data()->prev = node_value;

  List my_list = static_cast<List>(control_data_->operation_list);
  Addr& my_head = heads_[my_list];
  Addr& my_tail = tails_[my_list];
  if (!my_head.is_initialized() || !my_tail.is_initialized()) {
    my_head.set_value(node_value);
    my_tail.set_value(node_value);
    WriteHead(my_list);
    WriteTail(my_list);
  } else if (my_head.value() == next.address().value()) {
    my_head.set_value(node_value);
    prev.Data()->next = next.address().value();
    WriteHead(my_list);
  } else if (my_tail.value() == prev.address().value()) {
    my_tail.set_value(node_value);
    next.Data()->prev = prev.address().value();
    WriteTail(my_list);
  }

  next.Store();
  prev.Store();
  control_data_->transaction = 0;
  control_data_->operation = 0;
  backend_->FlushIndex();
}

bool Rankings::CheckLinks(CacheRankingsBlock* node, CacheRankingsBlock* prev,
                          CacheRankingsBlock* next, List* list) {
  CacheAddr node_addr = node->address().value();
  if (prev->Data()->next == node_addr &&
      next->Data()->prev == node_addr) {
    // A regular linked node.
    return true;
  }

  if (node_addr != prev->address().value() &&
      node_addr != next->address().value() &&
      prev->Data()->next == next->address().value() &&
      next->Data()->prev == prev->address().value()) {
    // The list is actually ok, node is wrong.
    node->Data()->next = 0;
    node->Data()->prev = 0;
    node->Store();
    return false;
  }

  if (prev->Data()->next == node_addr ||
      next->Data()->prev == node_addr) {
    // Only one link is weird, lets double check.
    if (prev->Data()->next != node_addr && IsHead(node_addr, list))
      return true;

    if (next->Data()->prev != node_addr && IsTail(node_addr, list))
      return true;
  }

  LOG(ERROR) << "Inconsistent LRU.";
  STRESS_NOTREACHED();

  backend_->CriticalError(ERR_INVALID_LINKS);
  return false;
}

bool Rankings::CheckSingleLink(CacheRankingsBlock* prev,
                               CacheRankingsBlock* next) {
  if (prev->Data()->next != next->address().value() ||
      next->Data()->prev != prev->address().value()) {
    LOG(ERROR) << "Inconsistent LRU.";

    backend_->CriticalError(ERR_INVALID_LINKS);
    return false;
  }

  return true;
}

int Rankings::CheckList(List list) {
  Addr last1, last2;
  int head_items;
  int rv = CheckListSection(list, last1, last2, true,  // Head to tail.
                            &last1, &last2, &head_items);
  if (rv == ERR_NO_ERROR)
    return head_items;

  return rv;
}

// Note that the returned error codes assume a forward walk (from head to tail)
// so they have to be adjusted accordingly by the caller. We use two stop values
// to be able to detect a corrupt node at the end that is not linked going back.
int Rankings::CheckListSection(List list, Addr end1, Addr end2, bool forward,
                               Addr* last, Addr* second_last, int* num_items) {
  Addr current = forward ? heads_[list] : tails_[list];
  *last = *second_last = current;
  *num_items = 0;
  if (!current.is_initialized())
    return ERR_NO_ERROR;

  if (!current.SanityCheckForRankings())
    return ERR_INVALID_HEAD;

  std::unique_ptr<CacheRankingsBlock> node;
  Addr prev_addr(current);
  do {
    node =
        std::make_unique<CacheRankingsBlock>(backend_->File(current), current);
    node->Load();
    if (!SanityCheck(node.get(), true))
      return ERR_INVALID_ENTRY;

    CacheAddr next = forward ? node->Data()->next : node->Data()->prev;
    CacheAddr prev = forward ? node->Data()->prev : node->Data()->next;

    if (prev != prev_addr.value())
      return ERR_INVALID_PREV;

    Addr next_addr(next);
    if (!next_addr.SanityCheckForRankings())
      return ERR_INVALID_NEXT;

    prev_addr = current;
    current = next_addr;
    *second_last = *last;
    *last = current;
    (*num_items)++;

    if (next_addr == prev_addr) {
      if (next_addr == (forward ? tails_[list] : heads_[list]))
        return ERR_NO_ERROR;
      return ERR_INVALID_TAIL;
    }
  } while (current != end1 && current != end2);
  return ERR_NO_ERROR;
}

bool Rankings::IsHead(CacheAddr addr, List* list) const {
  for (int i = 0; i < LAST_ELEMENT; i++) {
    if (addr == heads_[i].value()) {
      *list = static_cast<List>(i);
      return true;
    }
  }
  return false;
}

bool Rankings::IsTail(CacheAddr addr, List* list) const {
  for (int i = 0; i < LAST_ELEMENT; i++) {
    if (addr == tails_[i].value()) {
      *list = static_cast<List>(i);
      return true;
    }
  }
  return false;
}

// We expect to have just a few iterators at any given time, maybe two or three,
// But we could have more than one pointing at the same mode. We walk the list
// of cache iterators and update all that are pointing to the given node.
void Rankings::UpdateIterators(CacheRankingsBlock* node) {
  CacheAddr address = node->address().value();
  for (auto& iterator : iterators_) {
    if (iterator.first == address && iterator.second->HasData()) {
      CacheRankingsBlock* other = iterator.second;
      if (other != node)
        *other->Data() = *node->Data();
    }
  }
}

void Rankings::UpdateIteratorsForRemoved(CacheAddr address,
                                         CacheRankingsBlock* next) {
  CacheAddr next_addr = next->address().value();
  for (auto& iterator : iterators_) {
    if (iterator.first == address) {
      iterator.first = next_addr;
      iterator.second->CopyFrom(next);
    }
  }
}

void Rankings::IncrementCounter(List list) {
  if (!count_lists_)
    return;

  DCHECK(control_data_->sizes[list] < std::numeric_limits<int32_t>::max());
  if (control_data_->sizes[list] < std::numeric_limits<int32_t>::max())
    control_data_->sizes[list]++;
}

void Rankings::DecrementCounter(List list) {
  if (!count_lists_)
    return;

  DCHECK(control_data_->sizes[list] > 0);
  if (control_data_->sizes[list] > 0)
    control_data_->sizes[list]--;
}

}  // namespace disk_cache
```