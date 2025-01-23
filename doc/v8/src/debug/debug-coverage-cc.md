Response:
My thinking process to analyze the `debug-coverage.cc` code and answer the prompt goes like this:

1. **Understand the Core Purpose:**  The filename `debug-coverage.cc` immediately suggests this code is about collecting code coverage information for debugging purposes. The `#include "src/debug/debug-coverage.h"` reinforces this. I'll look for keywords related to counting executions, tracking code blocks, and reporting this data.

2. **High-Level Structure:** I'll scan the file for namespaces, classes, and major functions to get an overview of the organization. The `v8::internal` namespace is expected. The `SharedToCounterMap` class stands out as a potential key data structure. The functions starting with `Collect` and `Filter` are likely important.

3. **`SharedToCounterMap`:**  This looks like a simple hash map to store the execution count for each `SharedFunctionInfo`. The `Add` and `Get` methods are standard. The `DISALLOW_GARBAGE_COLLECTION` is a performance optimization and suggests this map is performance-critical during coverage collection.

4. **Helper Functions:** The functions like `StartPosition`, `CompareCoverageBlock`, and `SortBlockData` seem to be utilities for dealing with source code positions and sorting coverage blocks. The `CompareCoverageBlock` function specifically suggests a nested structure of code blocks.

5. **`CoverageBlockIterator`:** This class is crucial. The name and the presence of `Next`, `GetBlock`, `DeleteBlock`, `GetParent`, `HasSiblingOrChild`, and a `nesting_stack_` clearly indicate it's designed to traverse and manipulate a potentially nested structure of coverage blocks. The comments about "implicit tree structure" confirm this. The `Finalize` method modifying the `function_->blocks` vector suggests in-place modifications are happening.

6. **Transformation Functions:** Functions like `MergeDuplicateRanges`, `RewritePositionSingletonsToRanges`, `MergeConsecutiveRanges`, `MergeNestedRanges`, `FilterAliasedSingletons`, `FilterUncoveredRanges`, `FilterEmptyRanges`, and `ClampToBinary` suggest post-processing steps applied to the raw coverage data. The names clearly indicate their purpose. I'll keep these in mind when explaining the functionality.

7. **`CollectBlockCoverageInternal` and `CollectBlockCoverage`:** These are likely the core functions for gathering block-level coverage. The internal function probably does the heavy lifting, and the outer function might handle setup or cleanup. The logic of calling `GetSortedBlockData`, then applying various transformation functions (the "filters" and "mergers"), is important.

8. **`CollectAndMaybeResetCounts`:** This function appears to be responsible for iterating through `FeedbackVector`s (and potentially `JSFunction`s in the "best effort" mode) to collect invocation counts and store them in the `SharedToCounterMap`. The `reset_count` logic based on the `coverage_mode` is important.

9. **`Coverage::CollectPrecise` and `Coverage::CollectBestEffort`:** These seem to be entry points for collecting coverage with different levels of precision. The "precise" version interacts with feedback vectors more directly.

10. **`Coverage::Collect`:** This is the main entry point that orchestrates the entire coverage collection process. It creates the `Coverage` object, iterates through scripts and their functions, collects counts, and then, crucially, calls `CollectBlockCoverage` if block-level coverage is enabled. The logic for handling nested functions and the `sorted` vector of `SharedFunctionInfoAndCount` is interesting.

11. **`Coverage::SelectMode`:** This function manages switching between different coverage modes and performs necessary setup or teardown, such as deoptimizing functions and managing feedback vectors.

12. **Answering the Prompt (Iterative Refinement):**

    * **Functionality:** Based on the above analysis, I can now list the main functionalities: collecting invocation counts, collecting block-level coverage, transforming and filtering coverage data, supporting different coverage modes, and structuring the data by script and function.

    * **`.tq` Extension:** I know `.tq` files are for Torque, V8's type system and implementation language. The prompt is explicit about this.

    * **JavaScript Relationship:** The code directly relates to JavaScript execution. I can provide a simple example where different parts of the code are executed, leading to different coverage counts. The `if/else` example is a good standard illustration of block coverage.

    * **Code Logic Reasoning:** I'll choose a simpler transformation function like `ClampToBinary` or `MergeDuplicateRanges` to illustrate input and output. Providing a sample `CoverageFunction` before and after the transformation makes it clear.

    * **Common Programming Errors:** I'll think about errors that coverage tools help identify. Unreachable code (`if (false)`) and untested branches (`if (condition) { ... }`) are common examples.

This step-by-step analysis, focusing on understanding the purpose of different parts of the code and how they interact, allows me to build a comprehensive and accurate answer to the prompt. The iterative refinement comes in as I might initially misunderstand a function's purpose and then correct it as I analyze the code further. For example, I might initially think `FilterAliasedSingletons` is about merging, but the comment clarifies its purpose as *filtering*.
好的，让我们来分析一下 `v8/src/debug/debug-coverage.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/src/debug/debug-coverage.cc` 文件的主要功能是 **收集 JavaScript 代码的覆盖率信息**，用于调试和性能分析。它提供了多种覆盖率模式，包括：

* **精确计数模式 (Precise Count):** 记录每个函数被调用的精确次数。
* **精确二进制模式 (Precise Binary):**  记录每个函数是否被调用过（0 或 1）。
* **块计数模式 (Block Count):** 记录代码块（例如，if 语句的不同分支）被执行的次数。
* **块二进制模式 (Block Binary):** 记录代码块是否被执行过（0 或 1）。
* **尽力而为模式 (Best Effort):**  尝试在不影响性能的情况下收集覆盖率信息，可能不如精确模式准确。

该文件定义了用于收集、处理和存储覆盖率数据的类和函数。

**主要功能点:**

1. **收集函数调用计数:**
   - 使用 `SharedToCounterMap` 存储每个 `SharedFunctionInfo` 对应的调用次数。
   - 通过迭代 `FeedbackVector` 或 `JSFunction` 对象来获取调用计数。
   - 在精确模式下，会重置调用计数，以便进行新的覆盖率收集。

2. **收集代码块覆盖率 (Block Coverage):**
   - 如果启用了块覆盖率模式，会从 `CoverageInfo` 对象中获取代码块的信息（起始位置、结束位置、计数）。
   - 使用 `CoverageBlockIterator` 类来遍历和操作代码块数据。
   - 实现了多种转换和过滤操作来优化和精简块覆盖率数据，例如：
     - 合并重复的范围 (`MergeDuplicateRanges`)。
     - 将单点位置转换为范围 (`RewritePositionSingletonsToRanges`)。
     - 合并连续的范围 (`MergeConsecutiveRanges`)。
     - 合并嵌套的范围 (`MergeNestedRanges`)。
     - 过滤掉未覆盖的范围 (`FilterUncoveredRanges`)。
     - 过滤掉空范围 (`FilterEmptyRanges`)。

3. **管理覆盖率模式:**
   - `Coverage::SelectMode` 函数用于切换不同的覆盖率模式。
   - 切换模式时，可能需要去优化所有函数、确保 `FeedbackVector` 的存在等操作。

4. **组织覆盖率数据:**
   - 使用 `Coverage` 类来存储整个覆盖率结果，按脚本组织。
   - 每个脚本对应一个 `Coverage::Entry`，其中包含一个 `CoverageFunction` 的向量。
   - `CoverageFunction` 存储了函数的起始位置、结束位置、调用次数以及块覆盖率信息（`std::vector<CoverageBlock>`）。

5. **与 V8 内部机制交互:**
   - 使用 `SharedFunctionInfo` 来标识函数。
   - 使用 `FeedbackVector` 来获取函数的调用次数。
   - 使用 `CoverageInfo` 来获取代码块的覆盖率信息。
   - 与优化器 (`Deoptimizer`) 交互，以确保在收集覆盖率时能获取到所有函数的反馈信息。

**关于 .tq 扩展名**

如果 `v8/src/debug/debug-coverage.cc` 以 `.tq` 结尾，那么它的确是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用于实现运行时内置函数和优化代码的领域特定语言。  然而，根据您提供的代码内容和文件名，它是一个 **.cc (C++)** 文件。

**与 JavaScript 的关系及示例**

`v8/src/debug/debug-coverage.cc` 的核心功能是为 JavaScript 代码收集覆盖率信息。以下 JavaScript 示例可以说明其工作原理：

```javascript
function add(a, b) {
  if (a > 0) {
    return a + b;
  } else {
    return b;
  }
}

console.log(add(5, 2)); // 输出 7
console.log(add(-1, 3)); // 输出 3
```

**覆盖率信息 (假设启用了块计数模式):**

* **函数 `add` 的调用次数:** 2
* **代码块覆盖率:**
    * `if (a > 0)` 块（`return a + b;`）：执行 1 次 (当 `a` 为 5 时)
    * `else` 块（`return b;`）：执行 1 次 (当 `a` 为 -1 时)

**代码逻辑推理及假设输入输出**

让我们以 `ClampToBinary` 函数为例进行代码逻辑推理。

**功能:** 将所有代码块的计数限制为 0 或 1。如果计数大于 0，则设置为 1。

**假设输入 (一个 `CoverageFunction` 对象):**

```
CoverageFunction {
  start: 0,
  end: 50,
  count: 2,
  blocks: [
    { start: 5, end: 10, count: 3 },
    { start: 15, end: 20, count: 0 },
    { start: 25, end: 30, count: 1 },
  ]
}
```

**执行 `ClampToBinary` 后的输出:**

```
CoverageFunction {
  start: 0,
  end: 50,
  count: 2, // 函数调用计数不受影响
  blocks: [
    { start: 5, end: 10, count: 1 }, // 原始计数 3 被转换为 1
    { start: 15, end: 20, count: 0 }, // 原始计数 0 保持不变
    { start: 25, end: 30, count: 1 }, // 原始计数 1 保持不变
  ]
}
```

**涉及用户常见的编程错误**

覆盖率工具可以帮助开发者发现一些常见的编程错误，例如：

1. **未覆盖的代码分支 (Untested Branches):**

   ```javascript
   function calculateDiscount(price, hasCoupon) {
     if (hasCoupon) {
       return price * 0.9;
     }
     // 如果没有优惠券，这里缺少了 return 语句，或者应该返回原价
   }

   console.log(calculateDiscount(100, true)); // 输出 90
   ```

   如果只执行了 `calculateDiscount(100, true)`，覆盖率工具会显示 `if` 块被覆盖，但 `else` 分支（或者在没有 `else` 的情况下，`if` 条件为 `false` 的情况）没有被覆盖，提示开发者可能存在逻辑漏洞。

2. **死代码 (Dead Code) 或不可达代码 (Unreachable Code):**

   ```javascript
   function processOrder(items) {
     if (items.length > 0) {
       // ... 处理订单逻辑 ...
       return "Order processed";
     } else {
       return "No items in order";
     }

     console.log("这条语句永远不会执行到"); // 死代码
   }

   console.log(processOrder([]));
   ```

   覆盖率工具会标记 `console.log("这条语句永远不会执行到");` 这行代码没有被执行，提示开发者这段代码是多余的。

3. **条件判断错误:**

   ```javascript
   function isAdult(age) {
     if (age = 18) { // 错误地使用了赋值运算符 `=` 而不是比较运算符 `===` 或 `==`
       return true;
     } else {
       return false;
     }
   }

   console.log(isAdult(16)); // 输出 true，因为 age = 18 会返回 18 (truthy)
   ```

   虽然这段代码可能不会直接导致崩溃，但它的行为不符合预期。覆盖率工具可能无法直接指出这个错误，但如果测试用例只覆盖了 `age` 为 16 的情况，而没有覆盖其他情况，那么覆盖率报告可能会提示 `else` 分支没有被覆盖，从而促使开发者检查条件判断逻辑。

**总结**

`v8/src/debug/debug-coverage.cc` 是 V8 调试工具集中一个关键的组成部分，负责收集 JavaScript 代码的覆盖率信息。它提供了多种覆盖率模式，并对收集到的数据进行处理和优化，帮助开发者理解代码的执行情况，发现潜在的错误和未测试的代码路径。它通过与 V8 内部的 `SharedFunctionInfo`、`FeedbackVector` 和 `CoverageInfo` 等机制交互来实现其功能。

### 提示词
```
这是目录为v8/src/debug/debug-coverage.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-coverage.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug-coverage.h"

#include "src/ast/ast-source-ranges.h"
#include "src/base/hashmap.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

class SharedToCounterMap
    : public base::TemplateHashMapImpl<Tagged<SharedFunctionInfo>, uint32_t,
                                       base::KeyEqualityMatcher<Tagged<Object>>,
                                       base::DefaultAllocationPolicy> {
 public:
  using Entry =
      base::TemplateHashMapEntry<Tagged<SharedFunctionInfo>, uint32_t>;
  inline void Add(Tagged<SharedFunctionInfo> key, uint32_t count) {
    Entry* entry = LookupOrInsert(key, Hash(key), []() { return 0; });
    uint32_t old_count = entry->value;
    if (UINT32_MAX - count < old_count) {
      entry->value = UINT32_MAX;
    } else {
      entry->value = old_count + count;
    }
  }

  inline uint32_t Get(Tagged<SharedFunctionInfo> key) {
    Entry* entry = Lookup(key, Hash(key));
    if (entry == nullptr) return 0;
    return entry->value;
  }

 private:
  static uint32_t Hash(Tagged<SharedFunctionInfo> key) {
    return static_cast<uint32_t>(key.ptr());
  }

  DISALLOW_GARBAGE_COLLECTION(no_gc)
};

namespace {
int StartPosition(Tagged<SharedFunctionInfo> info) {
  int start = info->function_token_position();
  if (start == kNoSourcePosition) start = info->StartPosition();
  return start;
}

bool CompareCoverageBlock(const CoverageBlock& a, const CoverageBlock& b) {
  DCHECK_NE(kNoSourcePosition, a.start);
  DCHECK_NE(kNoSourcePosition, b.start);
  if (a.start == b.start) return a.end > b.end;
  return a.start < b.start;
}

void SortBlockData(std::vector<CoverageBlock>& v) {
  // Sort according to the block nesting structure.
  std::sort(v.begin(), v.end(), CompareCoverageBlock);
}

std::vector<CoverageBlock> GetSortedBlockData(
    Isolate* isolate, Tagged<SharedFunctionInfo> shared) {
  DCHECK(shared->HasCoverageInfo(isolate));

  Tagged<CoverageInfo> coverage_info =
      Cast<CoverageInfo>(shared->GetDebugInfo(isolate)->coverage_info());

  std::vector<CoverageBlock> result;
  if (coverage_info->slot_count() == 0) return result;

  for (int i = 0; i < coverage_info->slot_count(); i++) {
    const int start_pos = coverage_info->slots_start_source_position(i);
    const int until_pos = coverage_info->slots_end_source_position(i);
    const int count = coverage_info->slots_block_count(i);

    DCHECK_NE(kNoSourcePosition, start_pos);
    result.emplace_back(start_pos, until_pos, count);
  }

  SortBlockData(result);

  return result;
}

// A utility class to simplify logic for performing passes over block coverage
// ranges. Provides access to the implicit tree structure of ranges (i.e. access
// to parent and sibling blocks), and supports efficient in-place editing and
// deletion. The underlying backing store is the array of CoverageBlocks stored
// on the CoverageFunction.
class CoverageBlockIterator final {
 public:
  explicit CoverageBlockIterator(CoverageFunction* function)
      : function_(function) {
    DCHECK(std::is_sorted(function_->blocks.begin(), function_->blocks.end(),
                          CompareCoverageBlock));
  }

  ~CoverageBlockIterator() {
    Finalize();
    DCHECK(std::is_sorted(function_->blocks.begin(), function_->blocks.end(),
                          CompareCoverageBlock));
  }

  bool HasNext() const {
    return read_index_ + 1 < static_cast<int>(function_->blocks.size());
  }

  bool Next() {
    if (!HasNext()) {
      if (!ended_) MaybeWriteCurrent();
      ended_ = true;
      return false;
    }

    // If a block has been deleted, subsequent iteration moves trailing blocks
    // to their updated position within the array.
    MaybeWriteCurrent();

    if (read_index_ == -1) {
      // Initialize the nesting stack with the function range.
      nesting_stack_.emplace_back(function_->start, function_->end,
                                  function_->count);
    } else if (!delete_current_) {
      nesting_stack_.emplace_back(GetBlock());
    }

    delete_current_ = false;
    read_index_++;

    DCHECK(IsActive());

    CoverageBlock& block = GetBlock();
    while (nesting_stack_.size() > 1 &&
           nesting_stack_.back().end <= block.start) {
      nesting_stack_.pop_back();
    }

    DCHECK_IMPLIES(block.start >= function_->end,
                   block.end == kNoSourcePosition);
    DCHECK_NE(block.start, kNoSourcePosition);
    DCHECK_LE(block.end, GetParent().end);

    return true;
  }

  CoverageBlock& GetBlock() {
    DCHECK(IsActive());
    return function_->blocks[read_index_];
  }

  CoverageBlock& GetNextBlock() {
    DCHECK(IsActive());
    DCHECK(HasNext());
    return function_->blocks[read_index_ + 1];
  }

  CoverageBlock& GetPreviousBlock() {
    DCHECK(IsActive());
    DCHECK_GT(read_index_, 0);
    return function_->blocks[read_index_ - 1];
  }

  CoverageBlock& GetParent() {
    DCHECK(IsActive());
    return nesting_stack_.back();
  }

  bool HasSiblingOrChild() {
    DCHECK(IsActive());
    return HasNext() && GetNextBlock().start < GetParent().end;
  }

  CoverageBlock& GetSiblingOrChild() {
    DCHECK(HasSiblingOrChild());
    DCHECK(IsActive());
    return GetNextBlock();
  }

  // A range is considered to be at top level if its parent range is the
  // function range.
  bool IsTopLevel() const { return nesting_stack_.size() == 1; }

  void DeleteBlock() {
    DCHECK(!delete_current_);
    DCHECK(IsActive());
    delete_current_ = true;
  }

 private:
  void MaybeWriteCurrent() {
    if (delete_current_) return;
    if (read_index_ >= 0 && write_index_ != read_index_) {
      function_->blocks[write_index_] = function_->blocks[read_index_];
    }
    write_index_++;
  }

  void Finalize() {
    while (Next()) {
      // Just iterate to the end.
    }
    function_->blocks.resize(write_index_);
  }

  bool IsActive() const { return read_index_ >= 0 && !ended_; }

  CoverageFunction* function_;
  std::vector<CoverageBlock> nesting_stack_;
  bool ended_ = false;
  bool delete_current_ = false;
  int read_index_ = -1;
  int write_index_ = -1;
};

bool HaveSameSourceRange(const CoverageBlock& lhs, const CoverageBlock& rhs) {
  return lhs.start == rhs.start && lhs.end == rhs.end;
}

void MergeDuplicateRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next() && iter.HasNext()) {
    CoverageBlock& block = iter.GetBlock();
    CoverageBlock& next_block = iter.GetNextBlock();

    if (!HaveSameSourceRange(block, next_block)) continue;

    DCHECK_NE(kNoSourcePosition, block.end);  // Non-singleton range.
    next_block.count = std::max(block.count, next_block.count);
    iter.DeleteBlock();
  }
}

// Rewrite position singletons (produced by unconditional control flow
// like return statements, and by continuation counters) into source
// ranges that end at the next sibling range or the end of the parent
// range, whichever comes first.
void RewritePositionSingletonsToRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();
    CoverageBlock& parent = iter.GetParent();

    if (block.start >= function->end) {
      DCHECK_EQ(block.end, kNoSourcePosition);
      iter.DeleteBlock();
    } else if (block.end == kNoSourcePosition) {
      // The current block ends at the next sibling block (if it exists) or the
      // end of the parent block otherwise.
      if (iter.HasSiblingOrChild()) {
        block.end = iter.GetSiblingOrChild().start;
      } else if (iter.IsTopLevel()) {
        // See https://crbug.com/v8/6661. Functions are special-cased because
        // we never want the closing brace to be uncovered. This is mainly to
        // avoid a noisy UI.
        block.end = parent.end - 1;
      } else {
        block.end = parent.end;
      }
    }
  }
}

void MergeConsecutiveRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();

    if (iter.HasSiblingOrChild()) {
      CoverageBlock& sibling = iter.GetSiblingOrChild();
      if (sibling.start == block.end && sibling.count == block.count) {
        // Best-effort: this pass may miss mergeable siblings in the presence of
        // child blocks.
        sibling.start = block.start;
        iter.DeleteBlock();
      }
    }
  }
}

void MergeNestedRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();
    CoverageBlock& parent = iter.GetParent();

    if (parent.count == block.count) {
      // Transformation may not be valid if sibling blocks exist with a
      // differing count.
      iter.DeleteBlock();
    }
  }
}

void RewriteFunctionScopeCounter(CoverageFunction* function) {
  // Every function must have at least the top-level function counter.
  DCHECK(!function->blocks.empty());

  CoverageBlockIterator iter(function);
  if (iter.Next()) {
    DCHECK(iter.IsTopLevel());

    CoverageBlock& block = iter.GetBlock();
    if (block.start == SourceRange::kFunctionLiteralSourcePosition &&
        block.end == SourceRange::kFunctionLiteralSourcePosition) {
      // If a function-scope block exists, overwrite the function count. It has
      // a more reliable count than what we get from the FeedbackVector (which
      // is imprecise e.g. for generator functions and optimized code).
      function->count = block.count;

      // Then delete it; for compatibility with non-block coverage modes, the
      // function-scope block is expected in CoverageFunction, not as a
      // CoverageBlock.
      iter.DeleteBlock();
    }
  }
}

void FilterAliasedSingletons(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  iter.Next();  // Advance once since we reference the previous block later.

  while (iter.Next()) {
    CoverageBlock& previous_block = iter.GetPreviousBlock();
    CoverageBlock& block = iter.GetBlock();

    bool is_singleton = block.end == kNoSourcePosition;
    bool aliases_start = block.start == previous_block.start;

    if (is_singleton && aliases_start) {
      // The previous block must have a full range since duplicate singletons
      // have already been merged.
      DCHECK_NE(previous_block.end, kNoSourcePosition);
      // Likewise, the next block must have another start position since
      // singletons are sorted to the end.
      DCHECK_IMPLIES(iter.HasNext(), iter.GetNextBlock().start != block.start);
      iter.DeleteBlock();
    }
  }
}

void FilterUncoveredRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();
    CoverageBlock& parent = iter.GetParent();
    if (block.count == 0 && parent.count == 0) iter.DeleteBlock();
  }
}

void FilterEmptyRanges(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();
    if (block.start == block.end) iter.DeleteBlock();
  }
}

void ClampToBinary(CoverageFunction* function) {
  CoverageBlockIterator iter(function);

  while (iter.Next()) {
    CoverageBlock& block = iter.GetBlock();
    if (block.count > 0) block.count = 1;
  }
}

void ResetAllBlockCounts(Isolate* isolate, Tagged<SharedFunctionInfo> shared) {
  DCHECK(shared->HasCoverageInfo(isolate));

  Tagged<CoverageInfo> coverage_info =
      Cast<CoverageInfo>(shared->GetDebugInfo(isolate)->coverage_info());

  for (int i = 0; i < coverage_info->slot_count(); i++) {
    coverage_info->ResetBlockCount(i);
  }
}

bool IsBlockMode(debug::CoverageMode mode) {
  switch (mode) {
    case debug::CoverageMode::kBlockBinary:
    case debug::CoverageMode::kBlockCount:
      return true;
    default:
      return false;
  }
}

bool IsBinaryMode(debug::CoverageMode mode) {
  switch (mode) {
    case debug::CoverageMode::kBlockBinary:
    case debug::CoverageMode::kPreciseBinary:
      return true;
    default:
      return false;
  }
}

void CollectBlockCoverageInternal(Isolate* isolate, CoverageFunction* function,
                                  Tagged<SharedFunctionInfo> info,
                                  debug::CoverageMode mode) {
  DCHECK(IsBlockMode(mode));

  // Functions with empty source ranges are not interesting to report. This can
  // happen e.g. for internally-generated functions like class constructors.
  if (!function->HasNonEmptySourceRange()) return;

  function->has_block_coverage = true;
  function->blocks = GetSortedBlockData(isolate, info);

  // If in binary mode, only report counts of 0/1.
  if (mode == debug::CoverageMode::kBlockBinary) ClampToBinary(function);

  // To stay compatible with non-block coverage modes, the function-scope count
  // is expected to be in the CoverageFunction, not as part of its blocks.
  // This finds the function-scope counter, overwrites CoverageFunction::count,
  // and removes it from the block list.
  //
  // Important: Must be called before other transformation passes.
  RewriteFunctionScopeCounter(function);

  // Functions without blocks don't need to be processed further.
  if (!function->HasBlocks()) return;

  // Remove singleton ranges with the same start position as a full range and
  // throw away their counts.
  // Singleton ranges are only intended to split existing full ranges and should
  // never expand into a full range. Consider 'if (cond) { ... } else { ... }'
  // as a problematic example; if the then-block produces a continuation
  // singleton, it would incorrectly expand into the else range.
  // For more context, see https://crbug.com/v8/8237.
  FilterAliasedSingletons(function);

  // Rewrite all singletons (created e.g. by continuations and unconditional
  // control flow) to ranges.
  RewritePositionSingletonsToRanges(function);

  // Merge nested and consecutive ranges with identical counts.
  // Note that it's necessary to merge duplicate ranges prior to merging nested
  // changes in order to avoid invalid transformations. See crbug.com/827530.
  MergeConsecutiveRanges(function);

  SortBlockData(function->blocks);
  MergeDuplicateRanges(function);
  MergeNestedRanges(function);

  MergeConsecutiveRanges(function);

  // Filter out ranges with count == 0 unless the immediate parent range has
  // a count != 0.
  FilterUncoveredRanges(function);

  // Filter out ranges of zero length.
  FilterEmptyRanges(function);
}

void CollectBlockCoverage(Isolate* isolate, CoverageFunction* function,
                          Tagged<SharedFunctionInfo> info,
                          debug::CoverageMode mode) {
  CollectBlockCoverageInternal(isolate, function, info, mode);

  // Reset all counters on the DebugInfo to zero.
  ResetAllBlockCounts(isolate, info);
}

void PrintBlockCoverage(const CoverageFunction* function,
                        Tagged<SharedFunctionInfo> info,
                        bool has_nonempty_source_range,
                        bool function_is_relevant) {
  DCHECK(v8_flags.trace_block_coverage);
  std::unique_ptr<char[]> function_name = function->name->ToCString();
  i::PrintF(
      "Coverage for function='%s', SFI=%p, has_nonempty_source_range=%d, "
      "function_is_relevant=%d\n",
      function_name.get(), reinterpret_cast<void*>(info.ptr()),
      has_nonempty_source_range, function_is_relevant);
  i::PrintF("{start: %d, end: %d, count: %d}\n", function->start, function->end,
            function->count);
  for (const auto& block : function->blocks) {
    i::PrintF("{start: %d, end: %d, count: %d}\n", block.start, block.end,
              block.count);
  }
}

void CollectAndMaybeResetCounts(Isolate* isolate,
                                SharedToCounterMap* counter_map,
                                v8::debug::CoverageMode coverage_mode) {
  const bool reset_count =
      coverage_mode != v8::debug::CoverageMode::kBestEffort;

  switch (isolate->code_coverage_mode()) {
    case v8::debug::CoverageMode::kBlockBinary:
    case v8::debug::CoverageMode::kBlockCount:
    case v8::debug::CoverageMode::kPreciseBinary:
    case v8::debug::CoverageMode::kPreciseCount: {
      // Feedback vectors are already listed to prevent losing them to GC.
      DCHECK(IsArrayList(
          *isolate->factory()->feedback_vectors_for_profiling_tools()));
      auto list = Cast<ArrayList>(
          isolate->factory()->feedback_vectors_for_profiling_tools());
      for (int i = 0; i < list->length(); i++) {
        Tagged<FeedbackVector> vector = Cast<FeedbackVector>(list->get(i));
        Tagged<SharedFunctionInfo> shared = vector->shared_function_info();
        DCHECK(shared->IsSubjectToDebugging());
        uint32_t count = static_cast<uint32_t>(vector->invocation_count());
        if (reset_count) vector->clear_invocation_count(kRelaxedStore);
        counter_map->Add(shared, count);
      }
      break;
    }
    case v8::debug::CoverageMode::kBestEffort: {
      DCHECK(!IsArrayList(
          *isolate->factory()->feedback_vectors_for_profiling_tools()));
      DCHECK_EQ(v8::debug::CoverageMode::kBestEffort, coverage_mode);
      AllowGarbageCollection allow_gc;
      HeapObjectIterator heap_iterator(isolate->heap());
      for (Tagged<HeapObject> current_obj = heap_iterator.Next();
           !current_obj.is_null(); current_obj = heap_iterator.Next()) {
        if (!IsJSFunction(current_obj)) continue;
        Tagged<JSFunction> func = Cast<JSFunction>(current_obj);
        Tagged<SharedFunctionInfo> shared = func->shared();
        if (!shared->IsSubjectToDebugging()) continue;
        if (!(func->has_feedback_vector() ||
              func->has_closure_feedback_cell_array())) {
          continue;
        }
        uint32_t count = 0;
        if (func->has_feedback_vector()) {
          count = static_cast<uint32_t>(
              func->feedback_vector()->invocation_count());
        } else if (func->shared()->HasBytecodeArray() &&
                   func->raw_feedback_cell()->interrupt_budget() <
                       TieringManager::InterruptBudgetFor(isolate, func, {})) {
          // We haven't allocated feedback vector, but executed the function
          // atleast once. We don't have precise invocation count here.
          count = 1;
        }
        counter_map->Add(shared, count);
      }

      // Also check functions on the stack to collect the count map. With lazy
      // feedback allocation we may miss counting functions if the feedback
      // vector wasn't allocated yet and the function's interrupt budget wasn't
      // updated (i.e. it didn't execute return / jump).
      for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
        Tagged<SharedFunctionInfo> shared = it.frame()->function()->shared();
        if (counter_map->Get(shared) != 0) continue;
        counter_map->Add(shared, 1);
      }
      break;
    }
  }
}

// A {SFI, count} tuple is used to sort by source range (stored on
// the SFI) and call count (in the counter map).
struct SharedFunctionInfoAndCount {
  SharedFunctionInfoAndCount(Handle<SharedFunctionInfo> info, uint32_t count)
      : info(info),
        count(count),
        start(StartPosition(*info)),
        end(info->EndPosition()) {}

  // Sort by:
  // - start, ascending.
  // - end, descending.
  // - info.is_toplevel() first
  // - count, descending.
  bool operator<(const SharedFunctionInfoAndCount& that) const {
    if (this->start != that.start) return this->start < that.start;
    if (this->end != that.end) return this->end > that.end;
    if (this->info->is_toplevel() != that.info->is_toplevel()) {
      return this->info->is_toplevel();
    }
    return this->count > that.count;
  }

  Handle<SharedFunctionInfo> info;
  uint32_t count;
  int start;
  int end;
};

}  // anonymous namespace

std::unique_ptr<Coverage> Coverage::CollectPrecise(Isolate* isolate) {
  DCHECK(!isolate->is_best_effort_code_coverage());
  std::unique_ptr<Coverage> result =
      Collect(isolate, isolate->code_coverage_mode());
  if (isolate->is_precise_binary_code_coverage() ||
      isolate->is_block_binary_code_coverage()) {
    // We do not have to hold onto feedback vectors for invocations we already
    // reported. So we can reset the list.
    isolate->SetFeedbackVectorsForProfilingTools(
        ReadOnlyRoots(isolate).empty_array_list());
  }
  return result;
}

std::unique_ptr<Coverage> Coverage::CollectBestEffort(Isolate* isolate) {
  return Collect(isolate, v8::debug::CoverageMode::kBestEffort);
}

std::unique_ptr<Coverage> Coverage::Collect(
    Isolate* isolate, v8::debug::CoverageMode collectionMode) {
  // Unsupported if jitless mode is enabled at build-time since related
  // optimizations deactivate invocation count updates.
  CHECK(!V8_JITLESS_BOOL);

  // Collect call counts for all functions.
  SharedToCounterMap counter_map;
  CollectAndMaybeResetCounts(isolate, &counter_map, collectionMode);

  // Iterate shared function infos of every script and build a mapping
  // between source ranges and invocation counts.
  std::unique_ptr<Coverage> result(new Coverage());

  std::vector<Handle<Script>> scripts;
  Script::Iterator scriptIt(isolate);
  for (Tagged<Script> script = scriptIt.Next(); !script.is_null();
       script = scriptIt.Next()) {
    if (script->IsUserJavaScript()) scripts.push_back(handle(script, isolate));
  }

  for (Handle<Script> script : scripts) {
    // Create and add new script data.
    result->emplace_back(script);
    std::vector<CoverageFunction>* functions = &result->back().functions;

    std::vector<SharedFunctionInfoAndCount> sorted;

    {
      // Sort functions by start position, from outer to inner functions.
      SharedFunctionInfo::ScriptIterator infos(isolate, *script);
      for (Tagged<SharedFunctionInfo> info = infos.Next(); !info.is_null();
           info = infos.Next()) {
        sorted.emplace_back(handle(info, isolate), counter_map.Get(info));
      }
      std::sort(sorted.begin(), sorted.end());
    }

    // Stack to track nested functions, referring function by index.
    std::vector<size_t> nesting;

    // Use sorted list to reconstruct function nesting.
    for (const SharedFunctionInfoAndCount& v : sorted) {
      DirectHandle<SharedFunctionInfo> info = v.info;
      int start = v.start;
      int end = v.end;
      uint32_t count = v.count;

      // Find the correct outer function based on start position.
      //
      // This is, in general, not robust when considering two functions with
      // identical source ranges; then the notion of inner and outer is unclear.
      // Identical source ranges arise when the source range of top-most entity
      // (e.g. function) in the script is identical to the whole script, e.g.
      // <script>function foo() {}<script>. The script has its own shared
      // function info, which has the same source range as the SFI for `foo`.
      // Node.js creates an additional wrapper for scripts (again with identical
      // source range) and those wrappers will have a call count of zero even if
      // the wrapped script was executed (see v8:9212). We mitigate this issue
      // by sorting top-level SFIs first among SFIs with the same source range:
      // This ensures top-level SFIs are processed first. If a top-level SFI has
      // a non-zero call count, it gets recorded due to `function_is_relevant`
      // below (e.g. script wrappers), while top-level SFIs with zero call count
      // do not get reported (this ensures node's extra wrappers do not get
      // reported). If two SFIs with identical source ranges get reported, we
      // report them in decreasing order of call count, as in all known cases
      // this corresponds to the nesting order. In the case of the script tag
      // example above, we report the zero call count of `foo` last. As it turns
      // out, embedders started to rely on functions being reported in nesting
      // order.
      // TODO(jgruber):  Investigate whether it is possible to remove node's
      // extra  top-level wrapper script, or change its source range, or ensure
      // that it follows the invariant that nesting order is descending count
      // order for SFIs with identical source ranges.
      while (!nesting.empty() && functions->at(nesting.back()).end <= start) {
        nesting.pop_back();
      }

      if (count != 0) {
        switch (collectionMode) {
          case v8::debug::CoverageMode::kBlockCount:
          case v8::debug::CoverageMode::kPreciseCount:
            break;
          case v8::debug::CoverageMode::kBlockBinary:
          case v8::debug::CoverageMode::kPreciseBinary:
            count = info->has_reported_binary_coverage() ? 0 : 1;
            info->set_has_reported_binary_coverage(true);
            break;
          case v8::debug::CoverageMode::kBestEffort:
            count = 1;
            break;
        }
      }

      Handle<String> name = SharedFunctionInfo::DebugName(isolate, info);
      CoverageFunction function(start, end, count, name);

      if (IsBlockMode(collectionMode) && info->HasCoverageInfo(isolate)) {
        CollectBlockCoverage(isolate, &function, *info, collectionMode);
      }

      // Only include a function range if itself or its parent function is
      // covered, or if it contains non-trivial block coverage.
      bool is_covered = (count != 0);
      bool parent_is_covered =
          (!nesting.empty() && functions->at(nesting.back()).count != 0);
      bool has_block_coverage = !function.blocks.empty();
      bool function_is_relevant =
          (is_covered || parent_is_covered || has_block_coverage);

      // It must also have a non-empty source range (otherwise it is not
      // interesting to report).
      bool has_nonempty_source_range = function.HasNonEmptySourceRange();

      if (has_nonempty_source_range && function_is_relevant) {
        nesting.push_back(functions->size());
        functions->emplace_back(function);
      }

      if (v8_flags.trace_block_coverage) {
        PrintBlockCoverage(&function, *info, has_nonempty_source_range,
                           function_is_relevant);
      }
    }

    // Remove entries for scripts that have no coverage.
    if (functions->empty()) result->pop_back();
  }
  return result;
}

void Coverage::SelectMode(Isolate* isolate, debug::CoverageMode mode) {
  if (mode != isolate->code_coverage_mode()) {
    // Changing the coverage mode can change the bytecode that would be
    // generated for a function, which can interfere with lazy source positions,
    // so just force source position collection whenever there's such a change.
    isolate->CollectSourcePositionsForAllBytecodeArrays();
    // Changing the coverage mode changes the generated bytecode and hence it is
    // not safe to flush bytecode. Set a flag here, so we can disable bytecode
    // flushing.
    isolate->set_disable_bytecode_flushing(true);
  }

  switch (mode) {
    case debug::CoverageMode::kBestEffort:
      // Note that DevTools switches back to best-effort coverage once the
      // recording is stopped. Since we delete coverage infos at that point, any
      // following coverage recording (without reloads) will be at function
      // granularity.
      isolate->debug()->RemoveAllCoverageInfos();
      isolate->SetFeedbackVectorsForProfilingTools(
          ReadOnlyRoots(isolate).undefined_value());
      break;
    case debug::CoverageMode::kBlockBinary:
    case debug::CoverageMode::kBlockCount:
    case debug::CoverageMode::kPreciseBinary:
    case debug::CoverageMode::kPreciseCount: {
      HandleScope scope(isolate);

      // Remove all optimized function. Optimized and inlined functions do not
      // increment invocation count.
      Deoptimizer::DeoptimizeAll(isolate);

      std::vector<Handle<JSFunction>> funcs_needing_feedback_vector;
      {
        HeapObjectIterator heap_iterator(isolate->heap());
        for (Tagged<HeapObject> o = heap_iterator.Next(); !o.is_null();
             o = heap_iterator.Next()) {
          if (IsJSFunction(o)) {
            Tagged<JSFunction> func = Cast<JSFunction>(o);
            if (func->has_closure_feedback_cell_array()) {
              funcs_needing_feedback_vector.push_back(
                  Handle<JSFunction>(func, isolate));
            }
          } else if (IsBinaryMode(mode) && IsSharedFunctionInfo(o)) {
            // If collecting binary coverage, reset
            // SFI::has_reported_binary_coverage to avoid optimizing / inlining
            // functions before they have reported coverage.
            Tagged<SharedFunctionInfo> shared = Cast<SharedFunctionInfo>(o);
            shared->set_has_reported_binary_coverage(false);
          } else if (IsFeedbackVector(o)) {
            // In any case, clear any collected invocation counts.
            Cast<FeedbackVector>(o)->clear_invocation_count(kRelaxedStore);
          }
        }
      }

      for (DirectHandle<JSFunction> func : funcs_needing_feedback_vector) {
        IsCompiledScope is_compiled_scope(
            func->shared()->is_compiled_scope(isolate));
        CHECK(is_compiled_scope.is_compiled());
        JSFunction::EnsureFeedbackVector(isolate, func, &is_compiled_scope);
      }

      // Root all feedback vectors to avoid early collection.
      isolate->MaybeInitializeVectorListFromHeap();

      break;
    }
  }
  isolate->set_code_coverage_mode(mode);
}

}  // namespace internal
}  // namespace v8
```