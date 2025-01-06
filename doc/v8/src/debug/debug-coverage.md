Response: Let's break down the thought process for analyzing this C++ code and summarizing its functionality, especially concerning its relation to JavaScript.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick skim to identify key terms and data structures. I'd be looking for words like:

* `Coverage`: This is clearly a central concept.
* `Block`, `Range`, `Counter`: These likely represent units of code and their execution counts.
* `SharedFunctionInfo`, `Script`, `JSFunction`: These are V8 internal representations of JavaScript code elements.
* `Isolate`:  The core V8 execution environment.
* `debug`:  Indicates this code is part of debugging or developer tools.
* `Mode`, `Binary`, `Count`, `Precise`, `BestEffort`: These suggest different levels or types of coverage collection.
* `Sort`, `Merge`, `Filter`, `Rewrite`:  These hint at processing steps applied to the coverage data.

**2. Understanding Core Data Structures:**

Next, I'd focus on the major classes and structures to grasp how coverage information is stored:

* **`SharedToCounterMap`:**  A hash map linking `SharedFunctionInfo` (representing a function's compiled code) to an execution count (`uint32_t`). This is crucial for tracking how many times functions are called.
* **`CoverageBlock`:**  Represents a contiguous segment of source code with a `start`, `end`, and `count`. The `start` and `end` are likely source code positions.
* **`CoverageFunction`:**  Encapsulates coverage data for a single JavaScript function. It has its own `start`, `end`, `count` (likely for the whole function), a `name`, and a `std::vector<CoverageBlock>` to store block-level coverage.
* **`Coverage`:**  A top-level class holding coverage data for one or more scripts, containing a `std::vector<ScriptCoverage>` where `ScriptCoverage` likely links a `Script` to a `std::vector<CoverageFunction>`.

**3. Tracing the Data Flow (High-Level):**

I'd then try to follow the general flow of how coverage data is collected:

* **Initialization (`Coverage::SelectMode`)**:  This function sets the coverage mode. It seems to impact how feedback is collected and might even trigger deoptimization.
* **Counting Function Invocations (`CollectAndMaybeResetCounts`)**: This function iterates through `FeedbackVector`s (which store runtime information about functions) or potentially all `JSFunction`s to get invocation counts and store them in `SharedToCounterMap`.
* **Processing Coverage for Scripts (`Coverage::Collect`)**: This is the main collection logic.
    * It iterates through `Script`s.
    * It uses `SharedFunctionInfo::ScriptIterator` to find all functions within a script.
    * It retrieves the invocation count for each function from `SharedToCounterMap`.
    * **Crucially (if `IsBlockMode`):** It calls `CollectBlockCoverage` to gather more granular block-level coverage.
* **Block Coverage Collection (`CollectBlockCoverageInternal`)**:
    * It gets `CoverageInfo` from `SharedFunctionInfo` which likely holds raw block coverage data.
    * It transforms this raw data into a `std::vector<CoverageBlock>`.
    * **Important processing steps:**  `RewriteFunctionScopeCounter`, `FilterAliasedSingletons`, `RewritePositionSingletonsToRanges`, `MergeConsecutiveRanges`, `MergeDuplicateRanges`, `MergeNestedRanges`, `FilterUncoveredRanges`, `FilterEmptyRanges`. These functions refine and clean up the block coverage data.
* **Output (`Coverage` class and potentially `PrintBlockCoverage`):** The collected data is stored in the `Coverage` object.

**4. Identifying the JavaScript Connection:**

The key to linking this C++ code to JavaScript lies in the data structures it manipulates. The presence of:

* `SharedFunctionInfo`: Represents compiled JavaScript functions.
* `Script`: Represents a JavaScript source file.
* `JSFunction`: Represents a JavaScript function object in the V8 heap.
* `FeedbackVector`: Stores runtime feedback about function execution, including invocation counts.

These are all fundamental components of the V8 JavaScript engine. The C++ code interacts with these internal representations to gather execution information.

**5. Constructing JavaScript Examples:**

To illustrate the connection, I'd think of simple JavaScript code snippets that would trigger the different aspects of coverage collection:

* **Function Invocation Count:**  A basic function call demonstrates the counter being incremented.
* **Block Coverage:**  `if/else` statements, loops, and try/catch blocks are excellent examples because they create distinct code blocks with potentially different execution paths.
* **Binary vs. Count Coverage:** A function called once would have a count of 1. In binary mode, it would be marked as covered (1), regardless of how many times it's called after the first.
* **Precise vs. Best-Effort:** The "best-effort" mode description mentioning potential missed counts suggests scenarios where optimized code or functions without allocated feedback vectors might not be fully tracked. A complex, highly optimized application might show differences.

**6. Iterative Refinement:**

After the initial analysis, I'd reread the code more carefully, paying attention to the details of the processing steps in `CollectBlockCoverageInternal`. This helps understand *how* the raw data is transformed into the final coverage report. For instance, recognizing that singletons are rewritten to ranges is an important detail.

**7. Structuring the Summary:**

Finally, I'd organize the findings into a clear and concise summary, covering:

* **Core Functionality:** The main purpose of the file.
* **Key Mechanisms:** How it achieves its goal (e.g., using `SharedFunctionInfo`, `CoverageBlock`).
* **Relationship to JavaScript:** Concrete examples showing how JavaScript code relates to the coverage data.
* **Different Coverage Modes:** Explaining the variations in collection granularity.

By following these steps, I can systematically analyze the C++ code and effectively explain its role in generating JavaScript code coverage information.
这个C++源代码文件 `v8/src/debug/debug-coverage.cc` 的主要功能是 **收集 JavaScript 代码的覆盖率信息**。它实现了 V8 引擎中用于跟踪代码执行情况，并生成关于哪些代码被执行以及执行了多少次的报告。

**核心功能归纳:**

1. **定义数据结构:**
   - `SharedToCounterMap`: 用于存储每个 `SharedFunctionInfo`（代表一个函数）的调用计数。
   - `CoverageBlock`:  表示代码中的一个块，记录其起始位置、结束位置和执行次数。
   - `CoverageFunction`:  表示一个函数的覆盖率信息，包含函数的起始位置、结束位置、调用次数以及包含的 `CoverageBlock` 列表。
   - `Coverage`:  表示整个脚本或模块的覆盖率信息，包含多个 `CoverageFunction`。

2. **收集调用计数:**
   - 使用 `SharedToCounterMap` 跟踪每个 JavaScript 函数的调用次数。
   - 可以从 `FeedbackVector` 中获取精确的调用计数（在精确模式下）。
   - 在 "尽力而为" 模式下，可能通过遍历堆栈或函数对象来估算调用计数。

3. **收集块级覆盖率信息 (Block Coverage):**
   -  当启用块级覆盖率模式时，会更细粒度地跟踪代码块的执行情况。
   - `GetSortedBlockData` 函数从 `CoverageInfo` 对象中提取已排序的代码块信息。
   - `CoverageBlockIterator` 类用于方便地遍历和修改代码块列表。
   - 包含一系列用于处理和优化块级覆盖率数据的函数，例如：
     - `MergeDuplicateRanges`: 合并重复的范围。
     - `RewritePositionSingletonsToRanges`: 将单点位置转换为范围。
     - `MergeConsecutiveRanges`: 合并连续的范围。
     - `MergeNestedRanges`: 合并嵌套的范围。
     - `FilterUncoveredRanges`: 过滤未覆盖的范围。
     - `FilterEmptyRanges`: 过滤空范围。

4. **支持多种覆盖率模式:**
   - `kBlockBinary`: 块级二进制覆盖率 (0 或 1)。
   - `kBlockCount`: 块级计数覆盖率。
   - `kPreciseBinary`: 精确二进制覆盖率。
   - `kPreciseCount`: 精确计数覆盖率。
   - `kBestEffort`: 尽力而为的覆盖率。

5. **与 JavaScript 的关系:**
   - 该文件直接操作 V8 引擎内部的 JavaScript 代码表示，如 `SharedFunctionInfo`、`Script` 和 `JSFunction`。
   - 通过访问 `FeedbackVector` 来获取函数的运行时信息。
   - 最终生成的覆盖率报告反映了 JavaScript 代码的执行情况。

**JavaScript 示例说明:**

假设我们有以下 JavaScript 代码：

```javascript
function add(a, b) {
  if (a > 0) {
    console.log("a is positive");
    return a + b;
  } else {
    console.log("a is not positive");
    return b - a;
  }
}

add(5, 2); // 调用一次，a > 0 的分支会被执行
```

当启用代码覆盖率后，`debug-coverage.cc` 会收集以下信息：

- **函数级覆盖率:**
  - 函数 `add` 被调用了一次。

- **块级覆盖率 (如果启用):**
  - `if (a > 0)` 这个条件语句会被执行一次。
  - `console.log("a is positive");` 这个语句会被执行一次。
  - `return a + b;` 这个语句会被执行一次。
  - `else { ... }` 代码块会被跳过（因为 `a` 是正数）。
  - `console.log("a is not positive");` 这个语句不会被执行。
  - `return b - a;` 这个语句不会被执行。

**在 JavaScript 中，我们可以通过 V8 提供的调试 API 或开发者工具来获取这些覆盖率信息。例如，在 Chrome 开发者工具中，我们可以看到代码覆盖率报告，它会高亮显示哪些代码被执行了，哪些没有被执行。**

**更具体的 JavaScript 交互 (理论上，因为直接操作内部 C++ 不常用):**

虽然我们不能直接从 JavaScript 调用 `debug-coverage.cc` 中的 C++ 函数，但 V8 引擎会将收集到的覆盖率数据暴露给 JavaScript 环境，以便开发者使用。例如，V8 的调试 API 可能提供方法来启动覆盖率收集、获取覆盖率报告等。

例如，在 Node.js 环境中，可以使用 `v8-profiler` 或类似的工具来获取代码覆盖率信息，这些工具的底层实现很可能就依赖于像 `debug-coverage.cc` 这样的 V8 内部机制。

总而言之，`v8/src/debug/debug-coverage.cc` 是 V8 引擎中负责实现代码覆盖率收集的核心组件，它通过跟踪 JavaScript 代码的执行情况，为开发者提供代码执行的详细信息，帮助他们进行测试和代码优化。

Prompt: 
```
这是目录为v8/src/debug/debug-coverage.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```