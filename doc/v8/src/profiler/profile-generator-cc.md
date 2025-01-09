Response:
The user wants a summary of the functionality of the provided C++ code, which is part of the V8 JavaScript engine. I need to go through the code and identify the main components and their purposes. I should also address the specific questions about .tq files, JavaScript relation, code logic, common programming errors, and provide examples where applicable.

Here's a plan:
1. **Identify Core Classes:**  Look for the primary classes and their member functions.
2. **Analyze Functionality:** Describe what each class and its methods do.
3. **Address .tq question:** Explain what a .tq file is in the V8 context.
4. **JavaScript Relation:** Explain how this code relates to JavaScript profiling and provide a JavaScript example.
5. **Code Logic:**  Choose a part of the code with logic and provide a hypothetical input and output.
6. **Common Errors:**  Think about potential programming errors related to the code's functionality.
7. **Summarize Functionality:** Provide a concise summary of the overall purpose of the code.
这是V8源代码文件 `v8/src/profiler/profile-generator.cc` 的第一部分。从代码内容来看，它主要负责 **生成和管理 CPU 性能剖析数据**。

以下是代码中主要组成部分的功能归纳：

**1. `SourcePositionTable`:**

*   **功能:**  存储程序计数器 (PC) 偏移量与源代码行号以及内联 ID 之间的映射关系。这对于在性能剖析结果中将机器码指令关联回源代码至关重要。
*   **核心方法:**
    *   `SetPosition(int pc_offset, int line, int inlining_id)`:  添加一个新的 PC 偏移量到源代码位置的映射。
    *   `GetSourceLineNumber(int pc_offset) const`:  根据 PC 偏移量获取对应的源代码行号。
    *   `GetInliningId(int pc_offset) const`: 根据 PC 偏移量获取对应的内联 ID。

**2. `CodeEntry`:**

*   **功能:**  代表代码的条目，例如函数、内置函数、脚本代码等。它存储了代码的各种属性，如名称、资源名称（文件名）、行号、列号、脚本 ID、位置信息、去优化信息等。
*   **核心属性/方法:**
    *   不同的静态方法 (如 `program_entry()`, `idle_entry()`, `gc_entry()`) 返回预定义的 `CodeEntry` 对象，用于表示特殊的代码执行状态。
    *   `GetHash()`: 计算 `CodeEntry` 的哈希值，用于高效地存储和查找。
    *   `IsSameFunctionAs(const CodeEntry* entry) const`:  判断两个 `CodeEntry` 是否代表同一个函数。
    *   `SetBuiltinId(Builtin id)`:  设置内置函数的 ID。
    *   `GetSourceLine(int pc_offset) const`:  通过内部的 `SourcePositionTable` 获取指定 PC 偏移量的源代码行号。
    *   `SetInlineStacks(...)`: 存储内联函数的栈信息。
    *   `GetInlineStack(int pc_offset) const`: 获取指定 PC 偏移量的内联栈信息。
    *   `set_deopt_info(...)`:  记录代码去优化的原因和相关信息。
    *   `FillFunctionInfo(Tagged<SharedFunctionInfo> shared)`: 从 `SharedFunctionInfo` 对象填充 `CodeEntry` 的信息。
    *   `GetDeoptInfo()`:  返回代码的去优化信息。

**3. `ProfileNode`:**

*   **功能:**  表示性能剖析树中的一个节点。每个节点都关联一个 `CodeEntry`，并存储了该代码被执行的次数（`self_ticks_`）以及其子节点的集合。它还存储了每行代码的执行次数 (`line_ticks_`) 和去优化信息 (`deopt_infos_`).
*   **核心方法:**
    *   `FindChild(CodeEntry* entry, int line_number)`:  查找指定 `CodeEntry` 和行号的子节点。
    *   `FindOrAddChild(CodeEntry* entry, int line_number)`:  查找或添加指定 `CodeEntry` 和行号的子节点。
    *   `IncrementLineTicks(int src_line)`:  增加特定源代码行的执行计数。
    *   `GetLineTicks(...)`:  获取每行代码的执行计数。
    *   `CollectDeoptInfo(CodeEntry* entry)`: 收集并存储代码的去优化信息。

**4. `ProfileTree`:**

*   **功能:**  表示整个性能剖析树。它维护了根节点，并提供了添加路径（调用栈）的功能。
*   **核心方法:**
    *   `AddPathFromEnd(...)`:  从调用栈的末尾开始，向性能剖析树中添加路径。

**5. `ContextFilter`:**

*   **功能:** 用于过滤特定上下文的性能剖析数据。

**6. `CpuProfilesCollection` 和 `CpuProfile`:**

*   **功能:** `CpuProfile` 代表一个正在进行的 CPU 性能剖析会话。它存储了剖析的配置选项、开始和结束时间、以及构建的性能剖析树 (`top_down_`) 和采样数据 (`samples_`). `CpuProfilesCollection` 可能是用于管理多个 `CpuProfile` 实例的集合，但在提供的代码片段中没有完全展示。
*   **核心方法 (在 `CpuProfile` 中):**
    *   `AddPath(...)`:  向性能剖析树添加一个调用栈样本。
    *   `StreamPendingTraceEvents()`:  将待处理的剖析数据以 Trace Event 的形式输出。
    *   `FinishProfile()`:  完成性能剖析会话。

**7. `CpuProfileJSONSerializer`:**

*   **功能:**  将 `CpuProfile` 的数据序列化为 JSON 格式。这使得性能剖析数据可以被外部工具（如 Chrome DevTools）解析和可视化。

**关于 .tq 结尾的文件:**

如果 `v8/src/profiler/profile-generator.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，尤其是用于实现内置函数和运行时功能。

**与 JavaScript 的关系 (并用 JavaScript 举例说明):**

`v8/src/profiler/profile-generator.cc` 的核心功能是为 JavaScript 代码的执行生成性能剖析数据。当你使用 Chrome DevTools 或 Node.js 的 `--cpu-profile` 标志进行性能分析时，V8 引擎内部就会使用这里的代码来记录 JavaScript 代码的调用栈、执行时间等信息。

**JavaScript 示例:**

```javascript
function outerFunction() {
  innerFunction();
}

function innerFunction() {
  for (let i = 0; i < 100000; i++) {
    // 一些计算密集的操作
  }
}

outerFunction();
```

当你对此代码进行 CPU 性能剖析时，`ProfileGenerator` 相关的代码会记录 `outerFunction` 调用 `innerFunction` 的信息，以及 `innerFunction` 内部循环的执行情况。`SourcePositionTable` 会将执行的机器码地址映射回 `outerFunction` 和 `innerFunction` 的源代码行号。最终生成的剖析数据会显示 `innerFunction` 因为其循环而消耗了大部分 CPU 时间。

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 调用栈：

```
outerFn -> middleFn -> innerFn
```

并且在性能剖析期间，采样到了 `innerFn` 的执行。

**假设输入:**

*   `ProfileTree` 对象。
*   一个包含 `CodeEntry` 指针的 `std::vector<CodeEntry*>`，代表调用栈：`[CodeEntry for outerFn, CodeEntry for middleFn, CodeEntry for innerFn]`.
*   `src_line` (当前执行代码的行号，例如 `innerFn` 中的某行)。

**输出 (调用 `AddPathFromEnd` 后):**

*   性能剖析树 (`ProfileTree`) 中会添加一条从根节点到 `innerFn` 节点的路径：
    *   `root` -> `outerFn` 的 `ProfileNode` -> `middleFn` 的 `ProfileNode` -> `innerFn` 的 `ProfileNode`。
*   `innerFn` 对应的 `ProfileNode` 的 `self_ticks_` 计数器会增加。
*   `innerFn` 对应的 `ProfileNode` 的 `line_ticks_` 映射中，`src_line` 对应的计数器会增加。

**涉及用户常见的编程错误:**

虽然这个 C++ 代码本身是 V8 引擎的内部实现，但它所生成的性能剖析数据可以帮助开发者发现 JavaScript 代码中的一些常见编程错误，例如：

1. **意外的同步阻塞:** 如果性能剖析显示某个 JavaScript 函数（例如处理 I/O 操作的函数）占据了大量的 CPU 时间，可能意味着存在没有使用异步操作而导致的同步阻塞。
2. **不必要的计算密集操作:** 性能剖析可以帮助识别代码中的瓶颈，例如在循环中执行了不必要的计算或操作。
3. **频繁的垃圾回收:** 虽然 `ProfileGenerator` 主要关注 CPU 性能，但过多的垃圾回收也会影响性能。通过观察性能剖析结果中垃圾回收相关条目的占比，可以帮助开发者识别可能导致频繁垃圾回收的代码模式（例如，频繁创建大量临时对象）。
4. **性能不佳的正则表达式:** 如果性能剖析显示某个正则表达式匹配操作消耗了大量 CPU 时间，可能需要优化该正则表达式。

**第 1 部分功能归纳:**

总而言之，`v8/src/profiler/profile-generator.cc` 的第一部分定义了用于构建 CPU 性能剖析数据的核心数据结构和逻辑。它负责：

*   维护源代码位置信息 (`SourcePositionTable`).
*   表示不同的代码执行单元 (`CodeEntry`).
*   构建性能剖析树 (`ProfileNode`, `ProfileTree`).
*   管理性能剖析会话 (`CpuProfile`).
*   处理上下文过滤 (`ContextFilter`).
*   为性能剖析数据提供 JSON 序列化功能 (`CpuProfileJSONSerializer`).

这些组件共同协作，为 V8 引擎提供强大的 CPU 性能分析能力，帮助开发者理解和优化 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/profiler/profile-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/profile-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/profiler/profile-generator.h"

#include <algorithm>
#include <vector>

#include "include/v8-profiler.h"
#include "src/base/lazy-instance.h"
#include "src/codegen/source-position.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/profiler/cpu-profiler.h"
#include "src/profiler/output-stream-writer.h"
#include "src/profiler/profile-generator-inl.h"
#include "src/profiler/profiler-stats.h"
#include "src/tracing/trace-event.h"
#include "src/tracing/traced-value.h"

namespace v8 {
namespace internal {

void SourcePositionTable::SetPosition(int pc_offset, int line,
                                      int inlining_id) {
  DCHECK_GE(pc_offset, 0);
  DCHECK_GT(line, 0);  // The 1-based number of the source line.
  // It's possible that we map multiple source positions to a pc_offset in
  // optimized code. Usually these map to the same line, so there is no
  // difference here as we only store line number and not line/col in the form
  // of a script offset. Ignore any subsequent sets to the same offset.
  if (!pc_offsets_to_lines_.empty() &&
      pc_offsets_to_lines_.back().pc_offset == pc_offset) {
    return;
  }
  // Check that we are inserting in ascending order, so that the vector remains
  // sorted.
  DCHECK(pc_offsets_to_lines_.empty() ||
         pc_offsets_to_lines_.back().pc_offset < pc_offset);
  if (pc_offsets_to_lines_.empty() ||
      pc_offsets_to_lines_.back().line_number != line ||
      pc_offsets_to_lines_.back().inlining_id != inlining_id) {
    pc_offsets_to_lines_.push_back({pc_offset, line, inlining_id});
  }
}

int SourcePositionTable::GetSourceLineNumber(int pc_offset) const {
  if (pc_offsets_to_lines_.empty()) {
    return v8::CpuProfileNode::kNoLineNumberInfo;
  }
  auto it = std::lower_bound(
      pc_offsets_to_lines_.begin(), pc_offsets_to_lines_.end(),
      SourcePositionTuple{pc_offset, 0, SourcePosition::kNotInlined});
  if (it != pc_offsets_to_lines_.begin()) --it;
  return it->line_number;
}

int SourcePositionTable::GetInliningId(int pc_offset) const {
  if (pc_offsets_to_lines_.empty()) {
    return SourcePosition::kNotInlined;
  }
  auto it = std::lower_bound(
      pc_offsets_to_lines_.begin(), pc_offsets_to_lines_.end(),
      SourcePositionTuple{pc_offset, 0, SourcePosition::kNotInlined});
  if (it != pc_offsets_to_lines_.begin()) --it;
  return it->inlining_id;
}

size_t SourcePositionTable::Size() const {
  return sizeof(*this) + pc_offsets_to_lines_.capacity() *
                             sizeof(decltype(pc_offsets_to_lines_)::value_type);
}

void SourcePositionTable::print() const {
  base::OS::Print(" - source position table at %p\n", this);
  for (const SourcePositionTuple& pos_info : pc_offsets_to_lines_) {
    base::OS::Print("    %d --> line_number: %d inlining_id: %d\n",
                    pos_info.pc_offset, pos_info.line_number,
                    pos_info.inlining_id);
  }
}

const char* const CodeEntry::kEmptyResourceName = "";
const char* const CodeEntry::kEmptyBailoutReason = "";
const char* const CodeEntry::kNoDeoptReason = "";

const char* const CodeEntry::kProgramEntryName = "(program)";
const char* const CodeEntry::kIdleEntryName = "(idle)";
const char* const CodeEntry::kGarbageCollectorEntryName = "(garbage collector)";
const char* const CodeEntry::kUnresolvedFunctionName = "(unresolved function)";
const char* const CodeEntry::kRootEntryName = "(root)";

// static
CodeEntry* CodeEntry::program_entry() {
  static base::LeakyObject<CodeEntry> kProgramEntry(
      LogEventListener::CodeTag::kFunction, CodeEntry::kProgramEntryName,
      CodeEntry::kEmptyResourceName, v8::CpuProfileNode::kNoLineNumberInfo,
      v8::CpuProfileNode::kNoColumnNumberInfo, nullptr, false,
      CodeEntry::CodeType::OTHER);
  return kProgramEntry.get();
}

// static
CodeEntry* CodeEntry::idle_entry() {
  static base::LeakyObject<CodeEntry> kIdleEntry(
      LogEventListener::CodeTag::kFunction, CodeEntry::kIdleEntryName,
      CodeEntry::kEmptyResourceName, v8::CpuProfileNode::kNoLineNumberInfo,
      v8::CpuProfileNode::kNoColumnNumberInfo, nullptr, false,
      CodeEntry::CodeType::OTHER);
  return kIdleEntry.get();
}

// static
CodeEntry* CodeEntry::gc_entry() {
  static base::LeakyObject<CodeEntry> kGcEntry(
      LogEventListener::CodeTag::kBuiltin,
      CodeEntry::kGarbageCollectorEntryName, CodeEntry::kEmptyResourceName,
      v8::CpuProfileNode::kNoLineNumberInfo,
      v8::CpuProfileNode::kNoColumnNumberInfo, nullptr, false,
      CodeEntry::CodeType::OTHER);
  return kGcEntry.get();
}

// static
CodeEntry* CodeEntry::unresolved_entry() {
  static base::LeakyObject<CodeEntry> kUnresolvedEntry(
      LogEventListener::CodeTag::kFunction, CodeEntry::kUnresolvedFunctionName,
      CodeEntry::kEmptyResourceName, v8::CpuProfileNode::kNoLineNumberInfo,
      v8::CpuProfileNode::kNoColumnNumberInfo, nullptr, false,
      CodeEntry::CodeType::OTHER);
  return kUnresolvedEntry.get();
}

// static
CodeEntry* CodeEntry::root_entry() {
  static base::LeakyObject<CodeEntry> kRootEntry(
      LogEventListener::CodeTag::kFunction, CodeEntry::kRootEntryName,
      CodeEntry::kEmptyResourceName, v8::CpuProfileNode::kNoLineNumberInfo,
      v8::CpuProfileNode::kNoColumnNumberInfo, nullptr, false,
      CodeEntry::CodeType::OTHER);
  return kRootEntry.get();
}

uint32_t CodeEntry::GetHash() const {
  uint32_t hash = 0;
  if (script_id_ != v8::UnboundScript::kNoScriptId) {
    hash ^= ComputeUnseededHash(static_cast<uint32_t>(script_id_));
    hash ^= ComputeUnseededHash(static_cast<uint32_t>(position_));
  } else {
    hash ^= ComputeUnseededHash(
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(name_)));
    hash ^= ComputeUnseededHash(
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(resource_name_)));
    hash ^= ComputeUnseededHash(line_number_);
  }
  return hash;
}

bool CodeEntry::IsSameFunctionAs(const CodeEntry* entry) const {
  if (this == entry) return true;
  if (script_id_ != v8::UnboundScript::kNoScriptId) {
    return script_id_ == entry->script_id_ && position_ == entry->position_;
  }
  return name_ == entry->name_ && resource_name_ == entry->resource_name_ &&
         line_number_ == entry->line_number_;
}

void CodeEntry::SetBuiltinId(Builtin id) {
  bit_field_ =
      CodeTagField::update(bit_field_, LogEventListener::CodeTag::kBuiltin);
  bit_field_ = BuiltinField::update(bit_field_, id);
}

int CodeEntry::GetSourceLine(int pc_offset) const {
  if (line_info_) return line_info_->GetSourceLineNumber(pc_offset);
  return v8::CpuProfileNode::kNoLineNumberInfo;
}

void CodeEntry::SetInlineStacks(
    std::unordered_set<CodeEntry*, Hasher, Equals> inline_entries,
    std::unordered_map<int, std::vector<CodeEntryAndLineNumber>>
        inline_stacks) {
  EnsureRareData()->inline_entries_ = std::move(inline_entries);
  rare_data_->inline_stacks_ = std::move(inline_stacks);
}

const std::vector<CodeEntryAndLineNumber>* CodeEntry::GetInlineStack(
    int pc_offset) const {
  if (!line_info_) return nullptr;

  int inlining_id = line_info_->GetInliningId(pc_offset);
  if (inlining_id == SourcePosition::kNotInlined) return nullptr;
  DCHECK(rare_data_);

  auto it = rare_data_->inline_stacks_.find(inlining_id);
  return it != rare_data_->inline_stacks_.end() ? &it->second : nullptr;
}

void CodeEntry::set_deopt_info(
    const char* deopt_reason, int deopt_id,
    std::vector<CpuProfileDeoptFrame> inlined_frames) {
  RareData* rare_data = EnsureRareData();
  rare_data->deopt_reason_ = deopt_reason;
  rare_data->deopt_id_ = deopt_id;
  rare_data->deopt_inlined_frames_ = std::move(inlined_frames);
}

void CodeEntry::FillFunctionInfo(Tagged<SharedFunctionInfo> shared) {
  if (!IsScript(shared->script())) return;
  Tagged<Script> script = Cast<Script>(shared->script());
  set_script_id(script->id());
  set_position(shared->StartPosition());
  if (shared->optimization_disabled()) {
    set_bailout_reason(
        GetBailoutReason(shared->disabled_optimization_reason()));
  }
}

size_t CodeEntry::EstimatedSize() const {
  size_t estimated_size = 0;
  if (rare_data_) {
    estimated_size += sizeof(rare_data_.get());

    for (const auto& inline_entry : rare_data_->inline_entries_) {
      estimated_size += inline_entry->EstimatedSize();
    }
    estimated_size += rare_data_->inline_entries_.size() *
                      sizeof(decltype(rare_data_->inline_entries_)::value_type);

    for (const auto& inline_stack_pair : rare_data_->inline_stacks_) {
      estimated_size += inline_stack_pair.second.size() *
                        sizeof(decltype(inline_stack_pair.second)::value_type);
    }
    estimated_size +=
        rare_data_->inline_stacks_.size() *
        (sizeof(decltype(rare_data_->inline_stacks_)::key_type) +
         sizeof(decltype(rare_data_->inline_stacks_)::value_type));

    estimated_size +=
        rare_data_->deopt_inlined_frames_.capacity() *
        sizeof(decltype(rare_data_->deopt_inlined_frames_)::value_type);
  }

  if (line_info_) {
    estimated_size += line_info_->Size();
  }
  return sizeof(*this) + estimated_size;
}

CpuProfileDeoptInfo CodeEntry::GetDeoptInfo() {
  DCHECK(has_deopt_info());

  CpuProfileDeoptInfo info;
  info.deopt_reason = rare_data_->deopt_reason_;
  DCHECK_NE(kNoDeoptimizationId, rare_data_->deopt_id_);
  if (rare_data_->deopt_inlined_frames_.empty()) {
    info.stack.push_back(CpuProfileDeoptFrame(
        {script_id_, static_cast<size_t>(std::max(0, position()))}));
  } else {
    info.stack = rare_data_->deopt_inlined_frames_;
  }
  return info;
}

CodeEntry::RareData* CodeEntry::EnsureRareData() {
  if (!rare_data_) {
    rare_data_.reset(new RareData());
  }
  return rare_data_.get();
}

void CodeEntry::ReleaseStrings(StringsStorage& strings) {
  DCHECK_EQ(ref_count_, 0UL);

  if (name_) {
    strings.Release(name_);
    name_ = nullptr;
  }
  if (resource_name_) {
    strings.Release(resource_name_);
    resource_name_ = nullptr;
  }
}

void CodeEntry::print() const {
  base::OS::Print("CodeEntry: at %p\n", this);

  base::OS::Print(" - name: %s\n", name_);
  base::OS::Print(" - resource_name: %s\n", resource_name_);
  base::OS::Print(" - line_number: %d\n", line_number_);
  base::OS::Print(" - column_number: %d\n", column_number_);
  base::OS::Print(" - script_id: %d\n", script_id_);
  base::OS::Print(" - position: %d\n", position_);

  if (line_info_) {
    line_info_->print();
  }

  if (rare_data_) {
    base::OS::Print(" - deopt_reason: %s\n", rare_data_->deopt_reason_);
    base::OS::Print(" - bailout_reason: %s\n", rare_data_->bailout_reason_);
    base::OS::Print(" - deopt_id: %d\n", rare_data_->deopt_id_);

    if (!rare_data_->inline_stacks_.empty()) {
      base::OS::Print(" - inline stacks:\n");
      for (auto it = rare_data_->inline_stacks_.begin();
           it != rare_data_->inline_stacks_.end(); it++) {
        base::OS::Print("    inlining_id: [%d]\n", it->first);
        for (const auto& e : it->second) {
          base::OS::Print("     %s --> %d\n", e.code_entry->name(),
                          e.line_number);
        }
      }
    } else {
      base::OS::Print(" - inline stacks: (empty)\n");
    }

    if (!rare_data_->deopt_inlined_frames_.empty()) {
      base::OS::Print(" - deopt inlined frames:\n");
      for (const CpuProfileDeoptFrame& frame :
           rare_data_->deopt_inlined_frames_) {
        base::OS::Print("script_id: %d position: %zu\n", frame.script_id,
                        frame.position);
      }
    } else {
      base::OS::Print(" - deopt inlined frames: (empty)\n");
    }
  }
  base::OS::Print("\n");
}

ProfileNode::~ProfileNode() {
  if (tree_->code_entries()) tree_->code_entries()->DecRef(entry_);
}

CpuProfileNode::SourceType ProfileNode::source_type() const {
  // Handle metadata and VM state code entry types.
  if (entry_ == CodeEntry::program_entry() ||
      entry_ == CodeEntry::idle_entry() || entry_ == CodeEntry::gc_entry() ||
      entry_ == CodeEntry::root_entry()) {
    return CpuProfileNode::kInternal;
  }
  if (entry_ == CodeEntry::unresolved_entry())
    return CpuProfileNode::kUnresolved;

  // Otherwise, resolve based on logger tag.
  switch (entry_->code_tag()) {
    case LogEventListener::CodeTag::kEval:
    case LogEventListener::CodeTag::kScript:
    case LogEventListener::CodeTag::kFunction:
      return CpuProfileNode::kScript;
    case LogEventListener::CodeTag::kBuiltin:
    case LogEventListener::CodeTag::kHandler:
    case LogEventListener::CodeTag::kBytecodeHandler:
    case LogEventListener::CodeTag::kNativeFunction:
    case LogEventListener::CodeTag::kNativeScript:
      return CpuProfileNode::kBuiltin;
    case LogEventListener::CodeTag::kCallback:
      return CpuProfileNode::kCallback;
    case LogEventListener::CodeTag::kRegExp:
    case LogEventListener::CodeTag::kStub:
    case LogEventListener::CodeTag::kLength:
      return CpuProfileNode::kInternal;
  }
  return CpuProfileNode::kInternal;
  UNREACHABLE();
}

void ProfileNode::CollectDeoptInfo(CodeEntry* entry) {
  deopt_infos_.push_back(entry->GetDeoptInfo());
  entry->clear_deopt_info();
}

ProfileNode* ProfileNode::FindChild(CodeEntry* entry, int line_number) {
  auto map_entry = children_.find({entry, line_number});
  return map_entry != children_.end() ? map_entry->second : nullptr;
}

ProfileNode* ProfileNode::FindOrAddChild(CodeEntry* entry, int line_number) {
  auto map_entry = children_.find({entry, line_number});
  if (map_entry == children_.end()) {
    ProfileNode* node = new ProfileNode(tree_, entry, this, line_number);
    children_[{entry, line_number}] = node;
    children_list_.push_back(node);
    return node;
  } else {
    return map_entry->second;
  }
}


void ProfileNode::IncrementLineTicks(int src_line) {
  if (src_line == v8::CpuProfileNode::kNoLineNumberInfo) return;
  // Increment a hit counter of a certain source line.
  // Add a new source line if not found.
  auto map_entry = line_ticks_.find(src_line);
  if (map_entry == line_ticks_.end()) {
    line_ticks_[src_line] = 1;
  } else {
    line_ticks_[src_line]++;
  }
}


bool ProfileNode::GetLineTicks(v8::CpuProfileNode::LineTick* entries,
                               unsigned int length) const {
  if (entries == nullptr || length == 0) return false;

  unsigned line_count = static_cast<unsigned>(line_ticks_.size());

  if (line_count == 0) return true;
  if (length < line_count) return false;

  v8::CpuProfileNode::LineTick* entry = entries;

  for (auto p = line_ticks_.begin(); p != line_ticks_.end(); p++, entry++) {
    entry->line = p->first;
    entry->hit_count = p->second;
  }

  return true;
}

void ProfileNode::Print(int indent) const {
  int line_number = line_number_ != 0 ? line_number_ : entry_->line_number();
  base::OS::Print("%5u %*s %s:%d %d %d #%d", self_ticks_, indent, "",
                  entry_->name(), line_number, source_type(),
                  entry_->script_id(), id());
  if (entry_->resource_name()[0] != '\0')
    base::OS::Print(" %s:%d", entry_->resource_name(), entry_->line_number());
  base::OS::Print("\n");
  for (const CpuProfileDeoptInfo& info : deopt_infos_) {
    base::OS::Print(
        "%*s;;; deopted at script_id: %d position: %zu with reason '%s'.\n",
        indent + 10, "", info.stack[0].script_id, info.stack[0].position,
        info.deopt_reason);
    for (size_t index = 1; index < info.stack.size(); ++index) {
      base::OS::Print("%*s;;;     Inline point: script_id %d position: %zu.\n",
                      indent + 10, "", info.stack[index].script_id,
                      info.stack[index].position);
    }
  }
  const char* bailout_reason = entry_->bailout_reason();
  if (bailout_reason != GetBailoutReason(BailoutReason::kNoReason) &&
      bailout_reason != CodeEntry::kEmptyBailoutReason) {
    base::OS::Print("%*s bailed out due to '%s'\n", indent + 10, "",
                    bailout_reason);
  }
  for (auto child : children_) {
    child.second->Print(indent + 2);
  }
}

class DeleteNodesCallback {
 public:
  void BeforeTraversingChild(ProfileNode*, ProfileNode*) { }

  void AfterAllChildrenTraversed(ProfileNode* node) { delete node; }

  void AfterChildTraversed(ProfileNode*, ProfileNode*) { }
};

ProfileTree::ProfileTree(Isolate* isolate, CodeEntryStorage* storage)
    : next_node_id_(1),
      isolate_(isolate),
      code_entries_(storage),
      root_(new ProfileNode(this, CodeEntry::root_entry(), nullptr)) {}

ProfileTree::~ProfileTree() {
  DeleteNodesCallback cb;
  TraverseDepthFirst(&cb);
}

ProfileNode* ProfileTree::AddPathFromEnd(const std::vector<CodeEntry*>& path,
                                         int src_line, bool update_stats) {
  ProfileNode* node = root_;
  CodeEntry* last_entry = nullptr;
  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    if (*it == nullptr) continue;
    last_entry = *it;
    node = node->FindOrAddChild(*it, v8::CpuProfileNode::kNoLineNumberInfo);
  }
  if (last_entry && last_entry->has_deopt_info()) {
    node->CollectDeoptInfo(last_entry);
  }
  if (update_stats) {
    node->IncrementSelfTicks();
    if (src_line != v8::CpuProfileNode::kNoLineNumberInfo) {
      node->IncrementLineTicks(src_line);
    }
  }
  return node;
}

ProfileNode* ProfileTree::AddPathFromEnd(const ProfileStackTrace& path,
                                         int src_line, bool update_stats,
                                         ProfilingMode mode) {
  ProfileNode* node = root_;
  CodeEntry* last_entry = nullptr;
  int parent_line_number = v8::CpuProfileNode::kNoLineNumberInfo;
  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    if (it->code_entry == nullptr) continue;
    last_entry = it->code_entry;
    node = node->FindOrAddChild(it->code_entry, parent_line_number);
    parent_line_number = mode == ProfilingMode::kCallerLineNumbers
                             ? it->line_number
                             : v8::CpuProfileNode::kNoLineNumberInfo;
  }
  if (last_entry && last_entry->has_deopt_info()) {
    node->CollectDeoptInfo(last_entry);
  }
  if (update_stats) {
    node->IncrementSelfTicks();
    if (src_line != v8::CpuProfileNode::kNoLineNumberInfo) {
      node->IncrementLineTicks(src_line);
    }
  }
  return node;
}

class Position {
 public:
  explicit Position(ProfileNode* node)
      : node(node), child_idx_(0) { }
  V8_INLINE ProfileNode* current_child() {
    return node->children()->at(child_idx_);
  }
  V8_INLINE bool has_current_child() {
    return child_idx_ < static_cast<int>(node->children()->size());
  }
  V8_INLINE void next_child() { ++child_idx_; }

  ProfileNode* node;
 private:
  int child_idx_;
};


// Non-recursive implementation of a depth-first post-order tree traversal.
template <typename Callback>
void ProfileTree::TraverseDepthFirst(Callback* callback) {
  std::vector<Position> stack;
  stack.emplace_back(root_);
  while (!stack.empty()) {
    Position& current = stack.back();
    if (current.has_current_child()) {
      callback->BeforeTraversingChild(current.node, current.current_child());
      stack.emplace_back(current.current_child());
    } else {
      callback->AfterAllChildrenTraversed(current.node);
      if (stack.size() > 1) {
        Position& parent = stack[stack.size() - 2];
        callback->AfterChildTraversed(parent.node, current.node);
        parent.next_child();
      }
      // Remove child from the stack.
      stack.pop_back();
    }
  }
}

void ContextFilter::OnMoveEvent(Address from_address, Address to_address) {
  if (native_context_address() != from_address) return;

  set_native_context_address(to_address);
}

using v8::tracing::TracedValue;

std::atomic<ProfilerId> CpuProfilesCollection::last_id_{0};

CpuProfile::CpuProfile(CpuProfiler* profiler, ProfilerId id, const char* title,
                       CpuProfilingOptions options,
                       std::unique_ptr<DiscardedSamplesDelegate> delegate)
    : title_(title),
      options_(std::move(options)),
      delegate_(std::move(delegate)),
      start_time_(base::TimeTicks::Now()),
      top_down_(profiler->isolate(), profiler->code_entries()),
      profiler_(profiler),
      streaming_next_sample_(0),
      id_(id) {
  // The startTime timestamp is not converted to Perfetto's clock domain and
  // will get out of sync with other timestamps Perfetto knows about, including
  // the automatic trace event "ts" timestamp. startTime is included for
  // backward compatibility with the tracing protocol but the value of "ts"
  // should be used instead (it is recorded nearly immediately after).
  auto value = TracedValue::Create();
  value->SetDouble("startTime", start_time_.since_origin().InMicroseconds());
  TRACE_EVENT_SAMPLE_WITH_ID1(TRACE_DISABLED_BY_DEFAULT("v8.cpu_profiler"),
                              "Profile", id_, "data", std::move(value));

  DisallowHeapAllocation no_gc;
  if (delegate_) {
    delegate_->SetId(id_);
  }
  if (options_.has_filter_context()) {
    i::Address raw_filter_context =
        reinterpret_cast<i::Address>(options_.raw_filter_context());
    context_filter_.set_native_context_address(raw_filter_context);
  }
}

bool CpuProfile::CheckSubsample(base::TimeDelta source_sampling_interval) {
  DCHECK_GE(source_sampling_interval, base::TimeDelta());

  // If the sampling source's sampling interval is 0, record as many samples
  // are possible irrespective of the profile's sampling interval. Manually
  // taken samples (via CollectSample) fall into this case as well.
  if (source_sampling_interval.IsZero()) return true;

  next_sample_delta_ -= source_sampling_interval;
  if (next_sample_delta_ <= base::TimeDelta()) {
    next_sample_delta_ =
        base::TimeDelta::FromMicroseconds(options_.sampling_interval_us());
    return true;
  }
  return false;
}

void CpuProfile::AddPath(base::TimeTicks timestamp,
                         const ProfileStackTrace& path, int src_line,
                         bool update_stats, base::TimeDelta sampling_interval,
                         StateTag state_tag,
                         EmbedderStateTag embedder_state_tag) {
  if (!CheckSubsample(sampling_interval)) return;

  ProfileNode* top_frame_node =
      top_down_.AddPathFromEnd(path, src_line, update_stats, options_.mode());

  bool is_buffer_full =
      options_.max_samples() != CpuProfilingOptions::kNoSampleLimit &&
      samples_.size() >= options_.max_samples();
  bool should_record_sample =
      !timestamp.IsNull() && timestamp >= start_time_ && !is_buffer_full;

  if (should_record_sample) {
    samples_.push_back(
        {top_frame_node, timestamp, src_line, state_tag, embedder_state_tag});
  } else if (is_buffer_full && delegate_ != nullptr) {
    const auto task_runner = V8::GetCurrentPlatform()->GetForegroundTaskRunner(
        reinterpret_cast<v8::Isolate*>(profiler_->isolate()));

    task_runner->PostTask(std::make_unique<CpuProfileMaxSamplesCallbackTask>(
        std::move(delegate_)));
    // std::move ensures that the delegate_ will be null on the next sample,
    // so we don't post a task multiple times.
  }

  const int kSamplesFlushCount = 100;
  const int kNodesFlushCount = 10;
  if (samples_.size() - streaming_next_sample_ >= kSamplesFlushCount ||
      top_down_.pending_nodes_count() >= kNodesFlushCount) {
    StreamPendingTraceEvents();
  }
}

namespace {

void BuildNodeValue(const ProfileNode* node, TracedValue* value) {
  const CodeEntry* entry = node->entry();
  value->BeginDictionary("callFrame");
  value->SetString("functionName", entry->name());
  if (*entry->resource_name()) {
    value->SetString("url", entry->resource_name());
  }
  value->SetInteger("scriptId", entry->script_id());
  if (entry->line_number()) {
    value->SetInteger("lineNumber", entry->line_number() - 1);
  }
  if (entry->column_number()) {
    value->SetInteger("columnNumber", entry->column_number() - 1);
  }
  value->SetString("codeType", entry->code_type_string());
  value->EndDictionary();
  value->SetInteger("id", node->id());
  if (node->parent()) {
    value->SetInteger("parent", node->parent()->id());
  }
  const char* deopt_reason = entry->bailout_reason();
  if (deopt_reason && deopt_reason[0] && strcmp(deopt_reason, "no reason")) {
    value->SetString("deoptReason", deopt_reason);
  }
}

}  // namespace

void CpuProfile::StreamPendingTraceEvents() {
  std::vector<const ProfileNode*> pending_nodes = top_down_.TakePendingNodes();
  if (pending_nodes.empty() && samples_.empty()) return;
  auto value = TracedValue::Create();

  if (!pending_nodes.empty() || streaming_next_sample_ != samples_.size()) {
    value->BeginDictionary("cpuProfile");
    if (!pending_nodes.empty()) {
      value->BeginArray("nodes");
      for (auto node : pending_nodes) {
        value->BeginDictionary();
        BuildNodeValue(node, value.get());
        value->EndDictionary();
      }
      value->EndArray();
    }
    if (streaming_next_sample_ != samples_.size()) {
      value->BeginArray("samples");
      for (size_t i = streaming_next_sample_; i < samples_.size(); ++i) {
        value->AppendInteger(samples_[i].node->id());
      }
      value->EndArray();
    }
    value->EndDictionary();
  }
  if (streaming_next_sample_ != samples_.size()) {
    // timeDeltas are computed within CLOCK_MONOTONIC. However, trace event
    // "ts" timestamps are converted to CLOCK_BOOTTIME by Perfetto. To get
    // absolute timestamps in CLOCK_BOOTTIME from timeDeltas, add them to
    // the "ts" timestamp from the initial "Profile" trace event sent by
    // CpuProfile::CpuProfile().
    //
    // Note that if the system is suspended and resumed while samples_ is
    // captured, timeDeltas derived after resume will not be convertible to
    // correct CLOCK_BOOTTIME time values (for instance, producing
    // CLOCK_BOOTTIME time values in the middle of the suspended period).
    value->BeginArray("timeDeltas");
    base::TimeTicks lastTimestamp =
        streaming_next_sample_ ? samples_[streaming_next_sample_ - 1].timestamp
                               : start_time();
    for (size_t i = streaming_next_sample_; i < samples_.size(); ++i) {
      value->AppendInteger(static_cast<int>(
          (samples_[i].timestamp - lastTimestamp).InMicroseconds()));
      lastTimestamp = samples_[i].timestamp;
    }
    value->EndArray();
    bool has_non_zero_lines =
        std::any_of(samples_.begin() + streaming_next_sample_, samples_.end(),
                    [](const SampleInfo& sample) { return sample.line != 0; });
    if (has_non_zero_lines) {
      value->BeginArray("lines");
      for (size_t i = streaming_next_sample_; i < samples_.size(); ++i) {
        value->AppendInteger(samples_[i].line);
      }
      value->EndArray();
    }
    streaming_next_sample_ = samples_.size();
  }

  TRACE_EVENT_SAMPLE_WITH_ID1(TRACE_DISABLED_BY_DEFAULT("v8.cpu_profiler"),
                              "ProfileChunk", id_, "data", std::move(value));
}

void CpuProfile::FinishProfile() {
  end_time_ = base::TimeTicks::Now();
  // Stop tracking context movements after profiling stops.
  context_filter_.set_native_context_address(kNullAddress);
  StreamPendingTraceEvents();
  auto value = TracedValue::Create();
  // The endTime timestamp is not converted to Perfetto's clock domain and will
  // get out of sync with other timestamps Perfetto knows about, including the
  // automatic trace event "ts" timestamp. endTime is included for backward
  // compatibility with the tracing protocol: its presence in "data" is used by
  // devtools to identify the last ProfileChunk but the value of "ts" should be
  // used instead (it is recorded nearly immediately after).
  value->SetDouble("endTime", end_time_.since_origin().InMicroseconds());
  TRACE_EVENT_SAMPLE_WITH_ID1(TRACE_DISABLED_BY_DEFAULT("v8.cpu_profiler"),
                              "ProfileChunk", id_, "data", std::move(value));
}

namespace {

void FlattenNodesTree(const v8::CpuProfileNode* node,
                      std::vector<const v8::CpuProfileNode*>* nodes) {
  nodes->emplace_back(node);
  const int childrenCount = node->GetChildrenCount();
  for (int i = 0; i < childrenCount; i++)
    FlattenNodesTree(node->GetChild(i), nodes);
}

}  // namespace

void CpuProfileJSONSerializer::Serialize(v8::OutputStream* stream) {
  DCHECK_NULL(writer_);
  writer_ = new OutputStreamWriter(stream);
  SerializeImpl();
  delete writer_;
  writer_ = nullptr;
}

void CpuProfileJSONSerializer::SerializePositionTicks(
    const v8::CpuProfileNode* node, int lineCount) {
  std::vector<v8::CpuProfileNode::LineTick> entries(lineCount);
  if (node->GetLineTicks(&entries[0], lineCount)) {
    for (int i = 0; i < lineCount; i++) {
      writer_->AddCharacter('{');
      writer_->AddString("\"line\":");
      writer_->AddNumber(entries[i].line);
      writer_->AddString(",\"ticks\":");
      writer_->AddNumber(entries[i].hit_count);
      writer_->AddCharacter('}');
      if (i != (lineCount - 1)) writer_->AddCharacter(',');
    }
  }
}

void CpuProfileJSONSerializer::SerializeCallFrame(
    const v8::CpuProfileNode* node) {
  writer_->AddString("\"functionName\":\"");
  writer_->AddString(node->GetFunctionNameStr());
  writer_->AddString("\",\"lineNumber\":");
  writer_->AddNumber(node->GetLineNumber() - 1);
  writer_->AddString(",\"columnNumber\":");
  writer_->AddNumber(node->GetColumnNumber() - 1);
  writer_->AddString(",\"scriptId\":");
  writer_->AddNumber(node->GetScriptId());
  writer_->AddString(",\"url\":\"");
  writer_->AddString(node->GetScriptResourceNameStr());
  writer_->AddCharacter('"');
}

void CpuProfileJSONSerializer::SerializeChildren(const v8::CpuProfileNode* node,
                                                 int childrenCount) {
  for (int i = 0; i < childrenCount; i++) {
    writer_->AddNumber(node->GetChild(i)->GetNodeId());
    if (i != (childrenCount - 1)) writer_->AddCharacter(',');
  }
}

void CpuProfileJSONSerializer::SerializeNode(const v8::CpuProfileNode* node) {
  writer_->AddCharacter('{');
  writer_->AddString("\"id\":");
  writer_->AddNumber(node->GetNodeId());

  writer_->AddString(",\"hitCount\":");
  writer_->AddNumber(node->GetHitCount());

  writer_->AddString(",\"callFrame\":{");
  SerializeCallFrame(node);
  writer_->AddCharacter('}');

  const int childrenCount = node->GetChildrenCount();
  if (childrenCount) {
    writer_->AddString(",\"children\":[");
    SerializeChildren(node, childrenCount);
    writer_->AddCharacter(']');
  }

  const char* deoptReason = node->GetBailoutReason();
  if (deoptReason && deoptReason[0] && strcmp(deoptReason, "no reason")) {
    writer_->AddString(",\"deoptReason\":\"");
    writer_->AddString(deoptReason);
    writer_->AddCharacter('"');
  }

  unsigned lineCount = node->GetHitLineCount();
  if (lineCount) {
    writer_->AddString(",\"positionTicks\":[");
    SerializePositionTicks(node, lineCount);
    writer_->AddCharacter(']');
  }
  writer_->AddCharacter('}');
}

void CpuProfileJSONSerializer::SerializeNodes() {
  std::vector<const v8::CpuProfileNode*> nodes;
  FlattenNodesTree(
      reinterpret_cast<const v8::CpuProfileNode*>(profile_->top_down()->root()),
      &nodes);

  for (size_t i = 0; i < nodes.size(); i++) {
    SerializeNode(nodes.at(i));
    if (writer_->aborted()) return;
    if (i != (nodes.size() - 1)) writer_->AddCharacter(',');
  }
}

void CpuProfileJSONSerializer::SerializeTimeDeltas() {
  int count = profile_->samples_count();
  uint64_t lastTime = profile_->start_time().since_origin().InMicroseconds();
  for (int i = 0; i < count; i++) {
    uint64_t ts = profile_->sample(i).timestamp.since_origin().InMicroseconds();
    writer_->AddNumber(static_cast<int>(ts - lastTime));
    if (i != (count - 1)) writer_->AddString(",");
    lastTime = ts;
  }
}

void CpuProfileJSONSerializer::SerializeSamples() {
  int count = profile_->samples_count();
  for (int i = 0; i < count; i++) {
    writer_->AddNumber(profile_->sample(i).node->id());
    if (i != (count - 1)) writer_->AddString(",");
  }
}

void CpuProfileJSONSerializer::SerializeImpl() {
  writer_->AddCharacter('{');
  writer_->AddString("\"nodes\":[");
  SerializeNodes();
  writer_->AddString("]");

  writer_->AddString(",\"startTime\":");
  writer_->AddNumber(static_cast<unsigned>(
      profile_->start_time().since_origin().InMicroseconds()));

  writer_->AddString(",\"endTime\":");
  writer_->AddNumber(static_cast<unsigned>(
      profile_->end_time().since_origin().InMicroseconds()));

  writer_->AddString(",\"samples\":[");
  SerializeSamples();
  if (writer_->aborted()) return;
  writer_->AddCharacter(']');

  wri
"""


```