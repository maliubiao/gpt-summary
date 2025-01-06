Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understanding the Goal:** The core request is to summarize the functionality of `profiler-listener.cc` and, if related to JavaScript, illustrate the connection with a JavaScript example.

2. **Initial Skim for Keywords and Structure:**  A quick scan reveals important keywords: `ProfilerListener`, `CodeCreateEvent`, `CodeMoveEvent`, `CodeDisableOptEvent`, `CodeDeoptEvent`, `CallbackEvent`, `RegExpCodeCreateEvent`, `WasmCode`, `SharedFunctionInfo`, `Script`, `SourcePosition`, etc. The structure shows a class `ProfilerListener` with various methods related to different types of "code events."

3. **Identifying Core Responsibility:** The name `ProfilerListener` strongly suggests its role is to *listen* for events related to code execution and compilation. The methods like `CodeCreateEvent`, `CodeMoveEvent`, etc., confirm this. It's clearly acting as a central point for capturing information about different stages of code lifecycle within the V8 engine.

4. **Focusing on `CodeCreateEvent`:** This method appears multiple times with different signatures. This indicates it handles the creation of various types of code (regular functions, callbacks, regular expressions, WebAssembly). The parameters provide clues about the information being captured: code objects, names, script details, source positions, etc.

5. **Analyzing Other Event Types:** Briefly examine the other event methods:
    * `CodeMoveEvent`: Tracks code moving in memory.
    * `CodeDisableOptEvent`: Records when code optimization is disabled.
    * `CodeDeoptEvent`:  Logs deoptimization events (when optimized code reverts to less optimized versions). This is crucial for performance analysis.
    * `CallbackEvent`, `GetterCallbackEvent`, `SetterCallbackEvent`: Capture information about native callbacks.
    * `RegExpCodeCreateEvent`:  Handles regular expression compilation.
    * `WeakCodeClearEvent`, `OnHeapObjectDeletion`, `CodeSweepEvent`: Relate to managing the lifecycle of code objects, especially in the context of garbage collection.
    * `NativeContextMoveEvent`:  Tracks movement of native contexts.

6. **Identifying JavaScript Connections:** The presence of `SharedFunctionInfo`, `Script`, and the overall concept of profiling strongly indicate a connection to JavaScript. V8 compiles and executes JavaScript, and these events are fundamentally about what's happening with the JavaScript code. The handling of source positions and inlining further cements this connection.

7. **Formulating the Summary (Initial Draft):**  Based on the above, a first draft might be: "This C++ file defines `ProfilerListener`, a class that listens for and records various events related to code within the V8 engine. It handles code creation, movement, optimization/deoptimization, callbacks, and regular expressions. This is used for profiling."

8. **Refining the Summary (Adding Detail):**  The initial draft is too basic. Let's add more detail from the analysis:
    * Mention the purpose of capturing these events (CPU profiling, performance analysis).
    * Highlight the different types of code creation events.
    * Explain the significance of deoptimization events.
    * Note the WebAssembly specific handling.
    * Briefly mention the code lifecycle management aspects.

9. **Developing the JavaScript Example:**  To illustrate the connection, we need JavaScript code that would trigger the events being listened to by `ProfilerListener`.
    * **Function Definition:** A simple JavaScript function will trigger a `CodeCreateEvent`.
    * **Function Call:** Calling the function will potentially lead to execution and could be part of profiling data.
    * **Optimization/Deoptimization:** To show `CodeDisableOptEvent` or `CodeDeoptEvent`, we need scenarios that might cause these. Initially, I might think of complex code, but a simpler approach is to show a scenario where V8 might *initially* optimize but then deoptimize (e.g., changing types within a function). However, directly *forcing* deoptimization is tricky in a simple example. It's better to illustrate what *kind* of code *might* be subject to these events. A function with dynamic type changes is a good example.
    * **Callbacks:**  `setTimeout` is a straightforward way to demonstrate callbacks.
    * **Regular Expressions:**  Creating and using a regular expression will trigger `RegExpCodeCreateEvent`.

10. **Connecting the C++ to the JavaScript Example:** Explain how the JavaScript actions map to the C++ event methods. For example, defining a function in JavaScript leads to a `CodeCreateEvent` in the C++ code.

11. **Review and Refine:** Read through the summary and the JavaScript example to ensure accuracy, clarity, and completeness. Check for any missing links or unclear explanations. For instance, ensure that the example is simple and directly relates to the C++ concepts. Initially, I might have made the JavaScript example too complex, so simplifying it would be a refinement. Also, ensure the summary emphasizes the profiling aspect.

By following these steps, we can systematically analyze the C++ code and create a comprehensive summary and illustrative JavaScript example that clearly demonstrates the functionality of `profiler-listener.cc`.
这个C++源代码文件 `profiler-listener.cc` 的主要功能是**监听V8引擎中发生的各种代码事件，并将这些事件记录下来，以便用于CPU性能分析（profiling）**。 它充当了一个事件接收器和转发器的角色，将V8引擎内部发生的低级别代码事件转化为更高层次的、可用于分析的数据。

更具体地说，`ProfilerListener` 监听并处理以下类型的事件：

* **代码创建事件 (CodeCreateEvent):**  当新的JavaScript代码被编译或生成时触发。这包括：
    *  普通JavaScript函数
    *  匿名函数
    *  内置函数
    *  WebAssembly 代码
    *  正则表达式代码
    *  C++ 回调函数 (callbacks, getters, setters)
* **代码移动事件 (CodeMoveEvent):** 当代码在内存中被移动时触发。这通常发生在垃圾回收或代码优化过程中。
* **字节码移动事件 (BytecodeMoveEvent):** 当字节码数组在内存中移动时触发。
* **原生上下文移动事件 (NativeContextMoveEvent):**  当原生上下文（通常与全局对象相关联）在内存中移动时触发。
* **代码取消优化事件 (CodeDisableOptEvent):** 当V8引擎决定放弃对某个函数进行优化时触发。
* **代码反优化事件 (CodeDeoptEvent):** 当已经优化的代码需要回退到未优化或更低级别的代码时触发。这通常是由于运行时类型不匹配等原因引起的。
* **弱代码清除事件 (WeakCodeClearEvent) 和 代码扫描事件 (CodeSweepEvent):**  与垃圾回收相关，用于清理不再被引用的代码。
* **堆对象删除事件 (OnHeapObjectDeletion):** 当表示代码的对象从堆中删除时触发。

**与 JavaScript 功能的关系及示例:**

`ProfilerListener` 的核心功能是为 JavaScript 代码的性能分析提供基础数据。 每当执行 JavaScript 代码时，V8 引擎内部会发生各种代码事件，而 `ProfilerListener` 就负责捕捉这些事件，并将它们的信息（例如代码的起始地址、大小、所属函数、源文件名、行号等）记录下来。 这些记录下来的事件数据是 CPU profiler 生成性能分析报告的关键输入。

以下 JavaScript 示例展示了如何通过执行 JavaScript 代码来触发 `ProfilerListener` 中监听的某些事件：

```javascript
// 定义一个简单的 JavaScript 函数，会触发 CodeCreateEvent
function add(a, b) {
  return a + b;
}

// 调用该函数，可能会触发 CodeMoveEvent (如果引擎决定移动代码)
let result = add(5, 3);

// 定义一个匿名函数，也会触发 CodeCreateEvent
setTimeout(function() {
  console.log("延迟执行");
}, 100);

// 使用正则表达式，会触发 RegExpCodeCreateEvent
const regex = /abc/;
regex.test("abcdef");

// 可能触发 CodeDisableOptEvent 或 CodeDeoptEvent 的场景：
function polymorphicFunction(x) {
  return x + 1;
}

// 首次调用，假设传入数字，引擎可能会进行优化
polymorphicFunction(5);

// 后续调用传入字符串，可能导致引擎取消优化或反优化
polymorphicFunction("hello");
```

**对应到 `ProfilerListener` 中的事件：**

* **`function add(a, b) { ... }`**:  会触发 `CodeCreateEvent`，记录 `add` 函数的代码信息。
* **`setTimeout(function() { ... }, 100)`**: 会触发两次 `CodeCreateEvent`，一次是为 `setTimeout` 这个内置函数，另一次是为传递给 `setTimeout` 的匿名函数。
* **`const regex = /abc/`**: 会触发 `RegExpCodeCreateEvent`，记录正则表达式的代码信息。
* **`polymorphicFunction(5)` 和 `polymorphicFunction("hello")`**:  首次调用可能会触发优化后的代码创建 (`CodeCreateEvent`)。后续使用不同类型的参数调用，可能会导致 V8 引擎取消之前的优化 (`CodeDisableOptEvent`) 或者进行反优化 (`CodeDeoptEvent`)，并可能重新创建未优化的代码 (`CodeCreateEvent`)。

**总结:**

`profiler-listener.cc` 是 V8 引擎中一个至关重要的组件，它像一个忠实的记录员，捕捉着 JavaScript 代码在执行过程中发生的各种关键事件。 这些事件信息对于理解 JavaScript 代码的执行行为、进行性能瓶颈分析和优化至关重要。 通过 JavaScript 的执行，我们可以间接地触发 `ProfilerListener` 中定义的各种事件处理逻辑，从而生成用于性能分析的数据。

Prompt: 
```
这是目录为v8/src/profiler/profiler-listener.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/profiler/profiler-listener.h"

#include <algorithm>

#include "src/base/vector.h"
#include "src/codegen/reloc-info.h"
#include "src/codegen/source-position-table.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/handles/handles-inl.h"
#include "src/objects/code-inl.h"
#include "src/objects/code.h"
#include "src/objects/objects-inl.h"
#include "src/objects/script-inl.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/objects/string-inl.h"
#include "src/profiler/cpu-profiler.h"
#include "src/profiler/profile-generator-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-manager.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

ProfilerListener::ProfilerListener(Isolate* isolate,
                                   CodeEventObserver* observer,
                                   CodeEntryStorage& code_entry_storage,
                                   WeakCodeRegistry& weak_code_registry,
                                   CpuProfilingNamingMode naming_mode)
    : isolate_(isolate),
      observer_(observer),
      code_entries_(code_entry_storage),
      weak_code_registry_(weak_code_registry),
      naming_mode_(naming_mode) {}

ProfilerListener::~ProfilerListener() = default;

void ProfilerListener::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                       const char* name) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  PtrComprCageBase cage_base(isolate_);
  rec->instruction_start = code->InstructionStart(cage_base);
  rec->entry =
      code_entries_.Create(tag, GetName(name), CodeEntry::kEmptyResourceName,
                           CpuProfileNode::kNoLineNumberInfo,
                           CpuProfileNode::kNoColumnNumberInfo, nullptr);
  rec->instruction_size = code->InstructionSize(cage_base);
  weak_code_registry_.Track(rec->entry, code);
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                       Handle<Name> name) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  PtrComprCageBase cage_base(isolate_);
  rec->instruction_start = code->InstructionStart(cage_base);
  rec->entry =
      code_entries_.Create(tag, GetName(*name), CodeEntry::kEmptyResourceName,
                           CpuProfileNode::kNoLineNumberInfo,
                           CpuProfileNode::kNoColumnNumberInfo, nullptr);
  rec->instruction_size = code->InstructionSize(cage_base);
  weak_code_registry_.Track(rec->entry, code);
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                       Handle<SharedFunctionInfo> shared,
                                       Handle<Name> script_name) {
  PtrComprCageBase cage_base(isolate_);
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  rec->instruction_start = code->InstructionStart(cage_base);
  rec->entry =
      code_entries_.Create(tag, GetName(shared->DebugNameCStr().get()),
                           GetName(InferScriptName(*script_name, *shared)),
                           CpuProfileNode::kNoLineNumberInfo,
                           CpuProfileNode::kNoColumnNumberInfo, nullptr);
  rec->entry->FillFunctionInfo(*shared);
  rec->instruction_size = code->InstructionSize(cage_base);
  weak_code_registry_.Track(rec->entry, code);
  DispatchCodeEvent(evt_rec);
}

namespace {

CodeEntry* GetOrInsertCachedEntry(
    std::unordered_set<CodeEntry*, CodeEntry::Hasher, CodeEntry::Equals>*
        entries,
    CodeEntry* search_value, CodeEntryStorage& storage) {
  auto it = entries->find(search_value);
  if (it != entries->end()) {
    storage.DecRef(search_value);
    return *it;
  }
  entries->insert(search_value);
  return search_value;
}

}  // namespace

void ProfilerListener::CodeCreateEvent(CodeTag tag,
                                       Handle<AbstractCode> abstract_code,
                                       Handle<SharedFunctionInfo> shared,
                                       Handle<Name> script_name, int line,
                                       int column) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  PtrComprCageBase cage_base(isolate_);
  rec->instruction_start = abstract_code->InstructionStart(cage_base);
  std::unique_ptr<SourcePositionTable> line_table;
  std::unordered_map<int, std::vector<CodeEntryAndLineNumber>> inline_stacks;
  std::unordered_set<CodeEntry*, CodeEntry::Hasher, CodeEntry::Equals>
      cached_inline_entries;
  bool is_shared_cross_origin = false;
  if (IsScript(shared->script(cage_base), cage_base)) {
    DirectHandle<Script> script(Cast<Script>(shared->script(cage_base)),
                                isolate_);
    line_table.reset(new SourcePositionTable());

    is_shared_cross_origin = script->origin_options().IsSharedCrossOrigin();

    bool is_baseline = abstract_code->kind(cage_base) == CodeKind::BASELINE;
    Handle<TrustedByteArray> source_position_table(
        abstract_code->SourcePositionTable(isolate_, *shared), isolate_);
    std::unique_ptr<baseline::BytecodeOffsetIterator> baseline_iterator;
    if (is_baseline) {
      Handle<BytecodeArray> bytecodes(shared->GetBytecodeArray(isolate_),
                                      isolate_);
      Handle<TrustedByteArray> bytecode_offsets(
          abstract_code->GetCode()->bytecode_offset_table(), isolate_);
      baseline_iterator = std::make_unique<baseline::BytecodeOffsetIterator>(
          bytecode_offsets, bytecodes);
    }
    // Add each position to the source position table and store inlining stacks
    // for inline positions. We store almost the same information in the
    // profiler as is stored on the code object, except that we transform source
    // positions to line numbers here, because we only care about attributing
    // ticks to a given line.
    for (SourcePositionTableIterator it(source_position_table); !it.done();
         it.Advance()) {
      int position = it.source_position().ScriptOffset();
      int inlining_id = it.source_position().InliningId();
      int code_offset = it.code_offset();
      if (is_baseline) {
        // Use the bytecode offset to calculate pc offset for baseline code.
        baseline_iterator->AdvanceToBytecodeOffset(code_offset);
        code_offset =
            static_cast<int>(baseline_iterator->current_pc_start_offset());
      }

      if (inlining_id == SourcePosition::kNotInlined) {
        int line_number = script->GetLineNumber(position) + 1;
        line_table->SetPosition(code_offset, line_number, inlining_id);
      } else {
        DCHECK(!is_baseline);
        DCHECK(IsCode(*abstract_code, cage_base));
        std::vector<SourcePositionInfo> stack =
            it.source_position().InliningStack(isolate_,
                                               abstract_code->GetCode());
        DCHECK(!stack.empty());

        // When we have an inlining id and we are doing cross-script inlining,
        // then the script of the inlined frames may be different to the script
        // of |shared|.
        int line_number = stack.front().line + 1;
        line_table->SetPosition(code_offset, line_number, inlining_id);

        std::vector<CodeEntryAndLineNumber> inline_stack;
        for (SourcePositionInfo& pos_info : stack) {
          if (pos_info.position.ScriptOffset() == kNoSourcePosition) continue;
          if (pos_info.script.is_null()) continue;

          line_number =
              pos_info.script->GetLineNumber(pos_info.position.ScriptOffset()) +
              1;

          const char* resource_name =
              (IsName(pos_info.script->name()))
                  ? GetName(Cast<Name>(pos_info.script->name()))
                  : CodeEntry::kEmptyResourceName;

          bool inline_is_shared_cross_origin =
              pos_info.script->origin_options().IsSharedCrossOrigin();

          // We need the start line number and column number of the function for
          // kLeafNodeLineNumbers mode. Creating a SourcePositionInfo is a handy
          // way of getting both easily.
          SourcePositionInfo start_pos_info(
              isolate_, SourcePosition(pos_info.shared->StartPosition()),
              pos_info.shared);

          CodeEntry* inline_entry = code_entries_.Create(
              tag, GetFunctionName(*pos_info.shared), resource_name,
              start_pos_info.line + 1, start_pos_info.column + 1, nullptr,
              inline_is_shared_cross_origin);
          inline_entry->FillFunctionInfo(*pos_info.shared);

          // Create a canonical CodeEntry for each inlined frame and then re-use
          // them for subsequent inline stacks to avoid a lot of duplication.
          CodeEntry* cached_entry = GetOrInsertCachedEntry(
              &cached_inline_entries, inline_entry, code_entries_);

          inline_stack.push_back({cached_entry, line_number});
        }
        DCHECK(!inline_stack.empty());
        inline_stacks.emplace(inlining_id, std::move(inline_stack));
      }
    }
  }
  rec->entry = code_entries_.Create(
      tag, GetFunctionName(*shared),
      GetName(InferScriptName(*script_name, *shared)), line, column,
      std::move(line_table), is_shared_cross_origin);
  if (!inline_stacks.empty()) {
    rec->entry->SetInlineStacks(std::move(cached_inline_entries),
                                std::move(inline_stacks));
  }

  rec->entry->FillFunctionInfo(*shared);
  rec->instruction_size = abstract_code->InstructionSize(cage_base);
  weak_code_registry_.Track(rec->entry, abstract_code);
  DispatchCodeEvent(evt_rec);
}

#if V8_ENABLE_WEBASSEMBLY
void ProfilerListener::CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                                       wasm::WasmName name,
                                       const char* source_url, int code_offset,
                                       int script_id) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  rec->instruction_start = code->instruction_start();
  rec->entry = code_entries_.Create(tag, GetName(name), GetName(source_url), 1,
                                    code_offset + 1, nullptr, true,
                                    CodeEntry::CodeType::WASM);
  rec->entry->set_script_id(script_id);
  rec->entry->set_position(code_offset);
  rec->instruction_size = code->instructions().length();
  DispatchCodeEvent(evt_rec);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void ProfilerListener::CallbackEvent(Handle<Name> name, Address entry_point) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  rec->instruction_start = entry_point;
  rec->entry = code_entries_.Create(LogEventListener::CodeTag::kCallback,
                                    GetName(*name));
  rec->instruction_size = 1;
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::GetterCallbackEvent(Handle<Name> name,
                                           Address entry_point) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  rec->instruction_start = entry_point;
  rec->entry = code_entries_.Create(LogEventListener::CodeTag::kCallback,
                                    GetConsName("get ", *name));
  rec->instruction_size = 1;
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::SetterCallbackEvent(Handle<Name> name,
                                           Address entry_point) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  rec->instruction_start = entry_point;
  rec->entry = code_entries_.Create(LogEventListener::CodeTag::kCallback,
                                    GetConsName("set ", *name));
  rec->instruction_size = 1;
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::RegExpCodeCreateEvent(Handle<AbstractCode> code,
                                             Handle<String> source,
                                             RegExpFlags flags) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeCreation);
  CodeCreateEventRecord* rec = &evt_rec.CodeCreateEventRecord_;
  PtrComprCageBase cage_base(isolate_);
  rec->instruction_start = code->InstructionStart(cage_base);
  rec->entry = code_entries_.Create(
      LogEventListener::CodeTag::kRegExp, GetConsName("RegExp: ", *source),
      CodeEntry::kEmptyResourceName, CpuProfileNode::kNoLineNumberInfo,
      CpuProfileNode::kNoColumnNumberInfo, nullptr);
  rec->instruction_size = code->InstructionSize(cage_base);
  weak_code_registry_.Track(rec->entry, code);
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeMoveEvent(Tagged<InstructionStream> from,
                                     Tagged<InstructionStream> to) {
  DisallowGarbageCollection no_gc;
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeMove);
  CodeMoveEventRecord* rec = &evt_rec.CodeMoveEventRecord_;
  rec->from_instruction_start = from->instruction_start();
  rec->to_instruction_start = to->instruction_start();
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                         Tagged<BytecodeArray> to) {
  DisallowGarbageCollection no_gc;
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeMove);
  CodeMoveEventRecord* rec = &evt_rec.CodeMoveEventRecord_;
  rec->from_instruction_start = from->GetFirstBytecodeAddress();
  rec->to_instruction_start = to->GetFirstBytecodeAddress();
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::NativeContextMoveEvent(Address from, Address to) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kNativeContextMove);
  evt_rec.NativeContextMoveEventRecord_.from_address = from;
  evt_rec.NativeContextMoveEventRecord_.to_address = to;
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeDisableOptEvent(Handle<AbstractCode> code,
                                           Handle<SharedFunctionInfo> shared) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeDisableOpt);
  CodeDisableOptEventRecord* rec = &evt_rec.CodeDisableOptEventRecord_;
  PtrComprCageBase cage_base(isolate_);
  rec->instruction_start = code->InstructionStart(cage_base);
  rec->bailout_reason =
      GetBailoutReason(shared->disabled_optimization_reason());
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind,
                                      Address pc, int fp_to_sp_delta) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeDeopt);
  CodeDeoptEventRecord* rec = &evt_rec.CodeDeoptEventRecord_;
  Deoptimizer::DeoptInfo info = Deoptimizer::GetDeoptInfo(*code, pc);
  rec->instruction_start = code->instruction_start();
  rec->deopt_reason = DeoptimizeReasonToString(info.deopt_reason);
  rec->deopt_id = info.deopt_id;
  rec->pc = pc;
  rec->fp_to_sp_delta = fp_to_sp_delta;

  // When a function is deoptimized, we store the deoptimized frame information
  // for the use of GetDeoptInfos().
  AttachDeoptInlinedFrames(code, rec);
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::WeakCodeClearEvent() { weak_code_registry_.Sweep(this); }

void ProfilerListener::OnHeapObjectDeletion(CodeEntry* entry) {
  CodeEventsContainer evt_rec(CodeEventRecord::Type::kCodeDelete);
  evt_rec.CodeDeleteEventRecord_.entry = entry;
  DispatchCodeEvent(evt_rec);
}

void ProfilerListener::CodeSweepEvent() { weak_code_registry_.Sweep(this); }

const char* ProfilerListener::GetName(base::Vector<const char> name) {
  // TODO(all): Change {StringsStorage} to accept non-null-terminated strings.
  base::OwnedVector<char> null_terminated =
      base::OwnedVector<char>::New(name.size() + 1);
#if defined(__GNUC__) && !defined(__clang__)
  // Work around a spurious GCC-12 warning (-Werror=array-bounds).
  if (name.end() < name.begin()) return nullptr;
#endif
  std::copy(name.begin(), name.end(), null_terminated.begin());
  null_terminated[name.size()] = '\0';
  return GetName(null_terminated.begin());
}

Tagged<Name> ProfilerListener::InferScriptName(
    Tagged<Name> name, Tagged<SharedFunctionInfo> info) {
  if (IsString(name) && Cast<String>(name)->length()) return name;
  if (!IsScript(info->script())) return name;
  Tagged<Object> source_url = Cast<Script>(info->script())->source_url();
  return IsName(source_url) ? Cast<Name>(source_url) : name;
}

const char* ProfilerListener::GetFunctionName(
    Tagged<SharedFunctionInfo> shared) {
  switch (naming_mode_) {
    case kDebugNaming:
      return GetName(shared->DebugNameCStr().get());
    case kStandardNaming:
      return GetName(shared->Name());
    default:
      UNREACHABLE();
  }
}

void ProfilerListener::AttachDeoptInlinedFrames(DirectHandle<Code> code,
                                                CodeDeoptEventRecord* rec) {
  int deopt_id = rec->deopt_id;
  SourcePosition last_position = SourcePosition::Unknown();
  int mask = RelocInfo::ModeMask(RelocInfo::DEOPT_ID) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_SCRIPT_OFFSET) |
             RelocInfo::ModeMask(RelocInfo::DEOPT_INLINING_ID);

  rec->deopt_frames = nullptr;
  rec->deopt_frame_count = 0;

  for (RelocIterator it(*code, mask); !it.done(); it.next()) {
    RelocInfo* info = it.rinfo();
    if (info->rmode() == RelocInfo::DEOPT_SCRIPT_OFFSET) {
      int script_offset = static_cast<int>(info->data());
      it.next();
      DCHECK(it.rinfo()->rmode() == RelocInfo::DEOPT_INLINING_ID);
      int inlining_id = static_cast<int>(it.rinfo()->data());
      last_position = SourcePosition(script_offset, inlining_id);
      continue;
    }
    if (info->rmode() == RelocInfo::DEOPT_ID) {
      if (deopt_id != static_cast<int>(info->data())) continue;
      DCHECK(last_position.IsKnown());

      // SourcePosition::InliningStack allocates a handle for the SFI of each
      // frame. These don't escape this function, but quickly add up. This
      // scope limits their lifetime.
      HandleScope scope(isolate_);
      std::vector<SourcePositionInfo> stack =
          last_position.InliningStack(isolate_, *code);
      CpuProfileDeoptFrame* deopt_frames =
          new CpuProfileDeoptFrame[stack.size()];

      int deopt_frame_count = 0;
      for (SourcePositionInfo& pos_info : stack) {
        if (pos_info.position.ScriptOffset() == kNoSourcePosition) continue;
        if (pos_info.script.is_null()) continue;
        int script_id = pos_info.script->id();
        size_t offset = static_cast<size_t>(pos_info.position.ScriptOffset());
        deopt_frames[deopt_frame_count++] = {script_id, offset};
      }
      rec->deopt_frames = deopt_frames;
      rec->deopt_frame_count = deopt_frame_count;
      break;
    }
  }
}

}  // namespace internal
}  // namespace v8

"""

```