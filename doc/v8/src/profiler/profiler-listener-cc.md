Response:
Let's break down the thought process for analyzing the `profiler-listener.cc` code.

1. **Understand the Purpose:** The filename `profiler-listener.cc` immediately suggests this code is about *listening* for events related to profiling. The `ProfilerListener` class name reinforces this. The inclusion of `<profiler/cpu-profiler.h>` further points to CPU profiling as a key focus.

2. **Identify Key Dependencies:** Look at the `#include` directives. These reveal the core functionalities the listener interacts with:
    * `src/codegen/...`:  Indicates interaction with code generation (relocation, source positions).
    * `src/deoptimizer/...`:  Shows involvement in deoptimization events.
    * `src/handles/...`, `src/objects/...`:  Confirms interaction with V8's object model (Code, Script, SharedFunctionInfo, etc.).
    * `src/profiler/...`:  Highlights its role within the profiling system.
    * `src/wasm/...`: Suggests WebAssembly profiling support.

3. **Analyze the Class Structure:** The `ProfilerListener` class has a constructor and destructor. The constructor takes key dependencies as arguments (`Isolate`, `CodeEventObserver`, etc.), which hints at how it's integrated into the larger V8 system.

4. **Examine Public Methods - The Core Functionality:**  Focus on the public methods. Their names often reveal their purpose:
    * `CodeCreateEvent`:  Clearly deals with the creation of different types of code. Notice the multiple overloaded versions, suggesting different ways code creation can be signaled. Pay attention to the parameters – `CodeTag`, `AbstractCode`, `SharedFunctionInfo`, `Name`, script information, line/column numbers.
    * `CodeMoveEvent`, `BytecodeMoveEvent`, `NativeContextMoveEvent`: These handle the movement of code and related contexts, crucial for dynamic environments.
    * `CodeDisableOptEvent`, `CodeDeoptEvent`: These handle events related to optimization and deoptimization, key for understanding performance bottlenecks.
    * `CallbackEvent`, `GetterCallbackEvent`, `SetterCallbackEvent`, `RegExpCodeCreateEvent`:  Handle specific types of code or events.
    * `WeakCodeClearEvent`, `OnHeapObjectDeletion`, `CodeSweepEvent`: Relate to memory management and cleanup of code entries.

5. **Decipher Method Logic (High-Level):** For each public method, try to understand *what* it does:
    * Most `CodeCreateEvent` methods create a `CodeEntry` and dispatch a `CodeCreation` event. They extract information like instruction start, size, function name, script information, and potentially line numbers. The inlining stack handling in one overload is more complex and involves iterating over the source position table.
    * `CodeMoveEvent` methods record the "from" and "to" addresses.
    * `CodeDisableOptEvent` records the reason for disabling optimization.
    * `CodeDeoptEvent` captures deoptimization information, including the reason, ID, and stack frames.

6. **Identify Data Structures:** Pay attention to the data structures used:
    * `CodeEventsContainer`, `CodeCreateEventRecord`, `CodeMoveEventRecord`, etc.:  These seem to be structures for holding event data before dispatching.
    * `CodeEntryStorage`, `WeakCodeRegistry`:  These likely manage the storage and tracking of code entries.
    * `std::unordered_set`, `std::unordered_map`:  Used for caching inline code entries, indicating optimization for repeated inlining scenarios.
    * `SourcePositionTable`:  Crucial for mapping code offsets to source positions and handling inlining.

7. **Look for Conditional Compilation (`#if`):** The `#if V8_ENABLE_WEBASSEMBLY` block clearly indicates support for profiling WebAssembly code.

8. **Connect to JavaScript (if applicable):** Consider how these internal events relate to observable JavaScript behavior. For instance, function calls, optimizations, and deoptimizations all have corresponding events in the profiler.

9. **Infer Potential Programming Errors:**  Think about how developers might unintentionally trigger these profiling events. Deoptimizations, for example, are often caused by type inconsistencies or other performance-inhibiting patterns in JavaScript code.

10. **Structure the Output:** Organize the findings logically:
    * **Functionality:** Summarize the main responsibilities.
    * **Torque:** Check for the `.tq` extension.
    * **JavaScript Relationship:** Provide concrete examples.
    * **Code Logic:**  Illustrate with simple input/output scenarios.
    * **Common Errors:** Give practical examples of developer mistakes.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just records code creation."  **Correction:**  Realize it handles *multiple types* of code events (creation, movement, deoptimization, etc.).
* **Initial thought:** "The inlining stack logic is simple." **Correction:** Recognize the complexity of iterating through the source position table and the caching mechanism for inline entries.
* **Initial thought:** "Deoptimization is just an error." **Correction:** Understand that deoptimization is a dynamic process used by the VM to handle situations where optimized code is no longer valid. It's not always a direct "error" by the programmer but can be a consequence of certain coding patterns.

By following these steps, you can systematically analyze C++ code like `profiler-listener.cc` and extract its core functionalities, dependencies, and relationship to the broader system (in this case, V8 and JavaScript).
`v8/src/profiler/profiler-listener.cc` 是 V8 引擎中负责监听各种代码事件并将其转化为 profiler 可用数据的组件。 它的主要功能是作为 V8 引擎和 CPU profiler 之间的桥梁。

**功能列表:**

1. **监听代码创建事件:**
   - 接收 V8 引擎发出的各种代码创建事件，例如：
     - 新的 JavaScript 函数被编译 (JIT)。
     - 内置函数或运行时函数被创建。
     - 正则表达式代码被创建。
     - WebAssembly 代码被加载和编译。
   - 针对不同的代码创建场景，提供了多个重载的 `CodeCreateEvent` 方法，以处理不同类型的信息（例如，代码对象、函数名、SharedFunctionInfo、脚本信息、行号列号等）。
   - 创建 `CodeEntry` 对象，用于存储关于这段代码的关键信息，例如代码标签 (CodeTag)、函数名、资源名 (文件名)、起始地址、大小、行号、列号等。
   - 如果代码与 JavaScript 脚本关联，则会尝试推断脚本名称。
   - 对于包含内联调用的代码，会解析其源代码位置表 (`SourcePositionTable`)，记录内联函数的调用栈信息。
   - 对于 WebAssembly 代码，会记录其特有的信息，例如模块名、代码偏移、脚本 ID 等。

2. **监听代码移动事件:**
   - 接收代码在内存中移动的事件 (`CodeMoveEvent`, `BytecodeMoveEvent`)，并更新 `CodeEntry` 中记录的起始地址信息。这在动态代码生成和优化过程中很重要。

3. **监听本地上下文移动事件:**
   - 接收 Native Context 移动的事件 (`NativeContextMoveEvent`)，用于跟踪全局执行上下文的变化。

4. **监听代码禁用优化事件:**
   - 接收代码由于某些原因被禁用优化的事件 (`CodeDisableOptEvent`)，并记录禁用优化的原因。

5. **监听代码反优化事件 (Deoptimization):**
   - 接收代码发生反优化的事件 (`CodeDeoptEvent`)，记录反优化的原因、反优化 ID、程序计数器 (PC) 和栈指针偏移量等信息。
   -  会解析反优化点的重定位信息，提取出反优化发生时的内联帧信息，用于更精确的性能分析。

6. **管理 CodeEntry 的生命周期:**
   - 使用 `WeakCodeRegistry` 来跟踪 `CodeEntry` 对象和实际代码对象之间的关联。当代码对象被垃圾回收时，会收到通知并清理相应的 `CodeEntry`。
   - 提供 `CodeSweepEvent` 和 `OnHeapObjectDeletion` 方法来处理代码对象的垃圾回收。

7. **调度代码事件:**
   - 将收集到的代码事件信息封装成 `CodeEventsContainer`，并通过 `DispatchCodeEvent` 方法发送给 `CodeEventObserver`。`CodeEventObserver` 通常是 CPU profiler，它会进一步处理这些事件数据。

8. **提供辅助方法:**
   - `GetName`:  用于获取 C 风格字符串的便捷方法。
   - `InferScriptName`:  尝试推断 JavaScript 代码的脚本名称。
   - `GetFunctionName`:  根据配置的命名模式获取函数名称。
   - `AttachDeoptInlinedFrames`:  解析反优化信息以获取内联帧。

**关于文件扩展名和 Torque:**

如果 `v8/src/profiler/profiler-listener.cc` 的文件扩展名是 `.tq`，那么它就是用 V8 的 Torque 语言编写的源代码。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它允许以一种类型安全的方式生成 C++ 代码。

**与 JavaScript 功能的关系 (及 JavaScript 示例):**

`ProfilerListener` 直接关联着 JavaScript 代码的执行和性能。它捕获了 JavaScript 代码编译、执行、优化和反优化的各个阶段的事件。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，可能会触发解释执行或基线编译
add(1, 2);

// 多次调用后，可能会触发优化编译 (例如 TurboFan)
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}

// 导致反优化的代码模式示例 (例如，类型变化)
add(1, "hello");
```

在这个例子中，`ProfilerListener` 会捕获以下事件 (简化描述):

- 当 `add` 函数第一次被调用时，可能会触发一个 `CodeCreateEvent`，记录解释器或基线编译器生成的代码信息。
- 当 `add` 函数被多次调用并被 V8 认为是热点代码时，会触发另一个 `CodeCreateEvent`，记录优化编译器 (如 TurboFan) 生成的优化代码信息。
- 当调用 `add(1, "hello")` 时，由于参数类型不一致，可能会导致之前优化的代码失效，触发一个 `CodeDeoptEvent` 事件。

**代码逻辑推理示例 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
function foo() {
  return bar();
}

function bar() {
  return 1;
}

foo();
```

**假设输入:**  当 V8 编译和执行这段代码时，`ProfilerListener` 会接收到 `CodeCreateEvent` 事件。

**可能的部分输出 (简化):**

1. **`CodeCreateEvent` for `bar`:**
   - `tag`:  可能是 `kJavaScript` 或其他表示 JavaScript 代码的标签。
   - `instruction_start`: `bar` 函数机器码的起始地址。
   - `entry`:  一个指向 `CodeEntry` 对象的指针，该对象包含 `bar` 的信息，例如函数名 "bar"，可能的文件名（如果代码来自文件），行号等。

2. **`CodeCreateEvent` for `foo`:**
   - `tag`: 同上。
   - `instruction_start`: `foo` 函数机器码的起始地址。
   - `entry`:  一个指向 `CodeEntry` 对象的指针，包含 `foo` 的信息，例如函数名 "foo"。 由于 `foo` 调用了 `bar`，如果启用了内联，`ProfilerListener` 可能会解析 `foo` 的源代码位置表，记录 `bar` 函数被内联到 `foo` 中的信息。

**涉及用户常见的编程错误 (举例说明):**

`ProfilerListener` 捕获的事件可以帮助开发者识别常见的性能问题，这些问题往往是由于编程错误引起的。

**示例 1: 反复触发反优化:**

```javascript
function calculate(x) {
  if (typeof x === 'number') {
    return x * 2;
  } else if (typeof x === 'string') {
    return parseInt(x) * 2;
  }
}

calculate(10); // 触发优化
calculate("20"); // 可能会导致之前的优化失效，触发反优化
calculate(30); // 可能会再次触发优化
```

在这个例子中，函数 `calculate` 接受不同类型的参数，这可能会导致 V8 引擎反复进行优化和反优化，`ProfilerListener` 会记录下这些 `CodeDeoptEvent` 事件，提示开发者这种代码模式可能存在性能问题。 应该尽量保持函数参数类型的一致性，以避免不必要的反优化。

**示例 2: 性能瓶颈在某个特定函数:**

如果 CPU profiler 基于 `ProfilerListener` 提供的数据显示某个 JavaScript 函数占据了大量的 CPU 时间，那可能意味着该函数内部存在性能瓶颈，需要进一步分析和优化。 这可能是由于复杂的算法、不必要的操作或者低效的 DOM 操作等原因造成的。

**总结:**

`v8/src/profiler/profiler-listener.cc` 是 V8 引擎中一个至关重要的组件，它负责监听和记录各种代码事件，并将这些信息传递给 profiler，为开发者进行性能分析和优化提供了基础数据。 它深入参与了 JavaScript 代码的生命周期，从编译到执行，再到优化和反优化，都留下了它的足迹。理解其功能有助于我们更好地理解 V8 引擎的内部工作原理以及如何进行有效的 JavaScript 性能分析。

Prompt: 
```
这是目录为v8/src/profiler/profiler-listener.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/profiler-listener.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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