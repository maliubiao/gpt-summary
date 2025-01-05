Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of `code-serializer.cc` and its relationship to JavaScript, specifically requesting a JavaScript example.

2. **Initial Scan and Keywords:** Quickly read through the code, paying attention to class names, function names, and comments. Keywords that stand out are: `CodeSerializer`, `Serialize`, `Deserialize`, `SharedFunctionInfo`, `Script`, `CachedData`, `Snapshot`, `SourceHash`, `SanityCheck`, "off-thread", "background". These immediately suggest the file is about saving and loading compiled JavaScript code.

3. **Focus on Key Classes and Functions:**
    * **`CodeSerializer`:** The central class. Its constructor and methods like `Serialize` and `SerializeSharedFunctionInfo` are critical. The `source_hash_` member suggests tracking the source code.
    * **`Deserialize`:**  Handles the reverse process. The presence of "off-thread" variants like `StartDeserializeOffThread` and `FinishOffThreadDeserialize` is interesting and indicates asynchronous processing.
    * **`AlignedCachedData`:**  Looks like a wrapper for the serialized data. The alignment requirement and ownership hints at memory management.
    * **`SerializedCodeData`:**  Deals with the format of the serialized data, including headers, checksums, and sanity checks.

4. **Trace the Serialization Process:**  Follow the `Serialize` function.
    * It takes an `Isolate` (V8's execution environment) and `SharedFunctionInfo` (information about a JavaScript function).
    * It uses `CodeSerializer`.
    * It calls `SerializeSharedFunctionInfo`.
    * `SerializeSharedFunctionInfo` visits root pointers and serializes deferred objects.
    * It creates `SerializedCodeData` from the serialized sink data.
    * It returns a `ScriptCompiler::CachedData`. This confirms it's for caching compiled code.

5. **Trace the Deserialization Process:** Follow the `Deserialize` function.
    * It takes an `Isolate`, `AlignedCachedData`, and the original `source`.
    * It performs `SanityCheck` to ensure the cached data is valid (version, source, flags, etc.). This is a crucial security and correctness step.
    * It uses `ObjectDeserializer::DeserializeSharedFunctionInfo` to reconstruct the `SharedFunctionInfo`.
    * It handles off-thread deserialization for performance.
    * It does post-deserialization tasks like setting script details and potentially triggering baseline compilation.

6. **Identify Relationships with JavaScript Concepts:**
    * `SharedFunctionInfo` directly relates to JavaScript functions.
    * `Script` represents a JavaScript source code unit.
    * The serialization and deserialization are for *compiled* code, linking to the idea that V8 optimizes and caches code.
    * The "source hash" is about ensuring the cached code matches the original JavaScript source. This is key for avoiding incorrect execution.

7. **Formulate the Core Functionality:** Based on the tracing, the core function is to serialize and deserialize compiled JavaScript code (specifically `SharedFunctionInfo`). This is done for caching to speed up subsequent executions.

8. **Address the "Why":**  Why is this necessary?  Caching compiled code avoids the overhead of recompiling the same JavaScript code repeatedly, improving performance, especially for frequently used code. This links to concepts like code optimization and caching in JavaScript engines.

9. **Develop the JavaScript Example:**  The example needs to demonstrate the impact of this process. The key is showing that *subsequent* executions are faster if caching works. This can be shown by:
    * Defining a function.
    * Executing it the first time (likely triggering compilation and serialization if caching is enabled).
    * Executing it a second time.
    * Measuring the execution time for both runs. The second run should be faster if the code was cached.

10. **Refine the Explanation:**  Ensure the explanation clearly links the C++ code to the JavaScript example. Explain *how* the C++ code enables the faster execution in JavaScript. Emphasize the concepts of compilation, caching, and the checks performed to ensure the cached code is valid.

11. **Review and Iterate:** Read through the generated summary and example. Does it accurately reflect the C++ code? Is the JavaScript example clear and illustrative? Are the connections between C++ and JavaScript well-explained?  For example, initially, I might have focused too much on the low-level details of the serialization format. But the core user-facing impact is performance, so the JavaScript example should highlight that. The sanity checks are also important to explain for correctness.

This iterative process of scanning, tracing, connecting, and refining helps build a comprehensive understanding and generate a relevant and informative response.
这个C++源代码文件 `code-serializer.cc` 的主要功能是**将编译后的 JavaScript 代码 (特别是 `SharedFunctionInfo` 对象) 序列化 (转换为字节流) 和反序列化 (从字节流恢复)**。 这个过程是 V8 引擎实现代码缓存的关键部分。

更具体地说，它的作用包括：

1. **序列化 (`Serialize`)**:
   - 接收一个 `SharedFunctionInfo` 对象作为输入，该对象包含了关于一个 JavaScript 函数的编译信息（例如，生成的机器码或字节码）。
   - 将这个 `SharedFunctionInfo` 对象以及它引用的其他相关对象（例如，`Script` 对象，包含源代码信息）转换为一个字节流。
   - 这个字节流可以被存储到磁盘或内存中，以便后续快速加载。
   - 在序列化过程中，它会进行一些优化和处理，例如：
     - 排除不必要的信息（例如，调试信息在某些情况下可以被排除）。
     - 处理对其他对象的引用，以确保反序列化后这些引用仍然有效。
     - 计算校验和，以确保反序列化数据的完整性。

2. **反序列化 (`Deserialize`)**:
   - 接收一个包含序列化数据的字节流以及原始的 JavaScript 源代码。
   - 验证字节流的完整性和有效性，例如，检查魔数、版本号、源代码哈希等，以确保缓存的代码与当前的 JavaScript 引擎和源代码兼容。
   - 将字节流转换回 `SharedFunctionInfo` 对象以及它引用的其他对象。
   - 恢复编译后的代码，避免了重新编译 JavaScript 代码的开销，从而提高了性能。
   - 支持**离线 (off-thread)** 反序列化，允许在后台线程进行反序列化，减少主线程的阻塞。

**它与 JavaScript 的功能关系：**

`code-serializer.cc` 的功能直接关系到 JavaScript 的执行性能。 代码缓存允许 V8 引擎在多次执行相同的 JavaScript 代码时，重用之前编译的结果，而不是每次都重新编译。 这显著加速了页面的加载速度和脚本的执行效率。

**JavaScript 示例说明:**

假设我们有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

console.time('First Run');
add(5, 3);
console.timeEnd('First Run');

console.time('Second Run');
add(10, 7);
console.timeEnd('Second Run');
```

当 V8 引擎第一次执行 `add(5, 3)` 时，它会：

1. **解析 (Parsing):** 将 JavaScript 代码转换为抽象语法树 (AST)。
2. **编译 (Compilation):** 将 AST 转换为中间表示 (例如，字节码) 或直接编译成机器码。 这个编译结果会存储在 `SharedFunctionInfo` 对象中。
3. **序列化 (Serialization):** `code-serializer.cc` 负责将这个 `SharedFunctionInfo` 对象序列化成字节流，以便缓存。

当 V8 引擎第二次执行 `add(10, 7)` 时，它会尝试：

1. **查找缓存 (Cache Lookup):**  V8 会查找是否已经存在 `add` 函数的缓存。 这通常基于函数的源代码哈希等信息进行查找。
2. **反序列化 (Deserialization):** 如果找到了缓存，`code-serializer.cc` 负责将缓存的字节流反序列化回 `SharedFunctionInfo` 对象。
3. **执行 (Execution):**  V8 可以直接执行反序列化得到的编译后的代码，而无需再次进行解析和编译。

**预期效果：**

由于避免了第二次运行的编译开销，`Second Run` 的执行时间通常会比 `First Run` 的执行时间短很多。 这就是代码缓存带来的性能提升，而 `code-serializer.cc` 在这个过程中扮演着关键角色。

**更细致的 JavaScript 例子 (需要 V8 特定的 API 或配置来更直接地观察缓存行为):**

要更直接地观察代码缓存的行为，可能需要使用一些 V8 提供的命令行标志或 API (如果存在允许这种程度的控制的 API)。  例如，可以使用 `--js-flags="--cache=code"` 来启用代码缓存，并通过性能分析工具观察编译过程是否被跳过。

**总结:**

`code-serializer.cc` 是 V8 引擎中负责持久化和恢复编译后 JavaScript 代码的核心组件。 它通过序列化和反序列化 `SharedFunctionInfo` 对象，实现了代码缓存机制，从而显著提升了 JavaScript 代码的执行效率。 它的存在对于构建高性能的 JavaScript 运行时环境至关重要。

Prompt: 
```
这是目录为v8/src/snapshot/code-serializer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/code-serializer.h"

#include <memory>

#include "src/base/logging.h"
#include "src/base/platform/elapsed-timer.h"
#include "src/base/platform/platform.h"
#include "src/baseline/baseline-batch-compiler.h"
#include "src/codegen/background-merge-task.h"
#include "src/common/globals.h"
#include "src/handles/maybe-handles.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/heap-inl.h"
#include "src/heap/parked-scope.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots.h"
#include "src/objects/visitors.h"
#include "src/snapshot/object-deserializer.h"
#include "src/snapshot/snapshot-utils.h"
#include "src/snapshot/snapshot.h"
#include "src/utils/version.h"

namespace v8 {
namespace internal {

AlignedCachedData::AlignedCachedData(const uint8_t* data, int length)
    : owns_data_(false), rejected_(false), data_(data), length_(length) {
  if (!IsAligned(reinterpret_cast<intptr_t>(data), kPointerAlignment)) {
    uint8_t* copy = NewArray<uint8_t>(length);
    DCHECK(IsAligned(reinterpret_cast<intptr_t>(copy), kPointerAlignment));
    CopyBytes(copy, data, length);
    data_ = copy;
    AcquireDataOwnership();
  }
}

CodeSerializer::CodeSerializer(Isolate* isolate, uint32_t source_hash)
    : Serializer(isolate, Snapshot::kDefaultSerializerFlags),
      source_hash_(source_hash) {}

// static
ScriptCompiler::CachedData* CodeSerializer::Serialize(
    Isolate* isolate, Handle<SharedFunctionInfo> info) {
  TRACE_EVENT_CALL_STATS_SCOPED(isolate, "v8", "V8.Execute");
  NestedTimedHistogramScope histogram_timer(
      isolate->counters()->compile_serialize());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileSerialize);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.CompileSerialize");

  base::ElapsedTimer timer;
  if (v8_flags.profile_deserialization) timer.Start();
  DirectHandle<Script> script(Cast<Script>(info->script()), isolate);
  if (v8_flags.trace_serializer) {
    PrintF("[Serializing from");
    ShortPrint(script->name());
    PrintF("]\n");
  }
#if V8_ENABLE_WEBASSEMBLY
  // TODO(7110): Enable serialization of Asm modules once the AsmWasmData is
  // context independent.
  if (script->ContainsAsmModule()) return nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY

  // Serialize code object.
  DirectHandle<String> source(Cast<String>(script->source()), isolate);
  HandleScope scope(isolate);
  CodeSerializer cs(isolate, SerializedCodeData::SourceHash(
                                 source, script->origin_options()));
  DisallowGarbageCollection no_gc;

#ifndef DEBUG
  cs.reference_map()->AddAttachedReference(*source);
#endif
  AlignedCachedData* cached_data = cs.SerializeSharedFunctionInfo(info);

  if (v8_flags.profile_deserialization) {
    double ms = timer.Elapsed().InMillisecondsF();
    int length = cached_data->length();
    PrintF("[Serializing to %d bytes took %0.3f ms]\n", length, ms);
  }

  ScriptCompiler::CachedData* result =
      new ScriptCompiler::CachedData(cached_data->data(), cached_data->length(),
                                     ScriptCompiler::CachedData::BufferOwned);
  cached_data->ReleaseDataOwnership();
  delete cached_data;

  return result;
}

AlignedCachedData* CodeSerializer::SerializeSharedFunctionInfo(
    Handle<SharedFunctionInfo> info) {
  DisallowGarbageCollection no_gc;

  VisitRootPointer(Root::kHandleScope, nullptr,
                   FullObjectSlot(info.location()));
  SerializeDeferredObjects();
  Pad();

  SerializedCodeData data(sink_.data(), this);

  return data.GetScriptData();
}

void CodeSerializer::SerializeObjectImpl(Handle<HeapObject> obj,
                                         SlotType slot_type) {
  ReadOnlyRoots roots(isolate());
  InstanceType instance_type;
  {
    DisallowGarbageCollection no_gc;
    Tagged<HeapObject> raw = *obj;
    if (SerializeHotObject(raw)) return;
    if (SerializeRoot(raw)) return;
    if (SerializeBackReference(raw)) return;
    if (SerializeReadOnlyObjectReference(raw, &sink_)) return;

    instance_type = raw->map()->instance_type();
    CHECK(!InstanceTypeChecker::IsInstructionStream(instance_type));
  }

  if (InstanceTypeChecker::IsScript(instance_type)) {
    DirectHandle<FixedArray> host_options;
    DirectHandle<UnionOf<Smi, Symbol, Undefined>> context_data;
    {
      DisallowGarbageCollection no_gc;
      Tagged<Script> script_obj = Cast<Script>(*obj);
      DCHECK_NE(script_obj->compilation_type(), Script::CompilationType::kEval);
      // We want to differentiate between undefined and uninitialized_symbol for
      // context_data for now. It is hack to allow debugging for scripts that
      // are included as a part of custom snapshot. (see
      // debug::Script::IsEmbedded())
      Tagged<UnionOf<Smi, Symbol, Undefined>> raw_context_data =
          script_obj->context_data();
      if (raw_context_data != roots.undefined_value() &&
          raw_context_data != roots.uninitialized_symbol()) {
        script_obj->set_context_data(roots.undefined_value());
      }
      context_data = direct_handle(raw_context_data, isolate());
      // We don't want to serialize host options to avoid serializing
      // unnecessary object graph.
      host_options =
          direct_handle(script_obj->host_defined_options(), isolate());
      script_obj->set_host_defined_options(roots.empty_fixed_array());
    }
    SerializeGeneric(obj, slot_type);
    {
      DisallowGarbageCollection no_gc;
      Tagged<Script> script_obj = Cast<Script>(*obj);
      script_obj->set_host_defined_options(*host_options);
      script_obj->set_context_data(*context_data);
    }
    return;
  } else if (InstanceTypeChecker::IsSharedFunctionInfo(instance_type)) {
    DirectHandle<DebugInfo> debug_info;
    CachedTieringDecision cached_tiering_decision;
    bool restore_bytecode = false;
    {
      DisallowGarbageCollection no_gc;
      Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(*obj);
      DCHECK(!sfi->IsApiFunction());
#if V8_ENABLE_WEBASSEMBLY
      // TODO(7110): Enable serializing of Asm modules once the AsmWasmData
      // is context independent.
      DCHECK(!sfi->HasAsmWasmData());
#endif  // V8_ENABLE_WEBASSEMBLY

      if (auto maybe_debug_info = sfi->TryGetDebugInfo(isolate())) {
        debug_info = handle(maybe_debug_info.value(), isolate());
        // Clear debug info.
        if (debug_info->HasInstrumentedBytecodeArray()) {
          restore_bytecode = true;
          sfi->SetActiveBytecodeArray(
              debug_info->OriginalBytecodeArray(isolate()), isolate());
        }
      }
      if (v8_flags.profile_guided_optimization) {
        cached_tiering_decision = sfi->cached_tiering_decision();
        if (cached_tiering_decision > CachedTieringDecision::kEarlySparkplug) {
          sfi->set_cached_tiering_decision(
              CachedTieringDecision::kEarlySparkplug);
        }
      }
    }
    SerializeGeneric(obj, slot_type);
    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(*obj);
    if (restore_bytecode) {
      sfi->SetActiveBytecodeArray(debug_info->DebugBytecodeArray(isolate()),
                                  isolate());
    }
    if (v8_flags.profile_guided_optimization &&
        cached_tiering_decision > CachedTieringDecision::kEarlySparkplug) {
      sfi->set_cached_tiering_decision(cached_tiering_decision);
    }
    return;
  } else if (InstanceTypeChecker::IsUncompiledDataWithoutPreparseDataWithJob(
                 instance_type)) {
    Handle<UncompiledDataWithoutPreparseDataWithJob> data =
        Cast<UncompiledDataWithoutPreparseDataWithJob>(obj);
    Address job = data->job();
    data->set_job(kNullAddress);
    SerializeGeneric(data, slot_type);
    data->set_job(job);
    return;
  } else if (InstanceTypeChecker::IsUncompiledDataWithPreparseDataAndJob(
                 instance_type)) {
    Handle<UncompiledDataWithPreparseDataAndJob> data =
        Cast<UncompiledDataWithPreparseDataAndJob>(obj);
    Address job = data->job();
    data->set_job(kNullAddress);
    SerializeGeneric(data, slot_type);
    data->set_job(job);
    return;
  } else if (InstanceTypeChecker::IsScopeInfo(instance_type)) {
    // TODO(ishell): define a dedicated instance type for DependentCode and
    // serialize DependentCode objects as an empty_dependent_code instead
    // of customizing ScopeInfo serialization.
    static_assert(DEPENDENT_CODE_TYPE == WEAK_ARRAY_LIST_TYPE);
    Handle<ScopeInfo> scope_info = Cast<ScopeInfo>(obj);
    Handle<DependentCode> dependent_code;
    bool restore_dependent_code = false;
    if (scope_info->SloppyEvalCanExtendVars()) {
      // If |scope_info| has a dependent code field, serialize it as an empty
      // dependent code in order to avoid accidental serialization of optimized
      // code.
      Tagged<DependentCode> empty_dependent_code =
          DependentCode::empty_dependent_code(ReadOnlyRoots(isolate()));
      if (scope_info->dependent_code() != empty_dependent_code) {
        dependent_code = handle(scope_info->dependent_code(), isolate());
        restore_dependent_code = true;
        scope_info->set_dependent_code(empty_dependent_code);
      }
    }
    SerializeGeneric(scope_info, slot_type);
    if (restore_dependent_code) {
      scope_info->set_dependent_code(*dependent_code);
    }
    return;
  }

  // NOTE(mmarchini): If we try to serialize an InterpreterData our process
  // will crash since it stores a code object. Instead, we serialize the
  // bytecode array stored within the InterpreterData, which is the important
  // information. On deserialization we'll create our code objects again, if
  // --interpreted-frames-native-stack is on. See v8:9122 for more context
  if (V8_UNLIKELY(v8_flags.interpreted_frames_native_stack) &&
      IsInterpreterData(*obj)) {
    obj = handle(Cast<InterpreterData>(*obj)->bytecode_array(), isolate());
  }

  // Past this point we should not see any (context-specific) maps anymore.
  CHECK(!InstanceTypeChecker::IsMap(instance_type));
  // There should be no references to the global object embedded.
  CHECK(!InstanceTypeChecker::IsJSGlobalProxy(instance_type) &&
        !InstanceTypeChecker::IsJSGlobalObject(instance_type));
  // Embedded FixedArrays that need rehashing must support rehashing.
  CHECK_IMPLIES(obj->NeedsRehashing(cage_base()),
                obj->CanBeRehashed(cage_base()));
  // We expect no instantiated function objects or contexts.
  CHECK(!InstanceTypeChecker::IsJSFunction(instance_type) &&
        !InstanceTypeChecker::IsContext(instance_type));

  SerializeGeneric(obj, slot_type);
}

void CodeSerializer::SerializeGeneric(Handle<HeapObject> heap_object,
                                      SlotType slot_type) {
  // Object has not yet been serialized.  Serialize it here.
  ObjectSerializer serializer(this, heap_object, &sink_);
  serializer.Serialize(slot_type);
}

namespace {

// NOTE(mmarchini): when v8_flags.interpreted_frames_native_stack is on, we want
// to create duplicates of InterpreterEntryTrampoline for the deserialized
// functions, otherwise we'll call the builtin IET for those functions (which
// is not what a user of this flag wants).
void CreateInterpreterDataForDeserializedCode(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> result_sfi,
    bool log_code_creation) {
  DCHECK_IMPLIES(log_code_creation, isolate->NeedsSourcePositions());

  DirectHandle<Script> script(Cast<Script>(result_sfi->script()), isolate);
  if (log_code_creation) Script::InitLineEnds(isolate, script);

  Tagged<String> name = ReadOnlyRoots(isolate).empty_string();
  if (IsString(script->name())) name = Cast<String>(script->name());
  Handle<String> name_handle(name, isolate);

  SharedFunctionInfo::ScriptIterator iter(isolate, *script);
  for (Tagged<SharedFunctionInfo> shared_info = iter.Next();
       !shared_info.is_null(); shared_info = iter.Next()) {
    IsCompiledScope is_compiled(shared_info, isolate);
    if (!is_compiled.is_compiled()) continue;
    DCHECK(shared_info->HasBytecodeArray());
    Handle<SharedFunctionInfo> sfi = handle(shared_info, isolate);

    DirectHandle<BytecodeArray> bytecode(sfi->GetBytecodeArray(isolate),
                                         isolate);
    Handle<Code> code =
        Builtins::CreateInterpreterEntryTrampolineForProfiling(isolate);
    DirectHandle<InterpreterData> interpreter_data =
        isolate->factory()->NewInterpreterData(bytecode, code);

    if (sfi->HasBaselineCode()) {
      sfi->baseline_code(kAcquireLoad)
          ->set_bytecode_or_interpreter_data(*interpreter_data);
    } else {
      sfi->set_interpreter_data(*interpreter_data);
    }

    if (!log_code_creation) continue;

    Handle<AbstractCode> abstract_code = Cast<AbstractCode>(code);
    Script::PositionInfo info;
    Script::GetPositionInfo(script, sfi->StartPosition(), &info);
    int line_num = info.line_start + 1;
    int column_num = info.line_end + 1;
    PROFILE(isolate,
            CodeCreateEvent(LogEventListener::CodeTag::kFunction, abstract_code,
                            sfi, name_handle, line_num, column_num));
  }
}

class StressOffThreadDeserializeThread final : public base::Thread {
 public:
  explicit StressOffThreadDeserializeThread(Isolate* isolate,
                                            AlignedCachedData* cached_data)
      : Thread(
            base::Thread::Options("StressOffThreadDeserializeThread", 2 * MB)),
        isolate_(isolate),
        cached_data_(cached_data) {}

  void Run() final {
    LocalIsolate local_isolate(isolate_, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_isolate);
    LocalHandleScope handle_scope(&local_isolate);
    off_thread_data_ =
        CodeSerializer::StartDeserializeOffThread(&local_isolate, cached_data_);
  }

  MaybeDirectHandle<SharedFunctionInfo> Finalize(
      Isolate* isolate, DirectHandle<String> source,
      const ScriptDetails& script_details) {
    return CodeSerializer::FinishOffThreadDeserialize(
        isolate, std::move(off_thread_data_), cached_data_, source,
        script_details);
  }

 private:
  Isolate* isolate_;
  AlignedCachedData* cached_data_;
  CodeSerializer::OffThreadDeserializeData off_thread_data_;
};

void FinalizeDeserialization(Isolate* isolate,
                             DirectHandle<SharedFunctionInfo> result,
                             const base::ElapsedTimer& timer,
                             const ScriptDetails& script_details) {
  // Devtools can report time in this function as profiler overhead, since none
  // of the following tasks would need to happen normally.
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.FinalizeDeserialization");

  const bool log_code_creation = isolate->IsLoggingCodeCreation();

  if (V8_UNLIKELY(v8_flags.interpreted_frames_native_stack)) {
    CreateInterpreterDataForDeserializedCode(isolate, result,
                                             log_code_creation);
  }

  DirectHandle<Script> script(Cast<Script>(result->script()), isolate);
  // Reset the script details, including host-defined options.
  {
    DisallowGarbageCollection no_gc;
    SetScriptFieldsFromDetails(isolate, *script, script_details, &no_gc);
  }

  bool needs_source_positions = isolate->NeedsSourcePositions();
  if (!log_code_creation && !needs_source_positions) return;

  if (needs_source_positions) {
    Script::InitLineEnds(isolate, script);
  }

  Handle<String> name(IsString(script->name())
                          ? Cast<String>(script->name())
                          : ReadOnlyRoots(isolate).empty_string(),
                      isolate);

  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    LOG(isolate,
        FunctionEvent("deserialize", script->id(),
                      timer.Elapsed().InMillisecondsF(),
                      result->StartPosition(), result->EndPosition(), *name));
  }

  SharedFunctionInfo::ScriptIterator iter(isolate, *script);
  for (Tagged<SharedFunctionInfo> info = iter.Next(); !info.is_null();
       info = iter.Next()) {
    if (!info->is_compiled()) continue;
    Handle<SharedFunctionInfo> shared_info(info, isolate);
    if (needs_source_positions) {
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared_info);
    }
    Script::PositionInfo pos_info;
    Script::GetPositionInfo(script, shared_info->StartPosition(), &pos_info);
    int line_num = pos_info.line + 1;
    int column_num = pos_info.column + 1;
    PROFILE(isolate, CodeCreateEvent(
                         shared_info->is_toplevel()
                             ? LogEventListener::CodeTag::kScript
                             : LogEventListener::CodeTag::kFunction,
                         handle(shared_info->abstract_code(isolate), isolate),
                         shared_info, name, line_num, column_num));
  }
}

#ifdef V8_ENABLE_SPARKPLUG
void BaselineBatchCompileIfSparkplugCompiled(Isolate* isolate,
                                             Tagged<Script> script) {
  // Here is main thread, we trigger early baseline compilation only in
  // concurrent sparkplug and baseline batch compilation mode which consumes
  // little main thread execution time.
  if (v8_flags.concurrent_sparkplug && v8_flags.baseline_batch_compilation) {
    SharedFunctionInfo::ScriptIterator iter(isolate, script);
    for (Tagged<SharedFunctionInfo> info = iter.Next(); !info.is_null();
         info = iter.Next()) {
      if (info->cached_tiering_decision() != CachedTieringDecision::kPending &&
          CanCompileWithBaseline(isolate, info)) {
        isolate->baseline_batch_compiler()->EnqueueSFI(info);
      }
    }
  }
}
#else
void BaselineBatchCompileIfSparkplugCompiled(Isolate*, Tagged<Script>) {}
#endif  // V8_ENABLE_SPARKPLUG

const char* ToString(SerializedCodeSanityCheckResult result) {
  switch (result) {
    case SerializedCodeSanityCheckResult::kSuccess:
      return "success";
    case SerializedCodeSanityCheckResult::kMagicNumberMismatch:
      return "magic number mismatch";
    case SerializedCodeSanityCheckResult::kVersionMismatch:
      return "version mismatch";
    case SerializedCodeSanityCheckResult::kSourceMismatch:
      return "source mismatch";
    case SerializedCodeSanityCheckResult::kFlagsMismatch:
      return "flags mismatch";
    case SerializedCodeSanityCheckResult::kChecksumMismatch:
      return "checksum mismatch";
    case SerializedCodeSanityCheckResult::kInvalidHeader:
      return "invalid header";
    case SerializedCodeSanityCheckResult::kLengthMismatch:
      return "length mismatch";
    case SerializedCodeSanityCheckResult::kReadOnlySnapshotChecksumMismatch:
      return "read-only snapshot checksum mismatch";
  }
}
}  // namespace

MaybeDirectHandle<SharedFunctionInfo> CodeSerializer::Deserialize(
    Isolate* isolate, AlignedCachedData* cached_data, Handle<String> source,
    const ScriptDetails& script_details,
    MaybeHandle<Script> maybe_cached_script) {
  if (v8_flags.stress_background_compile) {
    StressOffThreadDeserializeThread thread(isolate, cached_data);
    CHECK(thread.Start());
    thread.Join();
    return thread.Finalize(isolate, source, script_details);
    // TODO(leszeks): Compare off-thread deserialized data to on-thread.
  }

  base::ElapsedTimer timer;
  if (v8_flags.profile_deserialization || v8_flags.log_function_events) {
    timer.Start();
  }

  HandleScope scope(isolate);

  SerializedCodeSanityCheckResult sanity_check_result =
      SerializedCodeSanityCheckResult::kSuccess;
  const SerializedCodeData scd = SerializedCodeData::FromCachedData(
      isolate, cached_data,
      SerializedCodeData::SourceHash(source, script_details.origin_options),
      &sanity_check_result);
  if (sanity_check_result != SerializedCodeSanityCheckResult::kSuccess) {
    if (v8_flags.profile_deserialization) {
      PrintF("[Cached code failed check: %s]\n", ToString(sanity_check_result));
    }
    DCHECK(cached_data->rejected());
    isolate->counters()->code_cache_reject_reason()->AddSample(
        static_cast<int>(sanity_check_result));
    return MaybeHandle<SharedFunctionInfo>();
  }

  // Deserialize.
  MaybeDirectHandle<SharedFunctionInfo> maybe_result =
      ObjectDeserializer::DeserializeSharedFunctionInfo(isolate, &scd, source);

  DirectHandle<SharedFunctionInfo> result;
  if (!maybe_result.ToHandle(&result)) {
    // Deserializing may fail if the reservations cannot be fulfilled.
    if (v8_flags.profile_deserialization) PrintF("[Deserializing failed]\n");
    return MaybeDirectHandle<SharedFunctionInfo>();
  }

  // Check whether the newly deserialized data should be merged into an
  // existing Script from the Isolate compilation cache. If so, perform
  // the merge in a single-threaded manner since this deserialization was
  // single-threaded.
  if (Handle<Script> cached_script;
      maybe_cached_script.ToHandle(&cached_script)) {
    BackgroundMergeTask merge;
    merge.SetUpOnMainThread(isolate, cached_script);
    CHECK(merge.HasPendingBackgroundWork());
    DirectHandle<Script> new_script(Cast<Script>(result->script()), isolate);
    merge.BeginMergeInBackground(isolate->AsLocalIsolate(), new_script);
    CHECK(merge.HasPendingForegroundWork());
    result = merge.CompleteMergeInForeground(isolate, new_script);
  }

  Tagged<Script> script = Cast<Script>(result->script());
  script->set_deserialized(true);
  BaselineBatchCompileIfSparkplugCompiled(isolate, script);
  if (v8_flags.profile_deserialization) {
    double ms = timer.Elapsed().InMillisecondsF();
    int length = cached_data->length();
    PrintF("[Deserializing from %d bytes took %0.3f ms]\n", length, ms);
  }

  FinalizeDeserialization(isolate, result, timer, script_details);

  return scope.CloseAndEscape(result);
}

Handle<Script> CodeSerializer::OffThreadDeserializeData::GetOnlyScript(
    LocalHeap* heap) {
  std::unique_ptr<PersistentHandles> previous_persistent_handles =
      heap->DetachPersistentHandles();
  heap->AttachPersistentHandles(std::move(persistent_handles));

  DCHECK_EQ(scripts.size(), 1);
  // Make a non-persistent handle to return.
  Handle<Script> script = handle(*scripts[0], heap);
  DCHECK_EQ(*script, maybe_result.ToHandleChecked()->script());

  persistent_handles = heap->DetachPersistentHandles();
  if (previous_persistent_handles) {
    heap->AttachPersistentHandles(std::move(previous_persistent_handles));
  }

  return script;
}

CodeSerializer::OffThreadDeserializeData
CodeSerializer::StartDeserializeOffThread(LocalIsolate* local_isolate,
                                          AlignedCachedData* cached_data) {
  OffThreadDeserializeData result;

  DCHECK(!local_isolate->heap()->HasPersistentHandles());

  const SerializedCodeData scd =
      SerializedCodeData::FromCachedDataWithoutSource(
          local_isolate, cached_data, &result.sanity_check_result);
  if (result.sanity_check_result != SerializedCodeSanityCheckResult::kSuccess) {
    // Exit early but don't report yet, we'll re-check this when finishing on
    // the main thread
    DCHECK(cached_data->rejected());
    return result;
  }

  MaybeDirectHandle<SharedFunctionInfo> local_maybe_result =
      OffThreadObjectDeserializer::DeserializeSharedFunctionInfo(
          local_isolate, &scd, &result.scripts);

  result.maybe_result =
      local_isolate->heap()->NewPersistentMaybeHandle(local_maybe_result);
  result.persistent_handles = local_isolate->heap()->DetachPersistentHandles();

  return result;
}

MaybeHandle<SharedFunctionInfo> CodeSerializer::FinishOffThreadDeserialize(
    Isolate* isolate, OffThreadDeserializeData&& data,
    AlignedCachedData* cached_data, DirectHandle<String> source,
    const ScriptDetails& script_details,
    BackgroundMergeTask* background_merge_task) {
  base::ElapsedTimer timer;
  if (v8_flags.profile_deserialization || v8_flags.log_function_events) {
    timer.Start();
  }

  HandleScope scope(isolate);

  // Do a source sanity check now that we have the source. It's important for
  // FromPartiallySanityCheckedCachedData call that the sanity_check_result
  // holds the result of the off-thread sanity check.
  SerializedCodeSanityCheckResult sanity_check_result =
      data.sanity_check_result;
  const SerializedCodeData scd =
      SerializedCodeData::FromPartiallySanityCheckedCachedData(
          cached_data,
          SerializedCodeData::SourceHash(source, script_details.origin_options),
          &sanity_check_result);
  if (sanity_check_result != SerializedCodeSanityCheckResult::kSuccess) {
    // The only case where the deserialization result could exist despite a
    // check failure is on a source mismatch, since we can't test for this
    // off-thread.
    DCHECK_IMPLIES(!data.maybe_result.is_null(),
                   sanity_check_result ==
                       SerializedCodeSanityCheckResult::kSourceMismatch);
    // The only kind of sanity check we can't test for off-thread is a source
    // mismatch.
    DCHECK_IMPLIES(sanity_check_result != data.sanity_check_result,
                   sanity_check_result ==
                       SerializedCodeSanityCheckResult::kSourceMismatch);
    if (v8_flags.profile_deserialization) {
      PrintF("[Cached code failed check: %s]\n", ToString(sanity_check_result));
    }
    DCHECK(cached_data->rejected());
    isolate->counters()->code_cache_reject_reason()->AddSample(
        static_cast<int>(sanity_check_result));
    return MaybeHandle<SharedFunctionInfo>();
  }

  Handle<SharedFunctionInfo> result;
  if (!data.maybe_result.ToHandle(&result)) {
    // Deserializing may fail if the reservations cannot be fulfilled.
    if (v8_flags.profile_deserialization) {
      PrintF("[Off-thread deserializing failed]\n");
    }
    return MaybeHandle<SharedFunctionInfo>();
  }

  // Change the result persistent handle into a regular handle.
  DCHECK(data.persistent_handles->Contains(result.location()));
  result = handle(*result, isolate);

  if (background_merge_task &&
      background_merge_task->HasPendingForegroundWork()) {
    DCHECK_EQ(data.scripts.size(), 1);
    DirectHandle<Script> new_script = data.scripts[0];
    result =
        background_merge_task->CompleteMergeInForeground(isolate, new_script);
    DCHECK(Object::StrictEquals(Cast<Script>(result->script())->source(),
                                *source));
    DCHECK(isolate->factory()->script_list()->Contains(
        MakeWeak(result->script())));
  } else {
    DirectHandle<Script> script(Cast<Script>(result->script()), isolate);
    // Fix up the source on the script. This should be the only deserialized
    // script, and the off-thread deserializer should have set its source to the
    // empty string. In debug mode the code cache does contain the original
    // source.
    DCHECK_EQ(data.scripts.size(), 1);
    DCHECK_EQ(*script, *data.scripts[0]);
#ifdef DEBUG
    if (!Cast<String>(script->source())->Equals(*source)) {
      isolate->PushStackTraceAndDie(
          reinterpret_cast<void*>(script->source().ptr()),
          reinterpret_cast<void*>(source->ptr()));
    }
#else
    CHECK_EQ(script->source(), ReadOnlyRoots(isolate).empty_string());
#endif
    Script::SetSource(isolate, script, source);

    // Fix up the script list to include the newly deserialized script.
    Handle<WeakArrayList> list = isolate->factory()->script_list();
    for (Handle<Script> script : data.scripts) {
      script->set_deserialized(true);
      BaselineBatchCompileIfSparkplugCompiled(isolate, *script);
      DCHECK(data.persistent_handles->Contains(script.location()));
      list = WeakArrayList::AddToEnd(isolate, list,
                                     MaybeObjectDirectHandle::Weak(script));
    }
    isolate->heap()->SetRootScriptList(*list);
  }

  if (v8_flags.profile_deserialization) {
    double ms = timer.Elapsed().InMillisecondsF();
    int length = cached_data->length();
    PrintF("[Finishing off-thread deserialize from %d bytes took %0.3f ms]\n",
           length, ms);
  }

  FinalizeDeserialization(isolate, result, timer, script_details);

  DCHECK(!background_merge_task ||
         !background_merge_task->HasPendingForegroundWork());

  return scope.CloseAndEscape(result);
}

SerializedCodeData::SerializedCodeData(const std::vector<uint8_t>* payload,
                                       const CodeSerializer* cs) {
  DisallowGarbageCollection no_gc;

  // Calculate sizes.
  uint32_t size = kHeaderSize + static_cast<uint32_t>(payload->size());
  DCHECK(IsAligned(size, kPointerAlignment));

  // Allocate backing store and create result data.
  AllocateData(size);

  // Zero out pre-payload data. Part of that is only used for padding.
  memset(data_, 0, kHeaderSize);

  // Set header values.
  SetMagicNumber();
  SetHeaderValue(kVersionHashOffset, Version::Hash());
  SetHeaderValue(kSourceHashOffset, cs->source_hash());
  SetHeaderValue(kFlagHashOffset, FlagList::Hash());
  SetHeaderValue(kReadOnlySnapshotChecksumOffset,
                 Snapshot::ExtractReadOnlySnapshotChecksum(
                     cs->isolate()->snapshot_blob()));
  SetHeaderValue(kPayloadLengthOffset, static_cast<uint32_t>(payload->size()));

  // Zero out any padding in the header.
  memset(data_ + kUnalignedHeaderSize, 0, kHeaderSize - kUnalignedHeaderSize);

  // Copy serialized data.
  CopyBytes(data_ + kHeaderSize, payload->data(),
            static_cast<size_t>(payload->size()));
  uint32_t checksum =
      v8_flags.verify_snapshot_checksum ? Checksum(ChecksummedContent()) : 0;
  SetHeaderValue(kChecksumOffset, checksum);
}

SerializedCodeSanityCheckResult SerializedCodeData::SanityCheck(
    uint32_t expected_ro_snapshot_checksum,
    uint32_t expected_source_hash) const {
  SerializedCodeSanityCheckResult result =
      SanityCheckWithoutSource(expected_ro_snapshot_checksum);
  if (result != SerializedCodeSanityCheckResult::kSuccess) return result;
  return SanityCheckJustSource(expected_source_hash);
}

SerializedCodeSanityCheckResult SerializedCodeData::SanityCheckJustSource(
    uint32_t expected_source_hash) const {
  uint32_t source_hash = GetHeaderValue(kSourceHashOffset);
  if (source_hash != expected_source_hash) {
    return SerializedCodeSanityCheckResult::kSourceMismatch;
  }
  return SerializedCodeSanityCheckResult::kSuccess;
}

SerializedCodeSanityCheckResult SerializedCodeData::SanityCheckWithoutSource(
    uint32_t expected_ro_snapshot_checksum) const {
  if (size_ < kHeaderSize) {
    return SerializedCodeSanityCheckResult::kInvalidHeader;
  }
  uint32_t magic_number = GetMagicNumber();
  if (magic_number != kMagicNumber) {
    return SerializedCodeSanityCheckResult::kMagicNumberMismatch;
  }
  uint32_t version_hash = GetHeaderValue(kVersionHashOffset);
  if (version_hash != Version::Hash()) {
    return SerializedCodeSanityCheckResult::kVersionMismatch;
  }
  uint32_t flags_hash = GetHeaderValue(kFlagHashOffset);
  if (flags_hash != FlagList::Hash()) {
    return SerializedCodeSanityCheckResult::kFlagsMismatch;
  }
  uint32_t ro_snapshot_checksum =
      GetHeaderValue(kReadOnlySnapshotChecksumOffset);
  if (ro_snapshot_checksum != expected_ro_snapshot_checksum) {
    return SerializedCodeSanityCheckResult::kReadOnlySnapshotChecksumMismatch;
  }
  uint32_t payload_length = GetHeaderValue(kPayloadLengthOffset);
  uint32_t max_payload_length = size_ - kHeaderSize;
  if (payload_length > max_payload_length) {
    return SerializedCodeSanityCheckResult::kLengthMismatch;
  }
  if (v8_flags.verify_snapshot_checksum) {
    uint32_t checksum = GetHeaderValue(kChecksumOffset);
    if (Checksum(ChecksummedContent()) != checksum) {
      return SerializedCodeSanityCheckResult::kChecksumMismatch;
    }
  }
  return SerializedCodeSanityCheckResult::kSuccess;
}

uint32_t SerializedCodeData::SourceHash(DirectHandle<String> source,
                                        ScriptOriginOptions origin_options) {
  const uint32_t source_length = source->length();

  static constexpr uint32_t kModuleFlagMask = (1 << 31);
  const uint32_t is_module = origin_options.IsModule() ? kModuleFlagMask : 0;
  DCHECK_EQ(0, source_length & kModuleFlagMask);

  return source_length | is_module;
}

// Return ScriptData object and relinquish ownership over it to the caller.
AlignedCachedData* SerializedCodeData::GetScriptData() {
  DCHECK(owns_data_);
  AlignedCachedData* result = new AlignedCachedData(data_, size_);
  result->AcquireDataOwnership();
  owns_data_ = false;
  data_ = nullptr;
  return result;
}

base::Vector<const uint8_t> SerializedCodeData::Payload() const {
  const uint8_t* payload = data_ + kHeaderSize;
  DCHECK(IsAligned(reinterpret_cast<intptr_t>(payload), kPointerAlignment));
  int length = GetHeaderValue(kPayloadLengthOffset);
  DCHECK_EQ(data_ + size_, payload + length);
  return base::Vector<const uint8_t>(payload, length);
}

SerializedCodeData::SerializedCodeData(AlignedCachedData* data)
    : SerializedData(const_cast<uint8_t*>(data->data()), data->length()) {}

SerializedCodeData SerializedCodeData::FromCachedData(
    Isolate* isolate, AlignedCachedData* cached_data,
    uint32_t expected_source_hash,
    SerializedCodeSanityCheckResult* rejection_result) {
  DisallowGarbageCollection no_gc;
  SerializedCodeData scd(cached_data);
  *rejection_result = scd.SanityCheck(
      Snapshot::ExtractReadOnlySnapshotChecksum(isolate->snapshot_blob()),
      expected_source_hash);
  if (*rejection_result != SerializedCodeSanityCheckResult::kSuccess) {
    cached_data->Reject();
    return SerializedCodeData(nullptr, 0);
  }
  return scd;
}

SerializedCodeData SerializedCodeData::FromCachedDataWithoutSource(
    LocalIsolate* local_isolate, AlignedCachedData* cached_data,
    SerializedCodeSanityCheckResult* rejection_result) {
  DisallowGarbageCollection no_gc;
  SerializedCodeData scd(cached_data);
  *rejection_result =
      scd.SanityCheckWithoutSource(Snapshot::ExtractReadOnlySnapshotChecksum(
          local_isolate->snapshot_blob()));
  if (*rejection_result != SerializedCodeSanityCheckResult::kSuccess) {
    cached_data->Reject();
    return SerializedCodeData(nullptr, 0);
  }
  return scd;
}

SerializedCodeData SerializedCodeData::FromPartiallySanityCheckedCachedData(
    AlignedCachedData* cached_data, uint32_t expected_source_hash,
    SerializedCodeSanityCheckResult* rejection_result) {
  DisallowGarbageCollection no_gc;
  // The previous call to FromCachedDataWithoutSource may have already rejected
  // the cached data, so re-use the previous rejection result if it's not a
  // success.
  if (*rejection_result != SerializedCodeSanityCheckResult::kSuccess) {
    // FromCachedDataWithoutSource doesn't check the source, so there can't be
    // a source mismatch.
    DCHECK_NE(*rejection_result,
              SerializedCodeSanityCheckResult::kSourceMismatch);
    cached_data->Reject();
    return SerializedCodeData(nullptr, 0);
  }
  SerializedCodeData scd(cached_data);
  *rejection_result = scd.SanityCheckJustSource(expected_source_hash);
  if (*rejection_result != SerializedCodeSanityCheckResult::kSuccess) {
    // This check only checks the source, so the only possible failure is a
    // source mismatch.
    DCHECK_EQ(*rejection_result,
              SerializedCodeSanityCheckResult::kSourceMismatch);
    cached_data->Reject();
    return SerializedCodeData(nullptr, 0);
  }
  return scd;
}

}  // namespace internal
}  // namespace v8

"""

```