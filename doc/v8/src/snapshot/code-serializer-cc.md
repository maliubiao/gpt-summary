Response:
My thought process to arrive at the summary of `v8/src/snapshot/code-serializer.cc` went something like this:

1. **Understand the Goal:** The request is to summarize the functionality of the provided C++ code related to V8's code serialization. It also asks about potential Torque involvement, JavaScript relevance, code logic inferences, and common user errors.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code for prominent keywords and class names. "Serializer," "CodeSerializer," "SharedFunctionInfo," "Script," "CachedData," "Deserialize," "Serialize," "Snapshot," and "BytecodeArray" jumped out. The inclusion of `#include "src/snapshot/..."` heavily suggests a focus on the snapshotting mechanism.

3. **High-Level Functionality Deduction:** Based on the keywords, I formed a preliminary hypothesis: this code is responsible for taking V8's compiled code (represented by `SharedFunctionInfo` and related structures) and turning it into a serialized form (`CachedData`) that can be stored and later loaded. The reverse process, deserialization, is also likely handled here. The presence of "snapshot" further reinforces the idea that this is part of V8's ability to quickly start up by loading pre-compiled code.

4. **Analyzing Class Structure and Methods:** I looked at the classes and their methods:
    * `CodeSerializer`:  The core class. Its `Serialize` method takes a `SharedFunctionInfo` and returns `ScriptCompiler::CachedData`, confirming the serialization path. The `Deserialize` method does the reverse.
    * `AlignedCachedData`: This seems to be the container for the serialized data.
    * `SerializedCodeData`:  Likely the in-memory representation of the serialized data with header information for validation.
    * Methods like `SerializeSharedFunctionInfo`, `SerializeObjectImpl`, and `SerializeGeneric` indicate the detailed steps in serializing various V8 objects.
    * Methods like `StartDeserializeOffThread` and `FinishOffThreadDeserialize` suggest support for background deserialization.

5. **Considering the Specific Questions:**  I then addressed the specific questions in the prompt:
    * **Torque:** The code explicitly checks for `.tq` extension, indicating awareness of Torque but no direct involvement in *this specific file*.
    * **JavaScript Relevance:**  The code directly deals with compiling and running JavaScript functions (`SharedFunctionInfo`, `Script`). I needed a JavaScript example illustrating how this relates. Caching compiled code for faster execution is the key link.
    * **Code Logic Inference:** The sanity checks within `SerializedCodeData` (magic number, version, source hash, etc.) are clearly for validation. I constructed a simple input/output scenario demonstrating this.
    * **Common User Errors:**  Mismatched code (changing the JavaScript source after caching) is a direct consequence of the caching mechanism and a common pitfall.

6. **Structuring the Summary:** I organized the findings into logical sections:
    * **Core Functionality:** A concise statement of the main purpose.
    * **Key Functions:** Listing the important methods and their roles.
    * **Conditional Logic:**  Highlighting the `.tq` check.
    * **JavaScript Relevance:** Providing a clear example.
    * **Code Logic Inference:**  Demonstrating the validation.
    * **Common User Errors:**  Giving a practical example.
    * **Overall Summary:**  A brief re-statement of the core purpose.

7. **Refinement and Detail:** I reviewed the code and my summary for accuracy and completeness. I added details like the purpose of the header in `SerializedCodeData` and the handling of different object types during serialization. I also ensured the JavaScript example was clear and concise. I noted the off-thread deserialization as an optimization.

8. **Self-Correction/Review:** I double-checked my understanding of the terms and concepts used in the code (e.g., `SharedFunctionInfo`, `Script`). I made sure the JavaScript example accurately reflected the scenario of cached code usage.

This iterative process of scanning, hypothesizing, analyzing, and refining allowed me to construct a comprehensive summary of the functionality of `v8/src/snapshot/code-serializer.cc`. The key was to start broad and then progressively zoom in on the details while keeping the overall purpose in mind.
这是 `v8/src/snapshot/code-serializer.cc` 源代码的第一部分，主要负责 **将 V8 的已编译代码序列化 (Serialize)**，以便后续可以快速反序列化 (Deserialize) 并加载，从而加速 V8 的启动和代码加载速度。

下面根据你的要求，对这部分代码的功能进行更详细的列举和说明：

**1. 核心功能：代码序列化**

*   **将编译后的 JavaScript 代码及其相关元数据保存到缓存中。** 这段代码的主要目标是将 `SharedFunctionInfo` 对象及其引用的其他对象（例如 `Script`、`BytecodeArray` 等）转换为字节流，以便存储起来。
*   **用于代码缓存 (Code Caching)。** 序列化的结果可以作为代码缓存存储在磁盘上或内存中。当 V8 再次需要执行相同的代码时，可以直接从缓存中加载，避免重新编译，从而提高性能。
*   **支持多种类型的对象序列化。**  代码中可以看到针对不同类型的对象（如 `Script`, `SharedFunctionInfo`, `ScopeInfo` 等）有特定的序列化逻辑，以确保所有必要的信息都被保存。
*   **处理嵌入式脚本和模块。** 代码中有针对嵌入式脚本和模块的特殊处理，确保它们也能被正确序列化。

**2. 关键类和函数的功能:**

*   **`CodeSerializer` 类:**
    *   是执行代码序列化的核心类。
    *   构造函数接收 `Isolate` 和 `source_hash` 作为参数。`source_hash` 用于在反序列化时验证源代码是否一致。
    *   `Serialize(Isolate* isolate, Handle<SharedFunctionInfo> info)`:  **静态方法**，作为序列化的入口点。它接收一个 `SharedFunctionInfo` 对象，并返回一个 `ScriptCompiler::CachedData` 对象，其中包含了序列化后的数据。
    *   `SerializeSharedFunctionInfo(Handle<SharedFunctionInfo> info)`:  负责序列化 `SharedFunctionInfo` 对象及其关联的数据。
    *   `SerializeObjectImpl(Handle<HeapObject> obj, SlotType slot_type)`:  根据对象的类型，调用相应的序列化逻辑。
    *   `SerializeGeneric(Handle<HeapObject> heap_object, SlotType slot_type)`:  通用的对象序列化方法。
*   **`AlignedCachedData` 类:**
    *   表示对齐的缓存数据。它存储了序列化后的字节流。
    *   负责管理缓存数据的内存，并确保数据是对齐的，这对于某些平台上的性能至关重要。
*   **`SerializedCodeData` 类:**
    *   表示序列化后的代码数据，包含头部信息和实际的代码载荷。
    *   头部信息存储了魔数、版本号、源哈希、标志哈希、校验和等，用于在反序列化时进行完整性校验。
    *   `SanityCheck()` 方法用于验证反序列化数据的完整性和一致性。
    *   `SourceHash()` 方法用于计算源代码的哈希值。

**3. 与 JavaScript 功能的关系及 JavaScript 示例:**

这段 C++ 代码是 V8 引擎内部实现的一部分，直接服务于 JavaScript 代码的执行效率。  它的功能体现在 JavaScript 代码的 **首次编译和后续加载** 过程中。

**JavaScript 示例:**

```javascript
// 假设我们有以下 JavaScript 代码：
function greet(name) {
  return `Hello, ${name}!`;
}

// 首次执行 greet 函数，V8 会对其进行编译
greet("World");

// 之后再次执行 greet 函数，V8 可能会尝试从缓存中加载编译后的代码，
// 而 `code-serializer.cc` 就负责生成和管理这个缓存。
greet("V8");
```

在这个例子中，`code-serializer.cc` 的作用是在首次编译 `greet` 函数后，将其序列化并存储起来。当再次调用 `greet` 函数时，V8 可以通过反序列化之前保存的数据，快速恢复编译后的代码，而无需重新进行编译过程。

**4. 代码逻辑推理 (假设输入与输出):**

**假设输入:**

*   一个 `Isolate` 实例 (V8 引擎的隔离环境)。
*   一个 `Handle<SharedFunctionInfo>` 对象，代表 `greet` 函数的编译信息 (包含字节码等)。
*   假设 `greet` 函数的源代码是 `"function greet(name) { return \`Hello, ${name}!\`; }"`.

**输出:**

*   一个 `ScriptCompiler::CachedData` 对象，其中包含了序列化后的 `greet` 函数的信息。
*   这个 `CachedData` 对象会包含以下信息 (示意):
    *   **头部:**  魔数、V8 版本哈希、源代码的哈希值 (基于上面的源代码计算得到)、V8 编译选项的哈希值、校验和等。
    *   **载荷:**  序列化后的 `SharedFunctionInfo` 对象及其引用的 `BytecodeArray` (包含 `greet` 函数的字节码)、`Script` 对象 (包含源代码信息) 等。

**5. 用户常见的编程错误 (与代码缓存相关):**

用户直接操作或修改 V8 代码缓存的情况比较少见，因为这通常是由 V8 引擎自动管理的。但是，理解代码缓存的工作原理可以帮助避免一些潜在的性能问题。

**常见错误情景:**

*   **在生产环境和开发环境之间使用不兼容的代码缓存:**  如果开发环境和生产环境的 V8 版本、编译选项或源代码存在差异，那么在开发环境生成的代码缓存可能无法在生产环境中使用，或者会导致不可预测的行为。`SerializedCodeData` 中的头部信息（如版本哈希、标志哈希、源哈希）就是为了防止这种情况。
*   **错误地假设代码缓存总是有效:**  代码缓存可能会因为各种原因失效（例如，V8 版本升级、编译选项变更、源代码修改等）。程序不应该依赖于代码缓存的存在来保证正确性。
*   **没有充分利用代码缓存:**  对于需要重复执行的代码，确保 V8 能够正确地缓存它们是很重要的。例如，对于模块化的应用，确保模块的编译结果能够被缓存，可以显著提升加载速度。

**6. 功能归纳 (第1部分):**

总而言之，`v8/src/snapshot/code-serializer.cc` 的第一部分主要负责 **V8 引擎中已编译 JavaScript 代码的序列化过程**。它将编译后的代码及其元数据转换为可以存储的格式，为代码缓存机制提供基础，从而加速后续的代码加载和执行。  它关注于将 `SharedFunctionInfo` 及其相关对象序列化成字节流，并包含了用于验证数据完整性的头部信息。这部分代码是 V8 性能优化的关键组成部分。

根据你提供的代码片段，没有发现以 `.tq` 结尾的文件名，因此可以判断它不是 V8 Torque 源代码。

### 提示词
```
这是目录为v8/src/snapshot/code-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/code-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  result->AcquireData
```