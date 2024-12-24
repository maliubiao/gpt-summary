Response: The user wants a summary of the functionality of the C++ source code file `v8/src/heap/factory.cc`. The file seems to be responsible for creating various heap objects in the V8 JavaScript engine. Since this is part 1 of 4, I should focus on the functionality present in this specific chunk. I need to identify the core purpose of the `Factory` class and highlight key methods. If any of the operations relate to JavaScript concepts, I need to provide illustrative JavaScript examples.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The primary class in this file is `Factory`. The filename itself hints at its role: creating objects.

2. **Examine the Includes:** The included headers provide clues about the types of objects the `Factory` might be involved with. Keywords like `heap`, `objects`, `strings`, `code`, `context`, `promise`, `symbol` stand out. This suggests the `Factory` is central to instantiating various V8 internal representations of JavaScript concepts.

3. **Analyze the `CodeBuilder` Subclass:** The `CodeBuilder` nested class indicates a specific responsibility related to code generation. It deals with `CodeDesc`, `InstructionStream`, and `Code` objects, which are fundamental to how V8 compiles and executes JavaScript.

4. **Focus on `Factory` Class Methods:**  Go through the public methods of the `Factory` class. Many methods start with "New", strongly suggesting object creation. Note the types being created:
    * `Code` (via `CodeBuilder`)
    * Basic heap objects with `AllocateRaw` and `New`
    * Specific structures like `PrototypeInfo`, `EnumCache`, `Tuple2`
    * Special values like `Hole`
    * Arrays: `PropertyArray`, `FixedArray`, `FeedbackVector`, `EmbedderDataArray`, `FixedDoubleArray`
    * Hash tables: `SmallOrderedHashSet`, `SmallOrderedHashMap`, `SmallOrderedNameDictionary`, `OrderedHashSet`, `OrderedHashMap`, `NameDictionary`, `SwissNameDictionary`
    * Descriptor objects: `PropertyDescriptorObject`
    * Strings (various encodings and types): `InternalizeUtf8String`, `InternalizeString`, `NewStringFromUtf8`, `NewStringFromTwoByte`, `NewCopiedSubstring`, `NewProperSubString`, `NewExternalStringFromOneByte`, `NewExternalStringFromTwoByte`, `NewJSStringIterator`
    * Symbols: `NewSymbolInternal`, `NewSymbol`, `NewPrivateSymbol`, `NewPrivateNameSymbol`
    * Contexts (various types): `NewContextInternal`, `NewNativeContext`, `NewScriptContext`, `NewModuleContext`, `NewFunctionContext`, `NewCatchContext`, `NewDebugEvaluateContext`, `NewWithContext`, `NewBlockContext`, `NewBuiltinContext`
    * Tasks: `NewCallableTask`, `NewCallbackTask`, `NewPromiseResolveThenableJobTask`
    * Miscellaneous: `AliasedArgumentsEntry`, `AccessorInfo`, `ErrorStackData`, `Script`

5. **Identify Core Functionality:**  Based on the methods, the `Factory` class is a central point for creating various V8 internal objects. It handles memory allocation, object initialization, and potentially some level of interning (e.g., strings).

6. **Relate to JavaScript (and provide examples):**
    * **Strings:**  JavaScript strings are created and managed by the V8 string creation methods. Example: `const str = "hello";`
    * **Arrays:**  JavaScript arrays correspond to V8's `FixedArray` or `JSArray`. Example: `const arr = [1, 2, 3];`
    * **Objects:**  JavaScript objects are built upon V8's heap objects and maps. Example: `const obj = { a: 1 };`
    * **Functions:** JavaScript functions have associated `Code` objects created using the `CodeBuilder`. Example: `function foo() {}`
    * **Contexts:**  JavaScript execution contexts are managed by V8's context creation methods.
    * **Symbols:** JavaScript symbols directly map to V8's `Symbol` objects. Example: `const sym = Symbol('desc');`
    * **Promises:**  JavaScript promises have corresponding internal structures created by the `Factory`. Example: `const promise = new Promise(() => {});`

7. **Structure the Summary:**  Start with a high-level overview of the file's purpose. Then, elaborate on the key functionalities, focusing on object creation. Mention the role of `CodeBuilder`. Finally, provide JavaScript examples to illustrate the connection to JavaScript concepts. Emphasize that this is only part 1 and the summary is based on this section alone.
这个C++代码文件 `v8/src/heap/factory.cc` 的主要功能是 **为 V8 引擎的堆 (heap) 创建各种类型的对象**。

更具体地说，它实现了 `Factory` 类，该类提供了一系列静态方法，用于分配和初始化 V8 内部使用的各种对象，包括：

* **代码对象 (Code objects):**  使用 `CodeBuilder` 辅助类来创建，用于存储编译后的 JavaScript 代码。
* **基本的堆对象 (Heap objects):**  例如，通过 `AllocateRaw` 和 `New` 方法分配内存和设置 Map 指针。
* **结构体对象 (Struct objects):**  例如 `PrototypeInfo`，`EnumCache`，`Tuple2` 等。
* **特殊值对象:** 例如 `Hole`。
* **数组对象 (Array objects):** 例如 `PropertyArray`, `FixedArray`, `FeedbackVector`, `EmbedderDataArray` 等。
* **哈希表对象 (Hash table objects):** 例如 `SmallOrderedHashSet`, `SmallOrderedHashMap`, `NameDictionary` 等。
* **属性描述符对象 (Property descriptor objects):** 例如 `PropertyDescriptorObject`。
* **字符串对象 (String objects):**  各种类型的字符串，包括 UTF-8 字符串，双字节字符串，内部化字符串，外部字符串等。
* **符号对象 (Symbol objects):**  包括公共符号和私有符号。
* **上下文对象 (Context objects):**  各种类型的执行上下文，例如 `NativeContext`, `ScriptContext`, `FunctionContext` 等。
* **任务对象 (Task objects):** 用于微任务队列，例如 `CallableTask`, `CallbackTask` 等。
* **其他对象:** 例如 `AliasedArgumentsEntry`, `AccessorInfo`, `ErrorStackData`, `Script` 等。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

`Factory` 类创建的这些对象是 V8 引擎内部表示 JavaScript 语言构造的基础。  每当你创建 JavaScript 中的一个值或者执行一段代码时，V8 都会在内部创建相应的堆对象。

以下是一些 JavaScript 功能与 `factory.cc` 中对象创建的关联示例：

1. **创建字符串:**

   ```javascript
   const str = "hello";
   ```

   在 V8 内部，`Factory` 类中的 `NewStringFromUtf8` 或 `NewStringFromTwoByte` 等方法会被调用来创建表示这个字符串的 `SeqOneByteString` 或 `SeqTwoByteString` 对象。 `InternalizeString` 方法则用于创建具有唯一性的字符串，例如用于对象属性名。

2. **创建数组:**

   ```javascript
   const arr = [1, 2, 3];
   ```

   V8 会使用 `Factory::NewFixedArray` 或 `Factory::NewJSArray` (可能在其他文件中) 来创建内部的 `FixedArray` 或 `JSArray` 对象来存储数组的元素。

3. **创建对象:**

   ```javascript
   const obj = { a: 1, b: 2 };
   ```

   V8 会使用 `Factory::NewJSObjectFromMap` (可能在其他文件中) 来创建 `JSObject` 对象，并使用 `Factory` 创建的 `Map` 对象来描述对象的结构和属性。

4. **创建函数:**

   ```javascript
   function foo() {
       console.log("hello");
   }
   ```

   当函数被编译时，`Factory::CodeBuilder` 会被用来创建 `Code` 对象，其中包含编译后的机器码。 `Factory::NewJSFunction` (可能在其他文件中) 会创建 `JSFunction` 对象，将 `Code` 对象和函数的其他元数据关联起来。

5. **创建 Symbol:**

   ```javascript
   const sym = Symbol("mySymbol");
   ```

   `Factory::NewSymbol` 方法会被调用来创建内部的 `Symbol` 对象。

6. **创建 Promise:**

   ```javascript
   const promise = new Promise((resolve, reject) => {
       // ...
   });
   ```

   V8 会使用 `Factory` 创建 `JSPromise` 对象以及相关的处理函数等。

7. **执行上下文:**

   当 JavaScript 代码执行时，V8 会创建不同类型的执行上下文，例如全局上下文、函数上下文等，这些上下文对象是通过 `Factory` 类中的 `NewNativeContext`, `NewFunctionContext` 等方法创建的。

总而言之， `v8/src/heap/factory.cc` 是 V8 引擎中一个非常核心的文件，它就像一个 "工厂"，负责生产引擎运行所需的各种各样的内部对象，这些对象是理解 V8 如何表示和管理 JavaScript 代码和数据的关键。由于这是第 1 部分，因此它只包含了 `Factory` 类的一部分功能，后续的部分会继续扩展其对象创建的能力。

Prompt: 
```
这是目录为v8/src/heap/factory.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/factory.h"

#include <algorithm>  // For copy
#include <memory>     // For shared_ptr<>
#include <optional>
#include <string>
#include <utility>  // For move

#include "src/ast/ast-source-ranges.h"
#include "src/base/bits.h"
#include "src/builtins/accessors.h"
#include "src/builtins/constants-table-builder.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/diagnostics/basic-block-profiler.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/flags/flags.h"
#include "src/heap/heap-allocator-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/read-only-heap.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/init/bootstrapper.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/conversions.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/allocation-site-scopes.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/bigint.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/cell-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/foreign-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/microtask-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects.h"
#include "src/objects/promise-inl.h"
#include "src/objects/property-descriptor-object-inl.h"
#include "src/objects/scope-info.h"
#include "src/objects/string-set-inl.h"
#include "src/objects/struct-inl.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/templates.h"
#include "src/objects/transitions-inl.h"
#include "src/roots/roots-inl.h"
#include "src/roots/roots.h"
#include "src/strings/unicode-inl.h"
#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-code-pointer-table-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/wasm-value.h"
#endif

#include "src/heap/local-factory-inl.h"
#include "src/heap/local-heap-inl.h"

namespace v8 {
namespace internal {

Factory::CodeBuilder::CodeBuilder(Isolate* isolate, const CodeDesc& desc,
                                  CodeKind kind)
    : isolate_(isolate),
      local_isolate_(isolate_->main_thread_local_isolate()),
      code_desc_(desc),
      kind_(kind) {}

Factory::CodeBuilder::CodeBuilder(LocalIsolate* local_isolate,
                                  const CodeDesc& desc, CodeKind kind)
    : isolate_(local_isolate->GetMainThreadIsolateUnsafe()),
      local_isolate_(local_isolate),
      code_desc_(desc),
      kind_(kind) {}

Handle<TrustedByteArray> Factory::CodeBuilder::NewTrustedByteArray(int length) {
  return local_isolate_->factory()->NewTrustedByteArray(length);
}

Handle<Code> Factory::CodeBuilder::NewCode(const NewCodeOptions& options) {
  return local_isolate_->factory()->NewCode(options);
}

MaybeHandle<Code> Factory::CodeBuilder::BuildInternal(
    bool retry_allocation_or_fail) {
  DirectHandle<TrustedByteArray> reloc_info =
      NewTrustedByteArray(code_desc_.reloc_size);

  // Basic block profiling data for builtins is stored in the JS heap rather
  // than in separately-allocated C++ objects. Allocate that data now if
  // appropriate.
  Handle<OnHeapBasicBlockProfilerData> on_heap_profiler_data;
  if (V8_UNLIKELY(profiler_data_ && isolate_->IsGeneratingEmbeddedBuiltins())) {
    on_heap_profiler_data = profiler_data_->CopyToJSHeap(isolate_);

    // Add the on-heap data to a global list, which keeps it alive and allows
    // iteration.
    Handle<ArrayList> list(isolate_->heap()->basic_block_profiling_data(),
                           isolate_);
    DirectHandle<ArrayList> new_list = ArrayList::Add(
        isolate_, list, on_heap_profiler_data, AllocationType::kOld);
    isolate_->heap()->SetBasicBlockProfilingData(new_list);
  }

  Tagged<HeapObject> istream_allocation =
      AllocateUninitializedInstructionStream(retry_allocation_or_fail);
  if (istream_allocation.is_null()) {
    return {};
  }

  Handle<InstructionStream> istream;
  {
    // The InstructionStream object has not been fully initialized yet. We
    // rely on the fact that no allocation will happen from this point on.
    DisallowGarbageCollection no_gc;
    Tagged<InstructionStream> raw_istream = InstructionStream::Initialize(
        istream_allocation,
        ReadOnlyRoots(local_isolate_).instruction_stream_map(),
        code_desc_.body_size(), code_desc_.constant_pool_offset, *reloc_info);
    istream = handle(raw_istream, local_isolate_);
    DCHECK(IsAligned(istream->instruction_start(), kCodeAlignment));
    DCHECK_IMPLIES(!local_isolate_->heap()->heap()->code_region().is_empty(),
                   local_isolate_->heap()->heap()->code_region().contains(
                       istream->address()));
  }

  Handle<Code> code;
  {
    static_assert(InstructionStream::kOnHeapBodyIsContiguous);

    NewCodeOptions new_code_options = {
        kind_,
        builtin_,
        is_context_specialized_,
        is_turbofanned_,
        parameter_count_,
        code_desc_.instruction_size(),
        code_desc_.metadata_size(),
        inlined_bytecode_size_,
        osr_offset_,
        code_desc_.handler_table_offset_relative(),
        code_desc_.constant_pool_offset_relative(),
        code_desc_.code_comments_offset_relative(),
        code_desc_.builtin_jump_table_info_offset_relative(),
        code_desc_.unwinding_info_offset_relative(),
        interpreter_data_,
        deoptimization_data_,
        bytecode_offset_table_,
        source_position_table_,
        istream,
        /*instruction_start=*/kNullAddress,
    };
    code = NewCode(new_code_options);
    DCHECK_EQ(istream->body_size(), code->body_size());

    {
      DisallowGarbageCollection no_gc;
      Tagged<InstructionStream> raw_istream = *istream;

      // Allow self references to created code object by patching the handle to
      // point to the newly allocated InstructionStream object.
      Handle<Object> self_reference;
      if (self_reference_.ToHandle(&self_reference)) {
        DCHECK_EQ(*self_reference,
                  ReadOnlyRoots(isolate_).self_reference_marker());
        DCHECK_NE(kind_, CodeKind::BASELINE);
        if (isolate_->IsGeneratingEmbeddedBuiltins()) {
          isolate_->builtins_constants_table_builder()->PatchSelfReference(
              self_reference, istream);
        }
        self_reference.PatchValue(raw_istream);
      }

      // Likewise, any references to the basic block counters marker need to be
      // updated to point to the newly-allocated counters array.
      if (V8_UNLIKELY(!on_heap_profiler_data.is_null())) {
        isolate_->builtins_constants_table_builder()
            ->PatchBasicBlockCountersReference(
                handle(on_heap_profiler_data->counts(), isolate_));
      }

      // Migrate generated code.
      // The generated code can contain embedded objects (typically from
      // handles) in a pointer-to-tagged-value format (i.e. with indirection
      // like a handle) that are dereferenced during the copy to point
      // directly to the actual heap objects. These pointers can include
      // references to the code object itself, through the self_reference
      // parameter.
      istream->Finalize(*code, *reloc_info, code_desc_, isolate_->heap());

#ifdef VERIFY_HEAP
      if (v8_flags.verify_heap) {
        HeapObject::VerifyCodePointer(isolate_, raw_istream);
      }
#endif
    }
  }

  // TODO(leszeks): Remove stack_slots_, it's already in the instruction stream.
  DCHECK_EQ(stack_slots_, code->stack_slots());

#ifdef ENABLE_DISASSEMBLER
  if (V8_UNLIKELY(profiler_data_ && v8_flags.turbo_profiling_verbose)) {
    std::ostringstream os;
    code->Disassemble(nullptr, os, isolate_);
    if (!on_heap_profiler_data.is_null()) {
      DirectHandle<String> disassembly =
          local_isolate_->factory()->NewStringFromAsciiChecked(
              os.str().c_str(), AllocationType::kOld);
      on_heap_profiler_data->set_code(*disassembly);
    } else {
      profiler_data_->SetCode(os);
    }
  }
#endif  // ENABLE_DISASSEMBLER

  return code;
}

Tagged<HeapObject> Factory::CodeBuilder::AllocateUninitializedInstructionStream(
    bool retry_allocation_or_fail) {
  LocalHeap* heap = local_isolate_->heap();
  Tagged<HeapObject> result;
  const int object_size = InstructionStream::SizeFor(code_desc_.body_size());
  if (retry_allocation_or_fail) {
    // Only allowed to do `retry_allocation_or_fail` from the main thread.
    // TODO(leszeks): Remove the retrying allocation, always use TryBuild in
    // the code builder.
    DCHECK(local_isolate_->is_main_thread());
    result =
        heap->heap()->allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
            object_size, AllocationType::kCode, AllocationOrigin::kRuntime);
    CHECK(!result.is_null());
    return result;
  } else {
    // Return null if we cannot allocate the code object.
    return heap->AllocateRawWith<HeapAllocator::kLightRetry>(
        object_size, AllocationType::kCode);
  }
}

MaybeHandle<Code> Factory::CodeBuilder::TryBuild() {
  return BuildInternal(false);
}

Handle<Code> Factory::CodeBuilder::Build() {
  return BuildInternal(true).ToHandleChecked();
}

Tagged<HeapObject> Factory::AllocateRaw(int size, AllocationType allocation,
                                        AllocationAlignment alignment) {
  return allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
      size, allocation, AllocationOrigin::kRuntime, alignment);
}

Tagged<HeapObject> Factory::AllocateRawWithAllocationSite(
    DirectHandle<Map> map, AllocationType allocation,
    DirectHandle<AllocationSite> allocation_site) {
  DCHECK(map->instance_type() != MAP_TYPE);
  int size = map->instance_size();
  if (!allocation_site.is_null()) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    size += ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
  }
  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(size,
                                                                allocation);
  WriteBarrierMode write_barrier_mode = allocation == AllocationType::kYoung
                                            ? SKIP_WRITE_BARRIER
                                            : UPDATE_WRITE_BARRIER;
  result->set_map_after_allocation(isolate(), *map, write_barrier_mode);
  if (!allocation_site.is_null()) {
    int aligned_size = ALIGN_TO_ALLOCATION_ALIGNMENT(map->instance_size());
    Tagged<AllocationMemento> alloc_memento = UncheckedCast<AllocationMemento>(
        Tagged<Object>(result.ptr() + aligned_size));
    InitializeAllocationMemento(alloc_memento, *allocation_site);
  }
  return result;
}

void Factory::InitializeAllocationMemento(
    Tagged<AllocationMemento> memento, Tagged<AllocationSite> allocation_site) {
  DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
  memento->set_map_after_allocation(isolate(), *allocation_memento_map(),
                                    SKIP_WRITE_BARRIER);
  memento->set_allocation_site(allocation_site, SKIP_WRITE_BARRIER);
  if (v8_flags.allocation_site_pretenuring) {
    allocation_site->IncrementMementoCreateCount();
  }
}

Tagged<HeapObject> Factory::New(DirectHandle<Map> map,
                                AllocationType allocation) {
  DCHECK(map->instance_type() != MAP_TYPE);
  int size = map->instance_size();
  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(size,
                                                                allocation);
  // New space objects are allocated white.
  WriteBarrierMode write_barrier_mode = allocation == AllocationType::kYoung
                                            ? SKIP_WRITE_BARRIER
                                            : UPDATE_WRITE_BARRIER;
  result->set_map_after_allocation(isolate(), *map, write_barrier_mode);
  return result;
}

Handle<HeapObject> Factory::NewFillerObject(int size,
                                            AllocationAlignment alignment,
                                            AllocationType allocation,
                                            AllocationOrigin origin) {
  Heap* heap = isolate()->heap();
  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
          size, allocation, origin, alignment);
  heap->CreateFillerObjectAt(result.address(), size);
  return Handle<HeapObject>(result, isolate());
}

Handle<PrototypeInfo> Factory::NewPrototypeInfo() {
  auto result = NewStructInternal<PrototypeInfo>(PROTOTYPE_INFO_TYPE,
                                                 AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  result->set_prototype_users(Smi::zero());
  result->set_registry_slot(MemoryChunk::UNREGISTERED);
  result->set_bit_field(0);
  result->set_module_namespace(*undefined_value(), SKIP_WRITE_BARRIER);
  return handle(result, isolate());
}

Handle<EnumCache> Factory::NewEnumCache(DirectHandle<FixedArray> keys,
                                        DirectHandle<FixedArray> indices,
                                        AllocationType allocation) {
  DCHECK(allocation == AllocationType::kOld ||
         allocation == AllocationType::kSharedOld);
  DCHECK_EQ(allocation == AllocationType::kSharedOld,
            HeapLayout::InAnySharedSpace(*keys) &&
                HeapLayout::InAnySharedSpace(*indices));
  auto result = NewStructInternal<EnumCache>(ENUM_CACHE_TYPE, allocation);
  DisallowGarbageCollection no_gc;
  result->set_keys(*keys);
  result->set_indices(*indices);
  return handle(result, isolate());
}

Handle<Tuple2> Factory::NewTuple2Uninitialized(AllocationType allocation) {
  auto result = NewStructInternal<Tuple2>(TUPLE2_TYPE, allocation);
  return handle(result, isolate());
}

Handle<Tuple2> Factory::NewTuple2(DirectHandle<Object> value1,
                                  DirectHandle<Object> value2,
                                  AllocationType allocation) {
  auto result = NewStructInternal<Tuple2>(TUPLE2_TYPE, allocation);
  DisallowGarbageCollection no_gc;
  result->set_value1(*value1);
  result->set_value2(*value2);
  return handle(result, isolate());
}

Handle<Hole> Factory::NewHole() {
  Handle<Hole> hole(Cast<Hole>(New(hole_map(), AllocationType::kReadOnly)),
                    isolate());
  Hole::Initialize(isolate(), hole, hole_nan_value());
  return hole;
}

Handle<PropertyArray> Factory::NewPropertyArray(int length,
                                                AllocationType allocation) {
  DCHECK_LE(0, length);
  if (length == 0) return empty_property_array();
  Tagged<HeapObject> result = AllocateRawFixedArray(length, allocation);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(isolate(), *property_array_map(),
                                   SKIP_WRITE_BARRIER);
  Tagged<PropertyArray> array = Cast<PropertyArray>(result);
  array->initialize_length(length);
  MemsetTagged(array->data_start(), read_only_roots().undefined_value(),
               length);
  return handle(array, isolate());
}

MaybeHandle<FixedArray> Factory::TryNewFixedArray(
    int length, AllocationType allocation_type) {
  DCHECK_LE(0, length);
  if (length == 0) return empty_fixed_array();

  int size = FixedArray::SizeFor(length);
  Heap* heap = isolate()->heap();
  AllocationResult allocation = heap->AllocateRaw(size, allocation_type);
  Tagged<HeapObject> result;
  if (!allocation.To(&result)) return MaybeHandle<FixedArray>();
  if ((size > heap->MaxRegularHeapObjectSize(allocation_type)) &&
      v8_flags.use_marking_progress_bar) {
    LargePageMetadata::FromHeapObject(result)->MarkingProgressTracker().Enable(
        size);
  }
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(isolate(), *fixed_array_map(),
                                   SKIP_WRITE_BARRIER);
  Tagged<FixedArray> array = Cast<FixedArray>(result);
  array->set_length(length);
  MemsetTagged(array->RawFieldOfFirstElement(), *undefined_value(), length);
  return handle(array, isolate());
}

Handle<FeedbackVector> Factory::NewFeedbackVector(
    DirectHandle<SharedFunctionInfo> shared,
    DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array,
    DirectHandle<FeedbackCell> parent_feedback_cell) {
  int length = shared->feedback_metadata()->slot_count();
  DCHECK_LE(0, length);
  int size = FeedbackVector::SizeFor(length);

  Tagged<FeedbackVector> vector =
      Cast<FeedbackVector>(AllocateRawWithImmortalMap(
          size, AllocationType::kOld, *feedback_vector_map()));
  DisallowGarbageCollection no_gc;
  vector->set_shared_function_info(*shared);
  vector->set_length(length);
  vector->set_invocation_count(0);
  vector->set_invocation_count_before_stable(0);
  vector->reset_osr_state();
  vector->reset_flags();
#ifndef V8_ENABLE_LEAPTIERING
  vector->set_maybe_optimized_code(ClearedValue(isolate()));
  vector->set_log_next_execution(v8_flags.log_function_events);
#endif  // !V8_ENABLE_LEAPTIERING
  vector->set_closure_feedback_cell_array(*closure_feedback_cell_array);
  vector->set_parent_feedback_cell(*parent_feedback_cell);

  // TODO(leszeks): Initialize based on the feedback metadata.
  MemsetTagged(ObjectSlot(vector->slots_start()), *undefined_value(), length);
  return handle(vector, isolate());
}

Handle<EmbedderDataArray> Factory::NewEmbedderDataArray(int length) {
  DCHECK_LE(0, length);
  int size = EmbedderDataArray::SizeFor(length);
  Tagged<EmbedderDataArray> array =
      Cast<EmbedderDataArray>(AllocateRawWithImmortalMap(
          size, AllocationType::kYoung, *embedder_data_array_map()));
  DisallowGarbageCollection no_gc;
  array->set_length(length);

  if (length > 0) {
    for (int i = 0; i < length; i++) {
      // TODO(v8): consider initializing embedded data array with Smi::zero().
      EmbedderDataSlot(array, i).Initialize(*undefined_value());
    }
  }
  return handle(array, isolate());
}

Handle<FixedArrayBase> Factory::NewFixedDoubleArrayWithHoles(int length) {
  DCHECK_LE(0, length);
  Handle<FixedArrayBase> array = NewFixedDoubleArray(length);
  if (length > 0) {
    Cast<FixedDoubleArray>(array)->FillWithHoles(0, length);
  }
  return array;
}

template <typename T>
Handle<T> Factory::AllocateSmallOrderedHashTable(DirectHandle<Map> map,
                                                 int capacity,
                                                 AllocationType allocation) {
  // Capacity must be a power of two, since we depend on being able
  // to divide and multiple by 2 (kLoadFactor) to derive capacity
  // from number of buckets. If we decide to change kLoadFactor
  // to something other than 2, capacity should be stored as another
  // field of this object.
  DCHECK_EQ(T::kLoadFactor, 2);
  capacity =
      base::bits::RoundUpToPowerOfTwo32(std::max({T::kMinCapacity, capacity}));
  capacity = std::min({capacity, T::kMaxCapacity});

  DCHECK_LT(0, capacity);
  DCHECK_EQ(0, capacity % T::kLoadFactor);

  int size = T::SizeFor(capacity);
  Tagged<HeapObject> result =
      AllocateRawWithImmortalMap(size, allocation, *map);
  Handle<T> table(Cast<T>(result), isolate());
  table->Initialize(isolate(), capacity);
  return table;
}

Handle<SmallOrderedHashSet> Factory::NewSmallOrderedHashSet(
    int capacity, AllocationType allocation) {
  return AllocateSmallOrderedHashTable<SmallOrderedHashSet>(
      small_ordered_hash_set_map(), capacity, allocation);
}

Handle<SmallOrderedHashMap> Factory::NewSmallOrderedHashMap(
    int capacity, AllocationType allocation) {
  return AllocateSmallOrderedHashTable<SmallOrderedHashMap>(
      small_ordered_hash_map_map(), capacity, allocation);
}

Handle<SmallOrderedNameDictionary> Factory::NewSmallOrderedNameDictionary(
    int capacity, AllocationType allocation) {
  Handle<SmallOrderedNameDictionary> dict =
      AllocateSmallOrderedHashTable<SmallOrderedNameDictionary>(
          small_ordered_name_dictionary_map(), capacity, allocation);
  dict->SetHash(PropertyArray::kNoHashSentinel);
  return dict;
}

Handle<OrderedHashSet> Factory::NewOrderedHashSet() {
  return OrderedHashSet::Allocate(isolate(), OrderedHashSet::kInitialCapacity,
                                  AllocationType::kYoung)
      .ToHandleChecked();
}

Handle<OrderedHashMap> Factory::NewOrderedHashMap() {
  return OrderedHashMap::Allocate(isolate(), OrderedHashMap::kInitialCapacity,
                                  AllocationType::kYoung)
      .ToHandleChecked();
}

Handle<NameDictionary> Factory::NewNameDictionary(int at_least_space_for) {
  return NameDictionary::New(isolate(), at_least_space_for);
}

Handle<PropertyDescriptorObject> Factory::NewPropertyDescriptorObject() {
  auto object = NewStructInternal<PropertyDescriptorObject>(
      PROPERTY_DESCRIPTOR_OBJECT_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  object->set_flags(0);
  Tagged<Hole> the_hole = read_only_roots().the_hole_value();
  object->set_value(the_hole, SKIP_WRITE_BARRIER);
  object->set_get(the_hole, SKIP_WRITE_BARRIER);
  object->set_set(the_hole, SKIP_WRITE_BARRIER);
  return handle(object, isolate());
}

Handle<SwissNameDictionary> Factory::CreateCanonicalEmptySwissNameDictionary() {
  // This function is only supposed to be used to create the canonical empty
  // version and should not be used afterwards.
  DCHECK(!ReadOnlyRoots(isolate()).is_initialized(
      RootIndex::kEmptySwissPropertyDictionary));

  ReadOnlyRoots roots(isolate());

  DirectHandle<ByteArray> empty_meta_table =
      NewByteArray(SwissNameDictionary::kMetaTableEnumerationDataStartIndex,
                   AllocationType::kReadOnly);

  Tagged<Map> map = roots.swiss_name_dictionary_map();
  int size = SwissNameDictionary::SizeFor(0);
  Tagged<HeapObject> obj =
      AllocateRawWithImmortalMap(size, AllocationType::kReadOnly, map);
  Tagged<SwissNameDictionary> result = Cast<SwissNameDictionary>(obj);
  result->Initialize(isolate(), *empty_meta_table, 0);
  return handle(result, isolate());
}

// Internalized strings are created in the old generation (data space).
Handle<String> Factory::InternalizeUtf8String(base::Vector<const char> string) {
  base::Vector<const uint8_t> utf8_data =
      base::Vector<const uint8_t>::cast(string);
  Utf8Decoder decoder(utf8_data);
  if (decoder.is_ascii()) return InternalizeString(utf8_data);
  if (decoder.is_one_byte()) {
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[decoder.utf16_length()]);
    decoder.Decode(buffer.get(), utf8_data);
    return InternalizeString(
        base::Vector<const uint8_t>(buffer.get(), decoder.utf16_length()));
  }
  std::unique_ptr<uint16_t[]> buffer(new uint16_t[decoder.utf16_length()]);
  decoder.Decode(buffer.get(), utf8_data);
  return InternalizeString(
      base::Vector<const base::uc16>(buffer.get(), decoder.utf16_length()));
}

template <typename SeqString>
Handle<String> Factory::InternalizeString(Handle<SeqString> string, int from,
                                          int length, bool convert_encoding) {
  SeqSubStringKey<SeqString> key(isolate(), string, from, length,
                                 convert_encoding);
  return InternalizeStringWithKey(&key);
}

template Handle<String> Factory::InternalizeString(
    Handle<SeqOneByteString> string, int from, int length,
    bool convert_encoding);
template Handle<String> Factory::InternalizeString(
    Handle<SeqTwoByteString> string, int from, int length,
    bool convert_encoding);

namespace {
void ThrowInvalidEncodedStringBytes(Isolate* isolate, MessageTemplate message) {
#if V8_ENABLE_WEBASSEMBLY
  DCHECK(message == MessageTemplate::kWasmTrapStringInvalidWtf8 ||
         message == MessageTemplate::kWasmTrapStringInvalidUtf8);
  Handle<JSObject> error_obj = isolate->factory()->NewWasmRuntimeError(message);
  JSObject::AddProperty(isolate, error_obj,
                        isolate->factory()->wasm_uncatchable_symbol(),
                        isolate->factory()->true_value(), NONE);
  isolate->Throw(*error_obj);
#else
  // The default in JS-land is to use Utf8Variant::kLossyUtf8, which never
  // throws an error, so if there is no WebAssembly compiled in we'll never get
  // here.
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

template <typename Decoder, typename PeekBytes>
MaybeHandle<String> NewStringFromBytes(Isolate* isolate, PeekBytes peek_bytes,
                                       AllocationType allocation,
                                       MessageTemplate message) {
  Decoder decoder(peek_bytes());
  if (decoder.is_invalid()) {
    if (message != MessageTemplate::kNone) {
      ThrowInvalidEncodedStringBytes(isolate, message);
    }
    return MaybeHandle<String>();
  }

  if (decoder.utf16_length() == 0) return isolate->factory()->empty_string();

  if (decoder.is_one_byte()) {
    if (decoder.utf16_length() == 1) {
      uint8_t codepoint;
      decoder.Decode(&codepoint, peek_bytes());
      return isolate->factory()->LookupSingleCharacterStringFromCode(codepoint);
    }
    // Allocate string.
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               isolate->factory()->NewRawOneByteString(
                                   decoder.utf16_length(), allocation));

    DisallowGarbageCollection no_gc;
    decoder.Decode(result->GetChars(no_gc), peek_bytes());
    return result;
  }

  // Allocate string.
  Handle<SeqTwoByteString> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                             isolate->factory()->NewRawTwoByteString(
                                 decoder.utf16_length(), allocation));

  DisallowGarbageCollection no_gc;
  decoder.Decode(result->GetChars(no_gc), peek_bytes());
  return result;
}

template <typename PeekBytes>
MaybeHandle<String> NewStringFromUtf8Variant(Isolate* isolate,
                                             PeekBytes peek_bytes,
                                             unibrow::Utf8Variant utf8_variant,
                                             AllocationType allocation) {
  switch (utf8_variant) {
    case unibrow::Utf8Variant::kLossyUtf8:
      return NewStringFromBytes<Utf8Decoder>(isolate, peek_bytes, allocation,
                                             MessageTemplate::kNone);
#if V8_ENABLE_WEBASSEMBLY
    case unibrow::Utf8Variant::kUtf8:
      return NewStringFromBytes<StrictUtf8Decoder>(
          isolate, peek_bytes, allocation,
          MessageTemplate::kWasmTrapStringInvalidUtf8);
    case unibrow::Utf8Variant::kUtf8NoTrap:
      return NewStringFromBytes<StrictUtf8Decoder>(
          isolate, peek_bytes, allocation, MessageTemplate::kNone);
    case unibrow::Utf8Variant::kWtf8:
      return NewStringFromBytes<Wtf8Decoder>(
          isolate, peek_bytes, allocation,
          MessageTemplate::kWasmTrapStringInvalidWtf8);
#endif
  }
}

}  // namespace

MaybeHandle<String> Factory::NewStringFromUtf8(
    base::Vector<const uint8_t> string, unibrow::Utf8Variant utf8_variant,
    AllocationType allocation) {
  if (string.size() > kMaxInt) {
    // The Utf8Decode can't handle longer inputs, and we couldn't create
    // strings from them anyway.
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  auto peek_bytes = [&]() -> base::Vector<const uint8_t> { return string; };
  return NewStringFromUtf8Variant(isolate(), peek_bytes, utf8_variant,
                                  allocation);
}

MaybeHandle<String> Factory::NewStringFromUtf8(base::Vector<const char> string,
                                               AllocationType allocation) {
  return NewStringFromUtf8(base::Vector<const uint8_t>::cast(string),
                           unibrow::Utf8Variant::kLossyUtf8, allocation);
}

#if V8_ENABLE_WEBASSEMBLY
MaybeHandle<String> Factory::NewStringFromUtf8(
    DirectHandle<WasmArray> array, uint32_t start, uint32_t end,
    unibrow::Utf8Variant utf8_variant, AllocationType allocation) {
  DCHECK_EQ(sizeof(uint8_t), array->type()->element_type().value_kind_size());
  DCHECK_LE(start, end);
  DCHECK_LE(end, array->length());
  // {end - start} can never be more than what the Utf8Decoder can handle.
  static_assert(WasmArray::MaxLength(sizeof(uint8_t)) <= kMaxInt);
  auto peek_bytes = [&]() -> base::Vector<const uint8_t> {
    const uint8_t* contents =
        reinterpret_cast<const uint8_t*>(array->ElementAddress(0));
    return {contents + start, end - start};
  };
  return NewStringFromUtf8Variant(isolate(), peek_bytes, utf8_variant,
                                  allocation);
}

MaybeHandle<String> Factory::NewStringFromUtf8(
    DirectHandle<ByteArray> array, uint32_t start, uint32_t end,
    unibrow::Utf8Variant utf8_variant, AllocationType allocation) {
  DCHECK_LE(start, end);
  DCHECK_LE(end, array->length());
  // {end - start} can never be more than what the Utf8Decoder can handle.
  static_assert(ByteArray::kMaxLength <= kMaxInt);
  auto peek_bytes = [&]() -> base::Vector<const uint8_t> {
    const uint8_t* contents = reinterpret_cast<const uint8_t*>(array->begin());
    return {contents + start, end - start};
  };
  return NewStringFromUtf8Variant(isolate(), peek_bytes, utf8_variant,
                                  allocation);
}

namespace {
struct Wtf16Decoder {
  int length_;
  bool is_one_byte_;
  explicit Wtf16Decoder(base::Vector<const uint16_t> data)
      : length_(data.length()),
        is_one_byte_(String::IsOneByte(data.begin(), length_)) {}
  bool is_invalid() const { return false; }
  bool is_one_byte() const { return is_one_byte_; }
  int utf16_length() const { return length_; }
  template <typename Char>
  void Decode(Char* out, base::Vector<const uint16_t> data) {
    CopyChars(out, data.begin(), length_);
  }
};
}  // namespace

MaybeHandle<String> Factory::NewStringFromUtf16(DirectHandle<WasmArray> array,
                                                uint32_t start, uint32_t end,
                                                AllocationType allocation) {
  DCHECK_EQ(sizeof(uint16_t), array->type()->element_type().value_kind_size());
  DCHECK_LE(start, end);
  DCHECK_LE(end, array->length());
  // {end - start} can never be more than what the Utf8Decoder can handle.
  static_assert(WasmArray::MaxLength(sizeof(uint16_t)) <= kMaxInt);
  auto peek_bytes = [&]() -> base::Vector<const uint16_t> {
    const uint16_t* contents =
        reinterpret_cast<const uint16_t*>(array->ElementAddress(0));
    return {contents + start, end - start};
  };
  return NewStringFromBytes<Wtf16Decoder>(isolate(), peek_bytes, allocation,
                                          MessageTemplate::kNone);
}
#endif  // V8_ENABLE_WEBASSEMBLY

MaybeHandle<String> Factory::NewStringFromUtf8SubString(
    Handle<SeqOneByteString> str, int begin, int length,
    AllocationType allocation) {
  base::Vector<const uint8_t> utf8_data;
  {
    DisallowGarbageCollection no_gc;
    utf8_data =
        base::Vector<const uint8_t>(str->GetChars(no_gc) + begin, length);
  }
  Utf8Decoder decoder(utf8_data);

  if (length == 1) {
    uint16_t t;
    // Decode even in the case of length 1 since it can be a bad character.
    decoder.Decode(&t, utf8_data);
    return LookupSingleCharacterStringFromCode(t);
  }

  if (decoder.is_ascii()) {
    // If the string is ASCII, we can just make a substring.
    // TODO(v8): the allocation flag is ignored in this case.
    return NewSubString(str, begin, begin + length);
  }

  DCHECK_GT(decoder.utf16_length(), 0);

  if (decoder.is_one_byte()) {
    // Allocate string.
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        NewRawOneByteString(decoder.utf16_length(), allocation));
    DisallowGarbageCollection no_gc;
    // Update pointer references, since the original string may have moved after
    // allocation.
    utf8_data =
        base::Vector<const uint8_t>(str->GetChars(no_gc) + begin, length);
    decoder.Decode(result->GetChars(no_gc), utf8_data);
    return result;
  }

  // Allocate string.
  Handle<SeqTwoByteString> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate(), result,
      NewRawTwoByteString(decoder.utf16_length(), allocation));

  DisallowGarbageCollection no_gc;
  // Update pointer references, since the original string may have moved after
  // allocation.
  utf8_data = base::Vector<const uint8_t>(str->GetChars(no_gc) + begin, length);
  decoder.Decode(result->GetChars(no_gc), utf8_data);
  return result;
}

MaybeHandle<String> Factory::NewStringFromTwoByte(const base::uc16* string,
                                                  int length,
                                                  AllocationType allocation) {
  DCHECK_NE(allocation, AllocationType::kReadOnly);
  if (length == 0) return empty_string();
  if (String::IsOneByte(string, length)) {
    if (length == 1) return LookupSingleCharacterStringFromCode(string[0]);
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               NewRawOneByteString(length, allocation));
    DisallowGarbageCollection no_gc;
    CopyChars(result->GetChars(no_gc), string, length);
    return result;
  } else {
    Handle<SeqTwoByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               NewRawTwoByteString(length, allocation));
    DisallowGarbageCollection no_gc;
    CopyChars(result->GetChars(no_gc), string, length);
    return result;
  }
}

MaybeHandle<String> Factory::NewStringFromTwoByte(
    base::Vector<const base::uc16> string, AllocationType allocation) {
  return NewStringFromTwoByte(string.begin(), string.length(), allocation);
}

MaybeHandle<String> Factory::NewStringFromTwoByte(
    const ZoneVector<base::uc16>* string, AllocationType allocation) {
  return NewStringFromTwoByte(string->data(), static_cast<int>(string->size()),
                              allocation);
}

#if V8_ENABLE_WEBASSEMBLY
MaybeHandle<String> Factory::NewStringFromTwoByteLittleEndian(
    base::Vector<const base::uc16> str, AllocationType allocation) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
  return NewStringFromTwoByte(str, allocation);
#elif defined(V8_TARGET_BIG_ENDIAN)
  // TODO(12868): Duplicate the guts of NewStringFromTwoByte, so that
  // copying and transcoding the data can be done in a single pass.
  UNIMPLEMENTED();
#else
#error Unknown endianness
#endif
}
#endif  // V8_ENABLE_WEBASSEMBLY

Handle<String> Factory::NewInternalizedStringImpl(DirectHandle<String> string,
                                                  int len,
                                                  uint32_t hash_field) {
  if (string->IsOneByteRepresentation()) {
    Handle<SeqOneByteString> result =
        AllocateRawOneByteInternalizedString(len, hash_field);
    DisallowGarbageCollection no_gc;
    String::WriteToFlat(*string, result->GetChars(no_gc), 0, len);
    return result;
  }

  Handle<SeqTwoByteString> result =
      AllocateRawTwoByteInternalizedString(len, hash_field);
  DisallowGarbageCollection no_gc;
  String::WriteToFlat(*string, result->GetChars(no_gc), 0, len);
  return result;
}

StringTransitionStrategy Factory::ComputeInternalizationStrategyForString(
    DirectHandle<String> string, MaybeDirectHandle<Map>* internalized_map) {
  // The serializer requires internalized strings to be in ReadOnlySpace s.t.
  // other objects referencing the string can be allocated in RO space
  // themselves.
  if (isolate()->enable_ro_allocation_for_snapshot() &&
      isolate()->serializer_enabled()) {
    return StringTransitionStrategy::kCopy;
  }
  // Do not internalize young strings in-place: This allows us to ignore both
  // string table and stub cache on scavenges.
  if (HeapLayout::InYoungGeneration(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  // If the string table is shared, we need to copy if the string is not already
  // in the shared heap.
  if (v8_flags.shared_string_table && !HeapLayout::InAnySharedSpace(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  DCHECK_NOT_NULL(internalized_map);
  DisallowGarbageCollection no_gc;
  // This method may be called concurrently, so snapshot the map from the input
  // string instead of the calling IsType methods on HeapObject, which would
  // reload the map each time.
  Tagged<Map> map = string->map();
  *internalized_map = GetInPlaceInternalizedStringMap(map);
  if (!internalized_map->is_null()) {
    return StringTransitionStrategy::kInPlace;
  }
  if (InstanceTypeChecker::IsInternalizedString(map)) {
    return StringTransitionStrategy::kAlreadyTransitioned;
  }
  return StringTransitionStrategy::kCopy;
}

template <class StringClass>
Handle<StringClass> Factory::InternalizeExternalString(
    DirectHandle<String> string) {
  DirectHandle<Map> map =
      GetInPlaceInternalizedStringMap(string->map()).ToHandleChecked();
  Tagged<StringClass> external_string =
      Cast<StringClass>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  external_string->InitExternalPointerFields(isolate());
  Tagged<StringClass> cast_string = Cast<StringClass>(*string);
  external_string->set_length(cast_string->length());
  external_string->set_raw_hash_field(cast_string->raw_hash_field());
  external_string->SetResource(isolate(), nullptr);
  isolate()->heap()->RegisterExternalString(external_string);
  return handle(external_string, isolate());
}

template Handle<ExternalOneByteString> Factory::InternalizeExternalString<
    ExternalOneByteString>(DirectHandle<String>);
template Handle<ExternalTwoByteString> Factory::InternalizeExternalString<
    ExternalTwoByteString>(DirectHandle<String>);

StringTransitionStrategy Factory::ComputeSharingStrategyForString(
    DirectHandle<String> string, MaybeDirectHandle<Map>* shared_map) {
  DCHECK(v8_flags.shared_string_table);
  // TODO(pthier): Avoid copying LO-space strings. Update page flags instead.
  if (!HeapLayout::InAnySharedSpace(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  DCHECK_NOT_NULL(shared_map);
  DisallowGarbageCollection no_gc;
  InstanceType instance_type = string->map()->instance_type();
  if (StringShape(instance_type).IsShared()) {
    return StringTransitionStrategy::kAlreadyTransitioned;
  }
  switch (instance_type) {
    case SEQ_TWO_BYTE_STRING_TYPE:
      *shared_map = read_only_roots().shared_seq_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case SEQ_ONE_BYTE_STRING_TYPE:
      *shared_map = read_only_roots().shared_seq_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
      *shared_map =
          read_only_roots().shared_external_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
      *shared_map =
          read_only_roots().shared_external_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
      *shared_map = read_only_roots()
                        .shared_uncached_external_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
      *shared_map = read_only_roots()
                        .shared_uncached_external_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    default:
      return StringTransitionStrategy::kCopy;
  }
}

Handle<String> Factory::NewSurrogatePairString(uint16_t lead, uint16_t trail) {
  DCHECK_GE(lead, 0xD800);
  DCHECK_LE(lead, 0xDBFF);
  DCHECK_GE(trail, 0xDC00);
  DCHECK_LE(trail, 0xDFFF);

  Handle<SeqTwoByteString> str =
      isolate()->factory()->NewRawTwoByteString(2).ToHandleChecked();
  DisallowGarbageCollection no_gc;
  base::uc16* dest = str->GetChars(no_gc);
  dest[0] = lead;
  dest[1] = trail;
  return str;
}

Handle<String> Factory::NewCopiedSubstring(DirectHandle<String> str,
                                           uint32_t begin, uint32_t length) {
  DCHECK(str->IsFlat());  // Callers must flatten.
  DCHECK_GT(length, 0);   // Callers must handle empty string.
  bool one_byte;
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent flat = str->GetFlatContent(no_gc);
    if (flat.IsOneByte()) {
      one_byte = true;
    } else {
      one_byte = String::IsOneByte(flat.ToUC16Vector().data() + begin, length);
    }
  }
  if (one_byte) {
    Handle<SeqOneByteString> result =
        NewRawOneByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    uint8_t* dest = result->GetChars(no_gc);
    String::WriteToFlat(*str, dest, begin, length);
    return result;
  } else {
    Handle<SeqTwoByteString> result =
        NewRawTwoByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    base::uc16* dest = result->GetChars(no_gc);
    String::WriteToFlat(*str, dest, begin, length);
    return result;
  }
}

Handle<String> Factory::NewProperSubString(Handle<String> str, uint32_t begin,
                                           uint32_t end) {
#if VERIFY_HEAP
  if (v8_flags.verify_heap) str->StringVerify(isolate());
#endif
  DCHECK_LE(begin, str->length());
  DCHECK_LE(end, str->length());

  str = String::Flatten(isolate(), str);

  if (begin >= end) return empty_string();
  uint32_t length = end - begin;

  if (length == 1) {
    return LookupSingleCharacterStringFromCode(str->Get(begin));
  }
  if (length == 2) {
    // Optimization for 2-byte strings often used as keys in a decompression
    // dictionary.  Check whether we already have the string in the string
    // table to prevent creation of many unnecessary strings.
    uint16_t c1 = str->Get(begin);
    uint16_t c2 = str->Get(begin + 1);
    return MakeOrFindTwoCharacterString(c1, c2);
  }

  if (!v8_flags.string_slices || length < SlicedString::kMinLength) {
    return NewCopiedSubstring(str, begin, length);
  }

  int offset = begin;

  if (IsSlicedString(*str)) {
    auto slice = Cast<SlicedString>(str);
    str = Handle<String>(slice->parent(), isolate());
    offset += slice->offset();
  }
  if (IsThinString(*str)) {
    auto thin = Cast<ThinString>(str);
    str = handle(thin->actual(), isolate());
  }

  DCHECK(IsSeqString(*str) || IsExternalString(*str));
  DirectHandle<Map> map = str->IsOneByteRepresentation()
                              ? sliced_one_byte_string_map()
                              : sliced_two_byte_string_map();
  Tagged<SlicedString> slice =
      Cast<SlicedString>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  slice->set_raw_hash_field(String::kEmptyHashField);
  slice->set_length(length);
  slice->set_parent(*str);
  slice->set_offset(offset);
  return handle(slice, isolate());
}

MaybeHandle<String> Factory::NewExternalStringFromOneByte(
    const ExternalOneByteString::Resource* resource) {
  size_t length = resource->length();
  if (length > static_cast<size_t>(String::kMaxLength)) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  if (length == 0) return empty_string();

  DirectHandle<Map> map = resource->IsCacheable()
                              ? external_one_byte_string_map()
                              : uncached_external_one_byte_string_map();
  Tagged<ExternalOneByteString> external_string =
      Cast<ExternalOneByteString>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  external_string->InitExternalPointerFields(isolate());
  external_string->set_length(static_cast<int>(length));
  external_string->set_raw_hash_field(String::kEmptyHashField);
  external_string->SetResource(isolate(), resource);

  isolate()->heap()->RegisterExternalString(external_string);

  return Handle<String>(external_string, isolate());
}

MaybeHandle<String> Factory::NewExternalStringFromTwoByte(
    const ExternalTwoByteString::Resource* resource) {
  size_t length = resource->length();
  if (length > static_cast<size_t>(String::kMaxLength)) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  if (length == 0) return empty_string();

  DirectHandle<Map> map = resource->IsCacheable()
                              ? external_two_byte_string_map()
                              : uncached_external_two_byte_string_map();
  Tagged<ExternalTwoByteString> string =
      Cast<ExternalTwoByteString>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  string->InitExternalPointerFields(isolate());
  string->set_length(static_cast<int>(length));
  string->set_raw_hash_field(String::kEmptyHashField);
  string->SetResource(isolate(), resource);

  isolate()->heap()->RegisterExternalString(string);

  return Handle<ExternalTwoByteString>(string, isolate());
}

Handle<JSStringIterator> Factory::NewJSStringIterator(Handle<String> string) {
  DirectHandle<Map> map(
      isolate()->native_context()->initial_string_iterator_map(), isolate());
  DirectHandle<String> flat_string = String::Flatten(isolate(), string);
  Handle<JSStringIterator> iterator =
      Cast<JSStringIterator>(NewJSObjectFromMap(map));

  DisallowGarbageCollection no_gc;
  Tagged<JSStringIterator> raw = *iterator;
  raw->set_string(*flat_string);
  raw->set_index(0);
  return iterator;
}

Tagged<Symbol> Factory::NewSymbolInternal(AllocationType allocation) {
  DCHECK(allocation != AllocationType::kYoung);
  // Statically ensure that it is safe to allocate symbols in paged spaces.
  static_assert(sizeof(Symbol) <= kMaxRegularHeapObjectSize);

  Tagged<Symbol> symbol = Cast<Symbol>(AllocateRawWithImmortalMap(
      sizeof(Symbol), allocation, read_only_roots().symbol_map()));
  DisallowGarbageCollection no_gc;
  // Generate a random hash value.
  int hash = isolate()->GenerateIdentityHash(Name::HashBits::kMax);
  symbol->set_raw_hash_field(
      Name::CreateHashFieldValue(hash, Name::HashFieldType::kHash));
  if (isolate()->read_only_heap()->roots_init_complete()) {
    symbol->set_description(read_only_roots().undefined_value(),
                            SKIP_WRITE_BARRIER);
  } else {
    // Can't use setter during bootstrapping as its typecheck tries to access
    // the roots table before it is initialized.
    symbol->description_.store(&*symbol, read_only_roots().undefined_value(),
                               SKIP_WRITE_BARRIER);
  }
  symbol->set_flags(0);
  DCHECK(!symbol->is_private());
  return symbol;
}

Handle<Symbol> Factory::NewSymbol(AllocationType allocation) {
  return handle(NewSymbolInternal(allocation), isolate());
}

Handle<Symbol> Factory::NewPrivateSymbol(AllocationType allocation) {
  DCHECK(allocation != AllocationType::kYoung);
  Tagged<Symbol> symbol = NewSymbolInternal(allocation);
  DisallowGarbageCollection no_gc;
  symbol->set_is_private(true);
  return handle(symbol, isolate());
}

Handle<Symbol> Factory::NewPrivateNameSymbol(DirectHandle<String> name) {
  Tagged<Symbol> symbol = NewSymbolInternal();
  DisallowGarbageCollection no_gc;
  symbol->set_is_private_name();
  symbol->set_description(*name);
  return handle(symbol, isolate());
}

Tagged<Context> Factory::NewContextInternal(DirectHandle<Map> map, int size,
                                            int variadic_part_length,
                                            AllocationType allocation) {
  DCHECK_LE(Context::kTodoHeaderSize, size);
  DCHECK(IsAligned(size, kTaggedSize));
  DCHECK_LE(Context::MIN_CONTEXT_SLOTS, variadic_part_length);
  DCHECK_LE(Context::SizeFor(variadic_part_length), size);

  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(size,
                                                                allocation);
  result->set_map_after_allocation(isolate(), *map);
  DisallowGarbageCollection no_gc;
  Tagged<Context> context = Cast<Context>(result);
  context->set_length(variadic_part_length);
  DCHECK_EQ(context->SizeFromMap(*map), size);
  if (size > Context::kTodoHeaderSize) {
    ObjectSlot start = context->RawField(Context::kTodoHeaderSize);
    ObjectSlot end = context->RawField(size);
    size_t slot_count = end - start;
    MemsetTagged(start, *undefined_value(), slot_count);
  }
  return context;
}

// Creates new maps and new native context and wires them up.
//
// +-+------------->|NativeContext|
// | |                    |
// | |                   map
// | |                    v
// | |              |context_map| <Map(NATIVE_CONTEXT_TYPE)>
// | |                  |   |
// | +--native_context--+  map
// |                        v
// |   +------->|contextful_meta_map| <Map(MAP_TYPE)>
// |   |             |      |
// |   +-----map-----+      |
// |                        |
// +-----native_context-----+
//
Handle<NativeContext> Factory::NewNativeContext() {
  // All maps that belong to this new native context will have this meta map.
  // The native context does not exist yet, so create the map as contextless
  // for now.
  Handle<Map> contextful_meta_map = NewContextlessMap(MAP_TYPE, Map::kSize);
  contextful_meta_map->set_map(isolate(), *contextful_meta_map);

  Handle<Map> context_map = NewMapWithMetaMap(
      contextful_meta_map, NATIVE_CONTEXT_TYPE, kVariableSizeSentinel);

  if (v8_flags.log_maps) {
    LOG(isolate(),
        MapEvent("NewNativeContext", isolate()->factory()->meta_map(),
                 contextful_meta_map, "contextful meta map"));
    LOG(isolate(),
        MapEvent("NewNativeContext", isolate()->factory()->meta_map(),
                 context_map, "native context map"));
  }

  Tagged<NativeContext> context = Cast<NativeContext>(NewContextInternal(
      context_map, NativeContext::kSize, NativeContext::NATIVE_CONTEXT_SLOTS,
      AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  contextful_meta_map->set_native_context(context);
  context_map->set_native_context(context);
  context->set_meta_map(*contextful_meta_map);
  context->set_scope_info(*native_scope_info());
  context->set_previous(Context());
  context->set_extension(*undefined_value());
  context->set_errors_thrown(Smi::zero());
  context->set_is_wasm_js_installed(Smi::zero());
  context->set_is_wasm_jspi_installed(Smi::zero());
  context->set_math_random_index(Smi::zero());
  context->set_serialized_objects(*empty_fixed_array());
  context->init_microtask_queue(isolate(), nullptr);
  context->set_retained_maps(*empty_weak_array_list());
  return handle(context, isolate());
}

Handle<Context> Factory::NewScriptContext(DirectHandle<NativeContext> outer,
                                          DirectHandle<ScopeInfo> scope_info) {
  DCHECK(scope_info->is_script_scope());
  int variadic_part_length = scope_info->ContextLength();

  DirectHandle<FixedArray> side_data;
  if (v8_flags.const_tracking_let ||
      v8_flags.script_context_mutable_heap_number) {
    side_data = NewFixedArray(scope_info->ContextLocalCount());
  } else {
    side_data = empty_fixed_array();
  }
  Tagged<Context> context =
      NewContextInternal(handle(outer->script_context_map(), isolate()),
                         Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  context->set(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX, *side_data);
  DCHECK(context->IsScriptContext());
  return handle(context, isolate());
}

Handle<ScriptContextTable> Factory::NewScriptContextTable() {
  static constexpr int kInitialCapacity = 0;
  return ScriptContextTable::New(isolate(), kInitialCapacity);
}

Handle<Context> Factory::NewModuleContext(DirectHandle<SourceTextModule> module,
                                          DirectHandle<NativeContext> outer,
                                          DirectHandle<ScopeInfo> scope_info) {
  // TODO(v8:13567): Const tracking let in module contexts.
  DCHECK_EQ(scope_info->scope_type(), MODULE_SCOPE);
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context = NewContextInternal(
      isolate()->module_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  context->set_extension(*module);
  DCHECK(context->IsModuleContext());
  return handle(context, isolate());
}

Handle<Context> Factory::NewFunctionContext(
    DirectHandle<Context> outer, DirectHandle<ScopeInfo> scope_info) {
  DirectHandle<Map> map;
  switch (scope_info->scope_type()) {
    case EVAL_SCOPE:
      map = isolate()->eval_context_map();
      break;
    case FUNCTION_SCOPE:
      map = isolate()->function_context_map();
      break;
    default:
      UNREACHABLE();
  }
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context =
      NewContextInternal(map, Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  return handle(context, isolate());
}

#if V8_SINGLE_GENERATION_BOOL
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object)
#elif V8_ENABLE_STICKY_MARK_BITS_BOOL
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object)             \
  DCHECK_IMPLIES(!isolate->heap()->incremental_marking()->IsMajorMarking(), \
                 HeapLayout::InYoungGeneration(object))
#else
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object) \
  DCHECK(HeapLayout::InYoungGeneration(object))
#endif

Handle<Context> Factory::NewCatchContext(DirectHandle<Context> previous,
                                         DirectHandle<ScopeInfo> scope_info,
                                         DirectHandle<Object> thrown_object) {
  DCHECK_EQ(scope_info->scope_type(), CATCH_SCOPE);
  static_assert(Context::MIN_CONTEXT_SLOTS == Context::THROWN_OBJECT_INDEX);
  // TODO(ishell): Take the details from CatchContext class.
  int variadic_part_length = Context::MIN_CONTEXT_SLOTS + 1;
  Tagged<Context> context = NewContextInternal(
      isolate()->catch_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set(Context::THROWN_OBJECT_INDEX, *thrown_object,
               SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewDebugEvaluateContext(
    DirectHandle<Context> previous, DirectHandle<ScopeInfo> scope_info,
    DirectHandle<JSReceiver> extension, DirectHandle<Context> wrapped) {
  DCHECK(scope_info->IsDebugEvaluateScope());
  DirectHandle<HeapObject> ext = extension.is_null()
                                     ? Cast<HeapObject>(undefined_value())
                                     : Cast<HeapObject>(extension);
  // TODO(ishell): Take the details from DebugEvaluateContextContext class.
  int variadic_part_length = Context::MIN_CONTEXT_EXTENDED_SLOTS + 1;
  Tagged<Context> context =
      NewContextInternal(isolate()->debug_evaluate_context_map(),
                         Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set_extension(*ext, SKIP_WRITE_BARRIER);
  if (!wrapped.is_null()) {
    context->set(Context::WRAPPED_CONTEXT_INDEX, *wrapped, SKIP_WRITE_BARRIER);
  }
  return handle(context, isolate());
}

Handle<Context> Factory::NewWithContext(DirectHandle<Context> previous,
                                        DirectHandle<ScopeInfo> scope_info,
                                        DirectHandle<JSReceiver> extension) {
  DCHECK_EQ(scope_info->scope_type(), WITH_SCOPE);
  // TODO(ishell): Take the details from WithContext class.
  int variadic_part_length = Context::MIN_CONTEXT_EXTENDED_SLOTS;
  Tagged<Context> context = NewContextInternal(
      isolate()->with_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set_extension(*extension, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewBlockContext(DirectHandle<Context> previous,
                                         DirectHandle<ScopeInfo> scope_info) {
  DCHECK_IMPLIES(scope_info->scope_type() != BLOCK_SCOPE,
                 scope_info->scope_type() == CLASS_SCOPE);
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context = NewContextInternal(
      isolate()->block_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewBuiltinContext(
    DirectHandle<NativeContext> native_context, int variadic_part_length) {
  DCHECK_LE(Context::MIN_CONTEXT_SLOTS, variadic_part_length);
  Tagged<Context> context = NewContextInternal(
      isolate()->function_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(read_only_roots().empty_scope_info(),
                          SKIP_WRITE_BARRIER);
  context->set_previous(*native_context, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<AliasedArgumentsEntry> Factory::NewAliasedArgumentsEntry(
    int aliased_context_slot) {
  auto entry = NewStructInternal<AliasedArgumentsEntry>(
      ALIASED_ARGUMENTS_ENTRY_TYPE, AllocationType::kYoung);
  entry->set_aliased_context_slot(aliased_context_slot);
  return handle(entry, isolate());
}

Handle<AccessorInfo> Factory::NewAccessorInfo() {
  Tagged<AccessorInfo> info =
      Cast<AccessorInfo>(New(accessor_info_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  info->set_name(*empty_string(), SKIP_WRITE_BARRIER);
  info->set_data(*undefined_value(), SKIP_WRITE_BARRIER);
  info->set_flags(0);  // Must clear the flags, it was initialized as undefined.
  info->set_is_sloppy(true);
  info->set_initial_property_attributes(NONE);

  info->init_getter(isolate(), kNullAddress);
  info->init_setter(isolate(), kNullAddress);

  info->clear_padding();

  return handle(info, isolate());
}

Handle<ErrorStackData> Factory::NewErrorStackData(
    DirectHandle<UnionOf<JSAny, FixedArray>> call_site_infos_or_formatted_stack,
    DirectHandle<StackTraceInfo> stack_trace) {
  Tagged<ErrorStackData> error_stack_data = NewStructInternal<ErrorStackData>(
      ERROR_STACK_DATA_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  error_stack_data->set_call_site_infos_or_formatted_stack(
      *call_site_infos_or_formatted_stack, SKIP_WRITE_BARRIER);
  error_stack_data->set_stack_trace(*stack_trace, SKIP_WRITE_BARRIER);
  return handle(error_stack_data, isolate());
}

void Factory::ProcessNewScript(Handle<Script> script,
                               ScriptEventType script_event_type) {
  int script_id = script->id();
  if (script_id != Script::kTemporaryScriptId) {
    Handle<WeakArrayList> scripts = script_list();
    scripts = WeakArrayList::Append(isolate(), scripts,
                                    MaybeObjectDirectHandle::Weak(script),
                                    AllocationType::kOld);
    isolate()->heap()->set_script_list(*scripts);
  }
  if (IsString(script->source()) && isolate()->NeedsSourcePositions()) {
    Script::InitLineEnds(isolate(), script);
  }
  LOG(isolate(), ScriptEvent(script_event_type, script_id));
}

Handle<Script> Factory::CloneScript(DirectHandle<Script> script,
                                    DirectHandle<String> source) {
  int script_id = isolate()->GetNextScriptId();
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
  Handle<ArrayList> list = ArrayList::New(isolate(), 0);
#endif
  Handle<Script> new_script_handle =
      Cast<Script>(NewStruct(SCRIPT_TYPE, AllocationType::kOld));
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> new_script = *new_script_handle;
    const Tagged<Script> old_script = *script;
    new_script->set_source(*source);
    new_script->set_name(old_script->name());
    new_script->set_id(script_id);
    new_script->set_line_offset(old_script->line_offset());
    new_script->set_column_offset(old_script->column_offset());
    new_script->set_context_data(old_script->context_data());
    new_script->set_type(old_script->type());
    new_script->set_line_ends(Smi::zero());
    new_script->set_eval_from_shared_or_wrapped_arguments(
        script->eval_from_shared_or_wrapped_arguments());
    new_script->set_infos(*empty_weak_fixed_array(), SKIP_WRITE_BARRIER);
    new_script->set_eval_from_position(old_script->eval_from_position());
    new_script->set_flags(old_script->flags());
    new_script->set_host_defined_options(old_script->host_defined_options());
    new_script->set_source_hash(*undefined_value(), SKIP_WRITE_BARRIER);
    new_script->set_compiled_lazy_function_positions(*undefined_value(),
                                                     SKIP_WRITE_BARRIER);
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    new_script->set_script_or_modules(*list);
#endif
  }
  ProcessNewScript(new_script_handle, ScriptEventType::kCreate);
  return new_script_handle;
}

Handle<CallableTask> Factory::NewCallableTask(DirectHandle<JSReceiver> callable,
                                              DirectHandle<Context> context) {
  DCHECK(IsCallable(*callable));
  auto microtask = NewStructInternal<CallableTask>(CALLABLE_TASK_TYPE,
                                                   AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  microtask->set_callable(*callable, SKIP_WRITE_BARRIER);
  microtask->set_context(*context, SKIP_WRITE_BARRIER);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  microtask->set_continuation_preserved_embedder_data(
      isolate()->isolate_data()->continuation_preserved_embedder_data(),
      SKIP_WRITE_BARRIER);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return handle(microtask, isolate());
}

Handle<CallbackTask> Factory::NewCallbackTask(DirectHandle<Foreign> callback,
                                              DirectHandle<Foreign> data) {
  auto microtask = NewStructInternal<CallbackTask>(CALLBACK_TASK_TYPE,
                                                   AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  microtask->set_callback(*callback, SKIP_WRITE_BARRIER);
  microtask->set_data(*data, SKIP_WRITE_BARRIER);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  microtask->set_continuation_preserved_embedder_data(
      isolate()->isolate_data()->continuation_preserved_embedder_data(),
      SKIP_WRITE_BARRIER);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return handle(microtask, isolate());
}

Handle<PromiseResolveThenableJobTask> Factory::NewPromiseResolveThenableJobTask(
    DirectHandle<JSPromise> promise_to_resolve,
    DirectHandle<JSReceiver> thenable, DirectHandle<JSReceiver> then,
    DirectHandle<Context> context) {
  DCH
"""


```