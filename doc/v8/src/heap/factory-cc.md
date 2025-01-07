Response:
My thought process for analyzing the `factory.cc` code goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the `factory.cc` file's functionality within the V8 JavaScript engine. It also mentions Torque, JavaScript relationships, code logic, common errors, and a final summary for this first part.

2. **Initial Scan for Keywords and Structure:**  I quickly scan the code for obvious patterns and keywords. I see lots of `#include` statements, suggesting dependencies on other V8 components. The `namespace v8 { namespace internal {` indicates this is internal V8 code, not public API. The class `Factory` is central. I notice methods like `New...`, `Allocate...`, `Internalize...`, and `Build...`, which strongly suggest object creation and management.

3. **Identify Core Responsibility - Object Creation:** The name "Factory" itself is a huge clue. This class is responsible for *creating* various V8 objects. The numerous `New...` methods confirm this (e.g., `NewCode`, `NewString`, `NewFixedArray`).

4. **Categorize Object Types:** I start grouping the different `New...` methods based on the object types they create. This helps to organize the functionality. I see things like:
    * Code objects (`NewCode`, `CodeBuilder`)
    * Data structures (`NewFixedArray`, `NewPropertyArray`, `NewNameDictionary`, `NewOrderedHashSet`, `NewOrderedHashMap`)
    * Strings (`NewStringFromUtf8`, `InternalizeString`)
    * Meta-information (`NewPrototypeInfo`, `NewEnumCache`, `NewFeedbackVector`)
    * Basic building blocks (`NewFillerObject`, `NewHole`)

5. **Look for Supporting Mechanisms:**  Creating objects isn't just about allocating memory. I look for related operations:
    * **Allocation:** Methods like `AllocateRaw`, `AllocateRawWithAllocationSite` point to memory management within V8's heap.
    * **Initialization:**  The `Initialize` calls within the `New...` methods (e.g., `Hole::Initialize`) indicate how objects are set up after allocation.
    * **String Internalization:** The `InternalizeString` methods suggest an optimization for reusing string objects.

6. **Consider the "Why":**  I ask myself *why* V8 needs a factory. The answer lies in abstraction and control. The `Factory` class centralizes object creation, ensuring consistency, applying V8-specific allocation strategies (young vs. old generation), and potentially handling side effects or bookkeeping.

7. **Address Specific Questions in the Prompt:**
    * **Torque:**  The prompt asks about `.tq` files. I note that this file ends in `.cc`, not `.tq`, so it's not a Torque file.
    * **JavaScript Relationship:** I consider how these V8 internal objects relate to JavaScript. For instance, `JSArray` is built on `FixedArray`, JavaScript strings map to V8 `String` objects. I need to find concrete examples.
    * **Code Logic:** The `CodeBuilder` class stands out. It involves multiple steps and options for creating executable code. This is a good area for a hypothetical input/output scenario.
    * **Common Errors:** I think about common mistakes developers make related to memory or object handling, even though this is internal V8 code. String encoding issues and incorrect array sizing come to mind.

8. **Structure the Answer:** I organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the key functionalities, grouping related methods.
    * Address the specific points raised in the prompt (Torque, JavaScript, logic, errors).
    * Provide a concise summary for this "Part 1".

9. **Refine and Elaborate:** I review my initial thoughts, adding more detail and specific examples where needed. For the JavaScript examples, I aim for simple, illustrative code. For the code logic, I create a clear scenario with hypothetical inputs and expected outputs for the `CodeBuilder`.

10. **Self-Correction/Refinement Example During Thought Process:** Initially, I might focus heavily on the individual `New...` methods. However, realizing the overarching purpose is *object creation with V8's specific memory management*, I shift my focus to include the allocation aspects and the role of the `Factory` in enforcing these strategies. Similarly, I initially might not have thought deeply about string internalization, but seeing the dedicated methods for it prompts me to investigate and understand its significance as an optimization.

By following this structured approach, I can systematically analyze the provided code snippet and generate a comprehensive and accurate summary that addresses all aspects of the prompt.
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能,
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

好的，让我们来分析一下 `v8/src/heap/factory.cc` 这个 V8 源代码文件的功能。

**1. 文件功能概述**

`v8/src/heap/factory.cc` 在 V8 引擎中扮演着至关重要的角色，它主要负责 **创建和初始化各种 V8 堆上的对象**。可以将其视为 V8 堆对象的“工厂”。  它提供了一系列便捷的函数，用于分配内存并初始化不同类型的 V8 对象，例如代码对象、字符串、数组、数据结构等。

**2. 是否为 Torque 源代码**

根据您的描述，如果文件以 `.tq` 结尾，那才是 V8 Torque 源代码。 `v8/src/heap/factory.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而非 Torque 源代码。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的内置函数。

**3. 与 JavaScript 功能的关系及举例**

`v8/src/heap/factory.cc` 中创建的对象是 JavaScript 代码执行的基础。 当 JavaScript 代码运行时，V8 需要在堆上创建各种对象来表示 JavaScript 的数据和结构。 `factory.cc` 提供的功能直接支持了这些对象的创建。

**JavaScript 示例：**

```javascript
// 当你创建一个新的对象时：
const obj = {};

// 或者创建一个数组：
const arr = [1, 2, 3];

// 或者创建一个字符串：
const str = "hello";

// 或者定义一个函数：
function myFunction() {}
```

在 V8 内部，执行这些 JavaScript 代码时，`factory.cc` 中的函数会被调用来分配和初始化相应的堆对象，例如：

*   对于 `const obj = {}`，会调用 `Factory::NewJSObject()` 或类似的函数来创建一个 `JSObject` 实例。
*   对于 `const arr = [1, 2, 3]`，会调用 `Factory::NewJSArray()` 和 `Factory::NewFixedArray()` 来创建数组对象及其存储元素的底层固定数组。
*   对于 `const str = "hello"`，会调用 `Factory::NewString()` 或 `Factory::InternalizeString()` 来创建字符串对象。
*   对于 `function myFunction() {}`，会调用 `Factory::NewFunction()` 和 `Factory::NewCode()` 来创建函数对象及其关联的可执行代码。

**4. 代码逻辑推理 (以 `CodeBuilder` 为例)**

`Factory::CodeBuilder` 是一个用于构建代码对象的辅助类。 让我们假设一种简单的场景：

**假设输入：**

*   `code_desc_`: 一个 `CodeDesc` 对象，描述了要生成的代码的各种属性，例如代码大小、重定位信息大小等。
*   `kind_`:  一个 `CodeKind` 枚举值，例如 `CodeKind::REGULAR`，表示这是一个普通函数的代码。

**代码逻辑片段（简化）：**

```c++
Handle<Code> Factory::CodeBuilder::Build() {
  DirectHandle<TrustedByteArray> reloc_info =
      NewTrustedByteArray(code_desc_.reloc_size); // 创建存储重定位信息的 TrustedByteArray

  Tagged<HeapObject> istream_allocation =
      AllocateUninitializedInstructionStream(true); // 分配未初始化的指令流

  Handle<InstructionStream> istream;
  {
    // ... 初始化 istream ...
    istream = handle(raw_istream, local_isolate_);
  }

  NewCodeOptions new_code_options = {
      kind_,
      // ... 其他选项 ...
      istream,
      /*instruction_start=*/kNullAddress,
  };
  Handle<Code> code = NewCode(new_code_options); // 创建 Code 对象

  // ... 将指令流与代码对象关联 ...

  return code;
}
```

**推理与输出：**

1. `NewTrustedByteArray(code_desc_.reloc_size)`:  根据 `code_desc_` 中指定的重定位信息大小，分配一个新的 `TrustedByteArray` 来存储代码的重定位信息。假设 `code_desc_.reloc_size` 为 100，则会分配一个大小为 100 字节的 `TrustedByteArray`。
2. `AllocateUninitializedInstructionStream(true)`: 分配一块内存用于存储代码的指令流。返回一个指向未初始化内存的 `HeapObject`。
3. `InstructionStream::Initialize(...)`:  在分配的内存上初始化 `InstructionStream` 对象，将重定位信息等数据写入。
4. `NewCode(new_code_options)`:  根据提供的选项（包括之前创建的 `InstructionStream`），分配并初始化最终的 `Code` 对象。

**假设输出：**

返回一个指向新创建的 `Code` 对象的 `Handle<Code>`，该对象包含了可执行代码及其元数据。

**5. 涉及用户常见的编程错误**

虽然 `factory.cc` 是 V8 内部代码，用户不会直接编写或修改它，但理解其功能有助于理解 V8 的内存管理和对象生命周期，从而避免一些与内存相关的 JavaScript 编程错误：

*   **内存泄漏：**  虽然 V8 有垃圾回收机制，但如果 JavaScript 代码创建了大量不再使用的对象，并且这些对象仍然被某些引用持有，就可能导致内存泄漏。理解 `factory.cc` 如何创建对象可以帮助开发者意识到对象创建的开销，并注意及时释放不再需要的引用。
*   **性能问题：**  频繁地创建和销毁大量对象会给垃圾回收器带来压力，影响性能。了解 `factory.cc` 创建不同类型对象的机制，可以帮助开发者选择更高效的数据结构和编程模式。例如，在循环中避免不必要的对象创建。
*   **类型错误：**  虽然 JavaScript 是动态类型语言，但在 V8 内部，对象都有其特定的类型。理解 `factory.cc` 创建的不同类型的对象，有助于理解 JavaScript 的类型系统，并避免一些潜在的类型错误。

**示例 (可能导致大量对象创建的错误)：**

```javascript
function processData(data) {
  const results = [];
  for (let i = 0; i < data.length; i++) {
    // 错误：在循环中创建新对象
    results.push({ index: i, value: data[i] });
  }
  return results;
}

const largeData = [...Array(10000).keys()];
const processed = processData(largeData);
```

在这个例子中，`processData` 函数在循环中为每个数据项都创建了一个新的对象 `{ index: i, value: data[i] }`。 对于 `largeData` 这样的数组，这将导致创建大量临时对象，可能会影响性能。 了解 V8 如何通过 `factory.cc` 创建这些对象，可以促使开发者考虑更优的实现方式，例如直接操作数组或使用更轻量级的数据结构。

**6. 第 1 部分功能归纳**

作为第一部分，`v8/src/heap/factory.cc` 的主要功能可以归纳为：

*   **核心对象创建中心：**  提供用于在 V8 堆上分配和初始化各种类型对象的 C++ 函数。
*   **支持 JavaScript 语义：**  其创建的对象是 V8 执行 JavaScript 代码的基础，直接关系到 JavaScript 语言的各种特性（对象、数组、字符串、函数等）。
*   **提供代码构建工具：**  通过 `CodeBuilder` 类，封装了创建和初始化可执行代码对象的复杂过程。
*   **内部实现细节：**  用户无法直接操作，但理解其工作原理有助于理解 V8 的内存管理和对象生命周期。

希望以上分析对您有所帮助！ 如果有后续部分，我们可以继续深入探讨 `factory.cc` 的其他细节。

Prompt: 
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

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
    // Decode even in the case of length 1 since it can be
"""


```