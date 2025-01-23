Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example illustrating its relation to JavaScript.

2. **Initial Scan and Keywords:**  Read through the code, paying attention to keywords, class names, and function names. Notice things like:
    * `#include`: Includes related to compilation, code generation, builtins, assembly, and the V8 isolate.
    * `namespace v8::internal`: This indicates internal V8 implementation details.
    * `Builtin_`, `Builtins::`, `BuildPlaceholder`, `BuildWithMacroAssembler`, `BuildAdaptor`, `BuildWithTurboshaftAssemblerJS`, `BuildWithCodeStubAssemblerJS`: These suggest the core purpose is building and managing "builtins."
    * `Isolate`: A fundamental V8 concept, representing an isolated JavaScript environment.
    * `Code`: Represents compiled code within V8.
    * `MacroAssembler`, `CodeAssembler`, `TurboshaftAssembler`:  Different ways to generate machine code within V8.
    * `Bytecode`: V8's intermediate representation of JavaScript code.
    * `SetupIsolateDelegate::SetupBuiltinsInternal`: A key function that seems to orchestrate the setup process.

3. **Identify the Core Functionality:**  The repeated patterns of `Build...` functions and the `SetupBuiltinsInternal` function strongly suggest the file is responsible for *creating and registering* the core, pre-compiled functions (builtins) that V8 uses. The placeholders and replacement logic further reinforce this idea –  initial setup to handle circular dependencies.

4. **Analyze Key Functions:**
    * **`BuildPlaceholder`:** Creates temporary, empty code objects. This is a crucial step for handling circular dependencies among builtins.
    * **`BuildWithMacroAssembler`:**  Generates builtins using a low-level assembler. Likely used for performance-critical, platform-specific builtins.
    * **`BuildAdaptor`:** Creates simple functions that act as intermediaries, calling the actual C++ implementations. This bridges the gap between the builtin system and raw C++ functions.
    * **`BuildWithTurboshaftAssemblerJS` / `BuildWithCodeStubAssemblerJS`:** Uses higher-level assemblers (Turboshaft and CodeStubAssembler) designed for optimized code generation, often linking directly to JavaScript concepts. The "JS" suffix suggests these builtins are more directly tied to JavaScript semantics.
    * **`BuildWithTurboshaftAssemblerCS` / `BuildWithCodeStubAssemblerCS`:** Similar to the above, but with "CS" for "CallStub" linkage, suggesting a different calling convention, potentially for more internal V8 functions.
    * **`GenerateBytecodeHandler`:**  Specifically creates handlers for individual JavaScript bytecode instructions.
    * **`SetupIsolateDelegate::SetupBuiltinsInternal`:**  The main setup function. It calls the `Build...` functions for each builtin defined in `BUILTIN_LIST`. The `PopulateWithPlaceholders` and `ReplacePlaceholders` calls highlight the circular dependency management.

5. **Infer the Relationship to JavaScript:** Builtins are fundamental to how JavaScript executes. They provide implementations for core language features and standard library functions. The different `Build...` methods indicate different levels of abstraction in how these builtins are implemented, ranging from direct assembly to higher-level code generation.

6. **Formulate the Summary:** Based on the analysis, structure a summary that highlights the core purpose: setting up builtins. Mention the different generation methods and the placeholder/replacement mechanism. Emphasize the "internal" nature of the file and its role in V8's initialization.

7. **Construct the JavaScript Example:** The key is to illustrate *how* these C++ builtins manifest in JavaScript. Focus on:
    * **Core Language Features:** Things you can't do *without* builtins. `console.log`, basic arithmetic, object creation, array manipulation are all good candidates.
    * **Standard Library:**  Methods on built-in objects like `Array.prototype.map`, `String.prototype.toUpperCase`.
    * **Internal/Less Obvious Builtins:**  Mention things like `Function.prototype.call` which are also implemented as builtins.

8. **Explain the Connection:** Clearly articulate that when you call a JavaScript function like `console.log`, the V8 engine ultimately executes a C++ builtin defined (or whose setup is managed) by files like this one. Explain that the different `Build...` methods represent how these JavaScript features are implemented under the hood.

9. **Refine and Polish:** Review the summary and example for clarity and accuracy. Ensure the language is accessible and avoids overly technical jargon where possible. Make the JavaScript example concise and easy to understand. For instance, initially, I might have thought of more complex JavaScript examples, but simpler ones directly illustrate the point better.

This systematic approach, combining code scanning, keyword analysis, function breakdown, and understanding the broader context of V8, leads to a comprehensive and accurate explanation of the C++ file's functionality and its relation to JavaScript.
这个C++源代码文件 `setup-builtins-internal.cc` 的主要功能是**负责在 V8 JavaScript 引擎启动时，设置和初始化内置（built-in）的函数和对象**。这些内置函数是 JavaScript 语言本身提供的核心功能，例如 `console.log`，`Array.prototype.map` 等。

更具体地说，这个文件做了以下几件事：

1. **定义了创建不同类型内置函数的构建器 (Builders):**
   - `BuildPlaceholder`:  创建一个临时的占位符，用于解决内置函数之间的循环依赖问题。
   - `BuildWithMacroAssembler`: 使用底层的 `MacroAssembler` 直接生成机器码来实现内置函数。这种方式通常用于性能关键的内置函数。
   - `BuildAdaptor`:  创建一个适配器，将 C++ 函数转换为可以被 V8 调用的内置函数。
   - `BuildWithTurboshaftAssemblerJS`/`BuildWithCodeStubAssemblerJS`: 使用更高级的 `TurboshaftAssembler` 或 `CodeStubAssembler` 生成代码，这些工具可以更容易地生成优化过的 JavaScript 代码。 "JS" 后缀通常表示这些内置函数与 JavaScript 的调用约定相关。
   - `BuildWithTurboshaftAssemblerCS`/`BuildWithCodeStubAssemblerCS`: 类似上面的构建器，但 "CS" 后缀表示 "Call Stub"，用于生成具有特定调用约定的内置函数，通常用于 V8 内部组件之间的调用。
   - `GenerateBytecodeHandler`:  为特定的 JavaScript 字节码生成处理器。

2. **管理内置函数的注册和替换:**
   - `PopulateWithPlaceholders`:  在启动时，先用占位符填充所有内置函数的位置。
   - `ReplacePlaceholders`:  在所有内置函数生成完毕后，将所有对占位符的引用替换为实际的内置函数代码。这解决了内置函数之间可能存在的相互调用（循环依赖）的问题。
   - `AddBuiltin`: 将构建好的内置函数添加到 V8 的内置函数列表中。

3. **处理不同类型的内置函数实现:** 文件中使用了宏 (`BUILD_CPP`, `BUILD_TSJ`, `BUILD_TFJ`, `BUILD_TSC`, `BUILD_TFC`, `BUILD_TFS`, `BUILD_TFH`, `BUILD_BCH`, `BUILD_ASM`) 来遍历 `BUILTIN_LIST`，并根据内置函数的类型调用相应的构建器函数。这些宏代表了不同的内置函数实现方式，例如：
   - `BUILD_CPP`:  内置函数直接由 C++ 函数实现。
   - `BUILD_TSJ`/`BUILD_TFJ`: 内置函数使用 Turboshaft 或 TurboFan (CodeStubAssembler) 生成，并使用 JavaScript 调用约定。
   - `BUILD_TSC`/`BUILD_TFC`: 内置函数使用 Turboshaft 或 TurboFan 生成，并使用 Call Stub 调用约定。
   - `BUILD_BCH`: 内置函数是 JavaScript 字节码的处理器。
   - `BUILD_ASM`: 内置函数使用 MacroAssembler 直接编写汇编代码。

4. **设置内置函数的属性和元数据:**  例如，设置内置函数的参数数量等。

**它与 JavaScript 的功能密切相关。**  这个文件是 V8 引擎启动的**关键部分**，它确保了 JavaScript 代码能够正常执行，因为所有核心的 JavaScript 功能都依赖于这里设置的内置函数。

**JavaScript 示例:**

当你执行以下 JavaScript 代码时：

```javascript
console.log("Hello, world!");
const arr = [1, 2, 3];
const doubled = arr.map(x => x * 2);
console.log(doubled);
```

在 V8 引擎内部，以下事情（简化版）会发生，并与 `setup-builtins-internal.cc` 有关：

1. **`console.log` 的调用:**
   - JavaScript 引擎会查找 `console` 对象及其 `log` 方法。
   - `console.log` 实际上是一个**内置函数**，它的实现（可能通过 `BUILD_CPP` 或 `BUILD_ASM`）在 V8 的 C++ 代码中。
   - `setup-builtins-internal.cc` 负责在引擎启动时创建并注册这个内置函数，将其与 JavaScript 的 `console.log` 关联起来。

2. **`Array.prototype.map` 的调用:**
   - JavaScript 引擎会查找 `arr` 对象的原型链，找到 `Array.prototype` 上的 `map` 方法。
   - `Array.prototype.map` 也是一个**内置函数**，它通常使用更高级的工具（如 `BUILD_TSJ` 或 `BUILD_TFJ`）生成，以实现高效的数组遍历和操作。
   - `setup-builtins-internal.cc` 同样负责在引擎启动时创建并注册这个内置函数。

3. **箭头函数 `x => x * 2` 的执行:**
   - 虽然箭头函数本身不是内置函数，但其执行过程中可能会调用一些底层的内置函数来进行算术运算。

**总结:**

`setup-builtins-internal.cc` 是 V8 引擎的基石之一。它就像一个工厂，在引擎启动时生产并组装了 JavaScript 语言的核心零件——内置函数。如果没有这个文件及其定义的功能，JavaScript 代码就无法执行，因为许多我们日常使用的基本功能都依赖于这里初始化的内置函数。这个文件体现了 V8 引擎的复杂性和底层实现，它将高级的 JavaScript 代码与底层的机器码执行连接起来。

### 提示词
```
这是目录为v8/src/builtins/setup-builtins-internal.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fstream>

#include "src/builtins/builtins-inl.h"
#include "src/builtins/profile-data-reader.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/reloc-info-inl.h"
#include "src/common/globals.h"
#include "src/compiler/code-assembler.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/turboshaft/builtin-compiler.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/init/setup-isolate.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter-generator.h"
#include "src/interpreter/interpreter.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/smi.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-builtin-list.h"
#endif

namespace v8 {
namespace internal {

// Forward declarations for C++ builtins.
#define FORWARD_DECLARE(Name, Argc) \
  Address Builtin_##Name(int argc, Address* args, Isolate* isolate);
BUILTIN_LIST_C(FORWARD_DECLARE)
#undef FORWARD_DECLARE

namespace {

const int kBufferSize = 128 * KB;

AssemblerOptions BuiltinAssemblerOptions(Isolate* isolate, Builtin builtin) {
  AssemblerOptions options = AssemblerOptions::Default(isolate);
  CHECK(!options.isolate_independent_code);
  CHECK(!options.collect_win64_unwind_info);

#if V8_ENABLE_WEBASSEMBLY
  if (wasm::BuiltinLookup::IsWasmBuiltinId(builtin) ||
      builtin == Builtin::kJSToWasmWrapper ||
      builtin == Builtin::kJSToWasmHandleReturns ||
      builtin == Builtin::kWasmToJsWrapperCSA) {
    options.is_wasm = true;
  }
#endif
  if (!isolate->IsGeneratingEmbeddedBuiltins()) {
    return options;
  }

  const base::AddressRegion& code_region = isolate->heap()->code_region();
  bool pc_relative_calls_fit_in_code_range =
      !code_region.is_empty() &&
      std::ceil(static_cast<float>(code_region.size() / MB)) <=
          kMaxPCRelativeCodeRangeInMB;

  // Mksnapshot ensures that the code range is small enough to guarantee that
  // PC-relative call/jump instructions can be used for builtin to builtin
  // calls/tail calls. The embedded builtins blob generator also ensures that.
  // However, there are serializer tests, where we force isolate creation at
  // runtime and at this point, Code space isn't restricted to a
  // size s.t. PC-relative calls may be used. So, we fall back to an indirect
  // mode.
  options.use_pc_relative_calls_and_jumps_for_mksnapshot =
      pc_relative_calls_fit_in_code_range;

  options.builtin_call_jump_mode = BuiltinCallJumpMode::kForMksnapshot;
  options.isolate_independent_code = true;
  options.collect_win64_unwind_info = true;

  if (builtin == Builtin::kInterpreterEntryTrampolineForProfiling) {
    // InterpreterEntryTrampolineForProfiling must be generated in a position
    // independent way because it might be necessary to create a copy of the
    // builtin in the code space if the v8_flags.interpreted_frames_native_stack
    // is enabled.
    options.builtin_call_jump_mode = BuiltinCallJumpMode::kIndirect;
  }

  return options;
}

using MacroAssemblerGenerator = void (*)(MacroAssembler*);
using CodeAssemblerGenerator = void (*)(compiler::CodeAssemblerState*);

Handle<Code> BuildPlaceholder(Isolate* isolate, Builtin builtin) {
  HandleScope scope(isolate);
  uint8_t buffer[kBufferSize];
  MacroAssembler masm(isolate, CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, kBufferSize));
  DCHECK(!masm.has_frame());
  {
    FrameScope frame_scope(&masm, StackFrame::NO_FRAME_TYPE);
    // The contents of placeholder don't matter, as long as they don't create
    // embedded constants or external references.
    masm.Move(kJavaScriptCallCodeStartRegister, Smi::zero());
    masm.Call(kJavaScriptCallCodeStartRegister);
  }
  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code = Factory::CodeBuilder(isolate, desc, CodeKind::BUILTIN)
                          .set_self_reference(masm.CodeObject())
                          .set_builtin(builtin)
                          .Build();
  return scope.CloseAndEscape(code);
}

V8_NOINLINE Tagged<Code> BuildWithMacroAssembler(
    Isolate* isolate, Builtin builtin, MacroAssemblerGenerator generator,
    const char* s_name) {
  HandleScope scope(isolate);
  uint8_t buffer[kBufferSize];

  MacroAssembler masm(isolate, BuiltinAssemblerOptions(isolate, builtin),
                      CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, kBufferSize));
  masm.set_builtin(builtin);
  DCHECK(!masm.has_frame());
  masm.CodeEntry();
  generator(&masm);

  int handler_table_offset = 0;

  // JSEntry builtins are a special case and need to generate a handler table.
  DCHECK_EQ(Builtins::KindOf(Builtin::kJSEntry), Builtins::ASM);
  DCHECK_EQ(Builtins::KindOf(Builtin::kJSConstructEntry), Builtins::ASM);
  DCHECK_EQ(Builtins::KindOf(Builtin::kJSRunMicrotasksEntry), Builtins::ASM);
  if (Builtins::IsJSEntryVariant(builtin)) {
    handler_table_offset = HandlerTable::EmitReturnTableStart(&masm);
    HandlerTable::EmitReturnEntry(
        &masm, 0, isolate->builtins()->js_entry_handler_offset());
#if V8_ENABLE_DRUMBRAKE
  } else if (builtin == Builtin::kWasmInterpreterCWasmEntry) {
    handler_table_offset = HandlerTable::EmitReturnTableStart(&masm);
    HandlerTable::EmitReturnEntry(
        &masm, 0,
        isolate->builtins()->cwasm_interpreter_entry_handler_offset());
#endif  // V8_ENABLE_DRUMBRAKE
  }
#if V8_ENABLE_WEBASSEMBLY &&                                              \
    (V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_IA32 || \
     V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_LOONG64)
  if (builtin == Builtin::kWasmReturnPromiseOnSuspendAsm) {
    handler_table_offset = HandlerTable::EmitReturnTableStart(&masm);
    HandlerTable::EmitReturnEntry(
        &masm, 0, isolate->builtins()->jspi_prompt_handler_offset());
  }
#endif

  CodeDesc desc;
  masm.GetCode(isolate->main_thread_local_isolate(), &desc,
               MacroAssembler::kNoSafepointTable, handler_table_offset);

  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::BUILTIN)
          .set_self_reference(masm.CodeObject())
          .set_builtin(builtin)
          .Build();
#if defined(V8_OS_WIN64)
  isolate->SetBuiltinUnwindData(builtin, masm.GetUnwindInfo());
#endif  // V8_OS_WIN64
  return *code;
}

Tagged<Code> BuildAdaptor(Isolate* isolate, Builtin builtin,
                          Address builtin_address, const char* name) {
  HandleScope scope(isolate);
  uint8_t buffer[kBufferSize];
  MacroAssembler masm(isolate, BuiltinAssemblerOptions(isolate, builtin),
                      CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, kBufferSize));
  masm.set_builtin(builtin);
  DCHECK(!masm.has_frame());
  int formal_parameter_count = Builtins::GetFormalParameterCount(builtin);
  Builtins::Generate_Adaptor(&masm, formal_parameter_count, builtin_address);
  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::BUILTIN)
          .set_self_reference(masm.CodeObject())
          .set_builtin(builtin)
          .set_parameter_count(formal_parameter_count)
          .Build();
  return *code;
}

// Builder for builtins implemented in Turboshaft with JS linkage.
V8_NOINLINE Tagged<Code> BuildWithTurboshaftAssemblerJS(
    Isolate* isolate, Builtin builtin,
    compiler::turboshaft::TurboshaftAssemblerGenerator generator, int argc,
    const char* name) {
  HandleScope scope(isolate);
  Handle<Code> code = compiler::turboshaft::BuildWithTurboshaftAssemblerImpl(
      isolate, builtin, generator,
      [argc](Zone* zone) {
        return compiler::Linkage::GetJSCallDescriptor(
            zone, false, argc, compiler::CallDescriptor::kCanUseRoots);
      },
      name, BuiltinAssemblerOptions(isolate, builtin));
  return *code;
}

// Builder for builtins implemented in TurboFan with JS linkage.
V8_NOINLINE Tagged<Code> BuildWithCodeStubAssemblerJS(
    Isolate* isolate, Builtin builtin, CodeAssemblerGenerator generator,
    int argc, const char* name) {
  // TODO(nicohartmann): Remove this once `BuildWithTurboshaftAssemblerCS` has
  // an actual use.
  USE(&BuildWithTurboshaftAssemblerJS);
  HandleScope scope(isolate);

  Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  compiler::CodeAssemblerState state(isolate, &zone, argc, CodeKind::BUILTIN,
                                     name, builtin);
  generator(&state);
  DirectHandle<Code> code = compiler::CodeAssembler::GenerateCode(
      &state, BuiltinAssemblerOptions(isolate, builtin),
      ProfileDataFromFile::TryRead(name));
  return *code;
}

// Builder for builtins implemented in Turboshaft with CallStub linkage.
V8_NOINLINE Tagged<Code> BuildWithTurboshaftAssemblerCS(
    Isolate* isolate, Builtin builtin,
    compiler::turboshaft::TurboshaftAssemblerGenerator generator,
    CallDescriptors::Key interface_descriptor, const char* name) {
  HandleScope scope(isolate);
  Handle<Code> code = compiler::turboshaft::BuildWithTurboshaftAssemblerImpl(
      isolate, builtin, generator,
      [interface_descriptor](Zone* zone) {
        CallInterfaceDescriptor descriptor(interface_descriptor);
        DCHECK_LE(0, descriptor.GetRegisterParameterCount());
        return compiler::Linkage::GetStubCallDescriptor(
            zone, descriptor, descriptor.GetStackParameterCount(),
            compiler::CallDescriptor::kNoFlags,
            compiler::Operator::kNoProperties);
      },
      name, BuiltinAssemblerOptions(isolate, builtin));
  return *code;
}

// Builder for builtins implemented in TurboFan with CallStub linkage.
V8_NOINLINE Tagged<Code> BuildWithCodeStubAssemblerCS(
    Isolate* isolate, Builtin builtin, CodeAssemblerGenerator generator,
    CallDescriptors::Key interface_descriptor, const char* name) {
  // TODO(nicohartmann): Remove this once `BuildWithTurboshaftAssemblerCS` has
  // an actual use.
  USE(&BuildWithTurboshaftAssemblerCS);
  HandleScope scope(isolate);
  Zone zone(isolate->allocator(), ZONE_NAME, kCompressGraphZone);
  // The interface descriptor with given key must be initialized at this point
  // and this construction just queries the details from the descriptors table.
  CallInterfaceDescriptor descriptor(interface_descriptor);
  // Ensure descriptor is already initialized.
  DCHECK_LE(0, descriptor.GetRegisterParameterCount());
  compiler::CodeAssemblerState state(isolate, &zone, descriptor,
                                     CodeKind::BUILTIN, name, builtin);
  generator(&state);
  DirectHandle<Code> code = compiler::CodeAssembler::GenerateCode(
      &state, BuiltinAssemblerOptions(isolate, builtin),
      ProfileDataFromFile::TryRead(name));
  return *code;
}

}  // anonymous namespace

// static
void SetupIsolateDelegate::AddBuiltin(Builtins* builtins, Builtin builtin,
                                      Tagged<Code> code) {
  DCHECK_EQ(builtin, code->builtin_id());
  builtins->set_code(builtin, code);
}

// static
void SetupIsolateDelegate::PopulateWithPlaceholders(Isolate* isolate) {
  // Fill the builtins list with placeholders. References to these placeholder
  // builtins are eventually replaced by the actual builtins. This is to
  // support circular references between builtins.
  Builtins* builtins = isolate->builtins();
  HandleScope scope(isolate);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    DirectHandle<Code> placeholder = BuildPlaceholder(isolate, builtin);
    AddBuiltin(builtins, builtin, *placeholder);
  }
}

// static
void SetupIsolateDelegate::ReplacePlaceholders(Isolate* isolate) {
  // Replace references from all builtin code objects to placeholders.
  Builtins* builtins = isolate->builtins();
  DisallowGarbageCollection no_gc;
  static const int kRelocMask =
      RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
      RelocInfo::ModeMask(RelocInfo::FULL_EMBEDDED_OBJECT) |
      RelocInfo::ModeMask(RelocInfo::COMPRESSED_EMBEDDED_OBJECT) |
      RelocInfo::ModeMask(RelocInfo::RELATIVE_CODE_TARGET);
  PtrComprCageBase cage_base(isolate);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    Tagged<Code> code = builtins->code(builtin);
    Tagged<InstructionStream> istream = code->instruction_stream();
    WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
        istream.address(), istream->Size(),
        ThreadIsolation::JitAllocationType::kInstructionStream, true);
    bool flush_icache = false;
    for (WritableRelocIterator it(jit_allocation, istream,
                                  code->constant_pool(), kRelocMask);
         !it.done(); it.next()) {
      WritableRelocInfo* rinfo = it.rinfo();
      if (RelocInfo::IsCodeTargetMode(rinfo->rmode())) {
        Tagged<Code> target_code =
            Code::FromTargetAddress(rinfo->target_address());
        DCHECK_IMPLIES(
            RelocInfo::IsRelativeCodeTarget(rinfo->rmode()),
            Builtins::IsIsolateIndependent(target_code->builtin_id()));
        if (!target_code->is_builtin()) continue;
        Tagged<Code> new_target = builtins->code(target_code->builtin_id());
        rinfo->set_target_address(istream, new_target->instruction_start(),
                                  UPDATE_WRITE_BARRIER, SKIP_ICACHE_FLUSH);
      } else {
        DCHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
        Tagged<Object> object = rinfo->target_object(cage_base);
        if (!IsCode(object, cage_base)) continue;
        Tagged<Code> target = Cast<Code>(object);
        if (!target->is_builtin()) continue;
        Tagged<Code> new_target = builtins->code(target->builtin_id());
        rinfo->set_target_object(istream, new_target, UPDATE_WRITE_BARRIER,
                                 SKIP_ICACHE_FLUSH);
      }
      flush_icache = true;
    }
    if (flush_icache) {
      FlushInstructionCache(code->instruction_start(),
                            code->instruction_size());
    }
  }
}

namespace {

V8_NOINLINE Tagged<Code> GenerateBytecodeHandler(
    Isolate* isolate, Builtin builtin, interpreter::OperandScale operand_scale,
    interpreter::Bytecode bytecode) {
  DCHECK(interpreter::Bytecodes::BytecodeHasHandler(bytecode, operand_scale));
  DirectHandle<Code> code = interpreter::GenerateBytecodeHandler(
      isolate, Builtins::name(builtin), bytecode, operand_scale, builtin,
      BuiltinAssemblerOptions(isolate, builtin));
  return *code;
}

}  // namespace

// static
void SetupIsolateDelegate::SetupBuiltinsInternal(Isolate* isolate) {
  Builtins* builtins = isolate->builtins();
  DCHECK(!builtins->initialized_);

  if (v8_flags.dump_builtins_hashes_to_file) {
    // Create an empty file.
    std::ofstream(v8_flags.dump_builtins_hashes_to_file, std::ios_base::trunc);
  }

  PopulateWithPlaceholders(isolate);

  // Create a scope for the handles in the builtins.
  HandleScope scope(isolate);

  int index = 0;
  Tagged<Code> code;
#define BUILD_CPP(Name, Argc)                                \
  code = BuildAdaptor(isolate, Builtin::k##Name,             \
                      FUNCTION_ADDR(Builtin_##Name), #Name); \
  AddBuiltin(builtins, Builtin::k##Name, code);              \
  index++;

#define BUILD_TSJ(Name, Argc, ...)                                         \
  code = BuildWithTurboshaftAssemblerJS(                                   \
      isolate, Builtin::k##Name, &Builtins::Generate_##Name, Argc, #Name); \
  AddBuiltin(builtins, Builtin::k##Name, code);                            \
  index++;

#define BUILD_TFJ(Name, Argc, ...)                                         \
  code = BuildWithCodeStubAssemblerJS(                                     \
      isolate, Builtin::k##Name, &Builtins::Generate_##Name, Argc, #Name); \
  AddBuiltin(builtins, Builtin::k##Name, code);                            \
  index++;

#define BUILD_TSC(Name, InterfaceDescriptor)                      \
  /* Return size is from the provided CallInterfaceDescriptor. */ \
  code = BuildWithTurboshaftAssemblerCS(                          \
      isolate, Builtin::k##Name, &Builtins::Generate_##Name,      \
      CallDescriptors::InterfaceDescriptor, #Name);               \
  AddBuiltin(builtins, Builtin::k##Name, code);                   \
  index++;

#define BUILD_TFC(Name, InterfaceDescriptor)                      \
  /* Return size is from the provided CallInterfaceDescriptor. */ \
  code = BuildWithCodeStubAssemblerCS(                            \
      isolate, Builtin::k##Name, &Builtins::Generate_##Name,      \
      CallDescriptors::InterfaceDescriptor, #Name);               \
  AddBuiltin(builtins, Builtin::k##Name, code);                   \
  index++;

#define BUILD_TFS(Name, ...)                                            \
  /* Return size for generic TF builtins (stub linkage) is always 1. */ \
  code = BuildWithCodeStubAssemblerCS(isolate, Builtin::k##Name,        \
                                      &Builtins::Generate_##Name,       \
                                      CallDescriptors::Name, #Name);    \
  AddBuiltin(builtins, Builtin::k##Name, code);                         \
  index++;

#define BUILD_TFH(Name, InterfaceDescriptor)                 \
  /* Return size for IC builtins/handlers is always 1. */    \
  code = BuildWithCodeStubAssemblerCS(                       \
      isolate, Builtin::k##Name, &Builtins::Generate_##Name, \
      CallDescriptors::InterfaceDescriptor, #Name);          \
  AddBuiltin(builtins, Builtin::k##Name, code);              \
  index++;

#define BUILD_BCH(Name, OperandScale, Bytecode)                           \
  code = GenerateBytecodeHandler(isolate, Builtin::k##Name, OperandScale, \
                                 Bytecode);                               \
  AddBuiltin(builtins, Builtin::k##Name, code);                           \
  index++;

#define BUILD_ASM(Name, InterfaceDescriptor)                        \
  code = BuildWithMacroAssembler(isolate, Builtin::k##Name,         \
                                 Builtins::Generate_##Name, #Name); \
  AddBuiltin(builtins, Builtin::k##Name, code);                     \
  index++;

  BUILTIN_LIST(BUILD_CPP, BUILD_TSJ, BUILD_TFJ, BUILD_TSC, BUILD_TFC, BUILD_TFS,
               BUILD_TFH, BUILD_BCH, BUILD_ASM);

#undef BUILD_CPP
#undef BUILD_TSJ
#undef BUILD_TFJ
#undef BUILD_TSC
#undef BUILD_TFC
#undef BUILD_TFS
#undef BUILD_TFH
#undef BUILD_BCH
#undef BUILD_ASM
  CHECK_EQ(Builtins::kBuiltinCount, index);

  ReplacePlaceholders(isolate);

  builtins->MarkInitialized();
}

}  // namespace internal
}  // namespace v8
```