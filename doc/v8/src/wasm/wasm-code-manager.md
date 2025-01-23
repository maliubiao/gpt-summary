Response: The user wants a summary of the C++ source code file `v8/src/wasm/wasm-code-manager.cc`.
This is the first part of a two-part file.
The goal is to understand the functionality of this part of the file.
If the code relates to Javascript, provide a Javascript example.

Looking at the includes, the file seems to be responsible for managing the compiled WebAssembly code within the V8 engine.

Key aspects that seem to emerge from the includes and the code:

- **Memory Management for Wasm Code:** Includes allocation and deallocation of memory for compiled code. This likely involves managing code spaces and potentially dealing with fragmentation. The `DisjointAllocationPool` class strongly suggests this.
- **Representation of Wasm Code:** The `WasmCode` class likely represents a compiled Wasm function or other code segment (like jump tables). It holds the actual machine code, relocation information, and metadata.
- **Relocation:** Handling relocations within the generated code.
- **Trap Handling:**  Registering and managing data for trap handlers.
- **Logging and Debugging:**  Support for logging code creation and potentially disassembly.
- **Integration with the V8 Engine:** Interacting with other parts of V8, like the deoptimizer and the logging system.
- **Jump Tables:** Managing jump tables for function calls.
- **Tiering:**  Potentially involved in managing different tiers of compiled code (e.g., Liftoff and TurboFan).
- **Native Module:**  The `NativeModule` class seems to be a higher-level abstraction that manages a collection of `WasmCode` objects for a given WebAssembly module.

Considering the "part 1" aspect, it's likely this part focuses on the core data structures and memory management, with the latter part potentially handling higher-level aspects like compilation and linking.

**Relationship to Javascript:**

WebAssembly code is ultimately executed within a Javascript environment. This file is crucial for how V8 handles the output of the Wasm compilation process. When Javascript calls a Wasm function, or when Wasm calls back into Javascript, this code plays a role in managing the execution flow.
这个C++源代码文件 `v8/src/wasm/wasm-code-manager.cc` 的第一部分主要负责 **管理和维护 WebAssembly 编译后的代码**。它定义了关键的数据结构和方法，用于：

1. **WebAssembly 代码的表示 (`WasmCode` 类):**  `WasmCode` 类封装了已编译的 WebAssembly 代码，包括其指令、元数据（如重定位信息、源位置、异常处理表等）、以及所属的模块信息。它提供了访问这些信息的接口，例如获取指令的起始地址、大小、以及各种元数据的偏移量。

2. **WebAssembly 代码的内存管理 (`DisjointAllocationPool` 和 `WasmCodeAllocator` 类):**
   - `DisjointAllocationPool` 用于管理不重叠的内存区域，用于分配和释放 Wasm 代码。它负责维护可用的代码空间，并支持合并相邻的空闲区域。
   - `WasmCodeAllocator` 基于 `DisjointAllocationPool`，提供了更高级的 Wasm 代码内存分配功能。它负责在代码空间中分配内存，并在需要时扩展代码空间。它还处理代码的提交（commit）和取消提交（decommit），以及在释放代码时清理内存。

3. **跟踪和记录已编译的代码:** `WasmCode` 类包含了用于记录代码创建事件和调试信息的机制，例如 `LogCode` 方法，用于在 V8 的日志系统中记录 Wasm 代码的创建。

4. **处理异常和陷阱:** `WasmCode` 类包含了与陷阱处理相关的信息，例如注册陷阱处理程序数据 (`RegisterTrapHandlerData`)。

5. **支持代码的验证和打印:**  提供了 `Validate` 方法用于进行内部一致性检查，以及 `Print` 和 `Disassemble` 方法用于打印代码的汇编表示，方便调试。

6. **管理代码的引用计数:**  `WasmCode` 对象通过引用计数进行管理，以确保在没有活动引用时可以安全地释放内存。`DecRefOnPotentiallyDeadCode` 和 `DecrementRefCount` 等方法用于管理代码的生命周期。

7. **处理重定位:** 代码中包含了处理重定位信息的逻辑，这在 Wasm 代码加载和链接时是必要的，以确保代码中的地址引用正确。

8. **与 NativeModule 关联:** `WasmCode` 对象属于一个 `NativeModule`，该模块代表一个已加载的 WebAssembly 模块。

**与 JavaScript 的关系以及 JavaScript 例子:**

此文件直接关系到 V8 如何执行 WebAssembly 代码。当 JavaScript 代码加载并实例化一个 WebAssembly 模块时，V8 会编译 Wasm 代码，而 `wasm-code-manager.cc` (的这一部分) 负责管理这些编译后的代码。

**JavaScript 例子:**

```javascript
// 假设已经加载了一个 WebAssembly 模块
const wasmCode = await fetch('my_module.wasm');
const wasmInstance = await WebAssembly.instantiateStreaming(wasmCode);

// 获取导出的 Wasm 函数
const wasmFunction = wasmInstance.instance.exports.myFunction;

// 调用 Wasm 函数
const result = wasmFunction(42);

console.log(result);
```

在这个例子中，当 `WebAssembly.instantiateStreaming` 执行时，V8 会编译 `my_module.wasm` 中的 Wasm 代码。`wasm-code-manager.cc` 中定义的类和方法会参与到以下过程中：

- **分配内存来存储编译后的 `myFunction` 的机器码。** (`WasmCodeAllocator`)
- **创建一个 `WasmCode` 对象来表示 `myFunction` 的编译结果，包含其指令和元数据。** (`WasmCode`)
- **当 JavaScript 调用 `wasmFunction(42)` 时，V8 会执行 `WasmCode` 对象中存储的机器码。**

虽然 JavaScript 代码本身不直接操作 `WasmCode` 对象或 `WasmCodeAllocator`，但这些 C++ 类和方法是 V8 引擎内部管理和执行 WebAssembly 代码的关键组成部分，使得 JavaScript 能够无缝地与 WebAssembly 模块交互。

总而言之，`v8/src/wasm/wasm-code-manager.cc` 的第一部分构建了 V8 引擎中 WebAssembly 代码管理的基础设施，为后续的编译、加载、执行和垃圾回收等操作提供了必要的支持。

### 提示词
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-code-manager.h"

#include <algorithm>
#include <iomanip>
#include <numeric>
#include <optional>

#include "src/base/atomicops.h"
#include "src/base/build_config.h"
#include "src/base/iterator.h"
#include "src/base/macros.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/base/small-vector.h"
#include "src/base/string-format.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/code-memory-access.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/disassembler.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/utils/ostreams.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/jump-table-assembler.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/names-provider.h"
#include "src/wasm/pgo.h"
#include "src/wasm/std-object-sizes.h"
#include "src/wasm/wasm-builtin-list.h"
#include "src/wasm/wasm-code-pointer-table-inl.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-deopt-data.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-module-sourcemap.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/well-known-imports.h"

#if V8_ENABLE_DRUMBRAKE
#include "src/wasm/interpreter/wasm-interpreter-runtime.h"
#endif  // V8_ENABLE_DRUMBRAKE

#if defined(V8_OS_WIN64)
#include "src/diagnostics/unwinding-info-win64.h"
#endif  // V8_OS_WIN64

#define TRACE_HEAP(...)                                       \
  do {                                                        \
    if (v8_flags.trace_wasm_native_heap) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8 {
namespace internal {
namespace wasm {

using trap_handler::ProtectedInstructionData;

// Check that {WasmCode} objects are sufficiently small. We create many of them,
// often for rather small functions.
// Increase the limit if needed, but first check if the size increase is
// justified.
#ifndef V8_GC_MOLE
static_assert(sizeof(WasmCode) <= 104);
#endif

base::AddressRegion DisjointAllocationPool::Merge(
    base::AddressRegion new_region) {
  // Find the possible insertion position by identifying the first region whose
  // start address is not less than that of {new_region}. Since there cannot be
  // any overlap between regions, this also means that the start of {above} is
  // bigger or equal than the *end* of {new_region}.
  auto above = regions_.lower_bound(new_region);
  DCHECK(above == regions_.end() || above->begin() >= new_region.end());

  // Check whether to merge with {above}.
  if (above != regions_.end() && new_region.end() == above->begin()) {
    base::AddressRegion merged_region{new_region.begin(),
                                      new_region.size() + above->size()};
    DCHECK_EQ(merged_region.end(), above->end());
    // Check whether to also merge with the region below.
    if (above != regions_.begin()) {
      auto below = above;
      --below;
      if (below->end() == new_region.begin()) {
        merged_region = {below->begin(), below->size() + merged_region.size()};
        regions_.erase(below);
      }
    }
    auto insert_pos = regions_.erase(above);
    regions_.insert(insert_pos, merged_region);
    return merged_region;
  }

  // No element below, and not adjavent to {above}: insert and done.
  if (above == regions_.begin()) {
    regions_.insert(above, new_region);
    return new_region;
  }

  auto below = above;
  --below;
  // Consistency check:
  DCHECK(above == regions_.end() || below->end() < above->begin());

  // Adjacent to {below}: merge and done.
  if (below->end() == new_region.begin()) {
    base::AddressRegion merged_region{below->begin(),
                                      below->size() + new_region.size()};
    DCHECK_EQ(merged_region.end(), new_region.end());
    regions_.erase(below);
    regions_.insert(above, merged_region);
    return merged_region;
  }

  // Not adjacent to any existing region: insert between {below} and {above}.
  DCHECK_LT(below->end(), new_region.begin());
  regions_.insert(above, new_region);
  return new_region;
}

base::AddressRegion DisjointAllocationPool::Allocate(size_t size) {
  return AllocateInRegion(size,
                          {kNullAddress, std::numeric_limits<size_t>::max()});
}

base::AddressRegion DisjointAllocationPool::AllocateInRegion(
    size_t size, base::AddressRegion region) {
  // Get an iterator to the first contained region whose start address is not
  // smaller than the start address of {region}. Start the search from the
  // region one before that (the last one whose start address is smaller).
  auto it = regions_.lower_bound(region);
  if (it != regions_.begin()) --it;

  for (auto end = regions_.end(); it != end; ++it) {
    base::AddressRegion overlap = it->GetOverlap(region);
    if (size > overlap.size()) continue;
    base::AddressRegion ret{overlap.begin(), size};
    base::AddressRegion old = *it;
    auto insert_pos = regions_.erase(it);
    if (size == old.size()) {
      // We use the full region --> nothing to add back.
    } else if (ret.begin() == old.begin()) {
      // We return a region at the start --> shrink old region from front.
      regions_.insert(insert_pos, {old.begin() + size, old.size() - size});
    } else if (ret.end() == old.end()) {
      // We return a region at the end --> shrink remaining region.
      regions_.insert(insert_pos, {old.begin(), old.size() - size});
    } else {
      // We return something in the middle --> split the remaining region
      // (insert the region with smaller address first).
      regions_.insert(insert_pos, {old.begin(), ret.begin() - old.begin()});
      regions_.insert(insert_pos, {ret.end(), old.end() - ret.end()});
    }
    return ret;
  }
  return {};
}

Address WasmCode::constant_pool() const {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    if (constant_pool_offset_ < code_comments_offset_) {
      return instruction_start() + constant_pool_offset_;
    }
  }
  return kNullAddress;
}

Address WasmCode::handler_table() const {
  return instruction_start() + handler_table_offset_;
}

int WasmCode::handler_table_size() const {
  DCHECK_GE(constant_pool_offset_, handler_table_offset_);
  return static_cast<int>(constant_pool_offset_ - handler_table_offset_);
}

Address WasmCode::code_comments() const {
  return instruction_start() + code_comments_offset_;
}

int WasmCode::code_comments_size() const {
  DCHECK_GE(unpadded_binary_size_, code_comments_offset_);
  return static_cast<int>(unpadded_binary_size_ - code_comments_offset_);
}

std::unique_ptr<const uint8_t[]> WasmCode::ConcatenateBytes(
    std::initializer_list<base::Vector<const uint8_t>> vectors) {
  size_t total_size = 0;
  for (auto& vec : vectors) total_size += vec.size();
  // Use default-initialization (== no initialization).
  std::unique_ptr<uint8_t[]> result{new uint8_t[total_size]};
  uint8_t* ptr = result.get();
  for (auto& vec : vectors) {
    if (vec.empty()) continue;  // Avoid nullptr in {memcpy}.
    memcpy(ptr, vec.begin(), vec.size());
    ptr += vec.size();
  }
  return result;
}

void WasmCode::RegisterTrapHandlerData() {
  DCHECK(!has_trap_handler_index());
  if (kind() != WasmCode::kWasmFunction) return;
  if (protected_instructions_size_ == 0) return;

  Address base = instruction_start();

  size_t size = instructions().size();
  auto protected_instruction_data = this->protected_instructions();
  const int index =
      RegisterHandlerData(base, size, protected_instruction_data.size(),
                          protected_instruction_data.begin());

  // TODO(eholk): if index is negative, fail.
  CHECK_LE(0, index);
  set_trap_handler_index(index);
  DCHECK(has_trap_handler_index());
}

bool WasmCode::ShouldBeLogged(Isolate* isolate) {
  // The return value is cached in {WasmEngine::IsolateData::log_codes}. Ensure
  // to call {WasmEngine::EnableCodeLogging} if this return value would change
  // for any isolate. Otherwise we might lose code events.
  return isolate->IsLoggingCodeCreation();
}

std::string WasmCode::DebugName() const {
  switch (kind()) {
    case kWasmToCapiWrapper:
      return "wasm-to-c";
    case kJumpTable:
      return "jump-table";
    case kWasmToJsWrapper:
      return "wasm-to-js";
#if V8_ENABLE_DRUMBRAKE
    case kInterpreterEntry:
      return "interpreter entry";
#endif  // V8_ENABLE_DRUMBRAKE
    case kWasmFunction:
      // Gets handled below
      break;
  }

  ModuleWireBytes wire_bytes(native_module()->wire_bytes());
  const WasmModule* module = native_module()->module();
  WireBytesRef name_ref =
      module->lazily_generated_names.LookupFunctionName(wire_bytes, index());
  WasmName name = wire_bytes.GetNameOrNull(name_ref);
  std::string name_buffer;
  if (name.empty()) {
    name_buffer.resize(32);
    name_buffer.resize(
        SNPrintF(base::VectorOf(&name_buffer.front(), name_buffer.size()),
                 "wasm-function[%d]", index()));
  } else {
    name_buffer.append(name.begin(), name.end());
  }
  return name_buffer;
}

void WasmCode::LogCode(Isolate* isolate, const char* source_url,
                       int script_id) const {
  DCHECK(ShouldBeLogged(isolate));
  if (IsAnonymous() && kind() != WasmCode::Kind::kWasmToJsWrapper) return;

  std::string fn_name = DebugName();
  WasmName name = base::VectorOf(fn_name);

  if (native_module_) {
    const WasmModule* module = native_module_->module();
    const WasmDebugSymbols& symbol =
        module->debug_symbols[WasmDebugSymbols::Type::SourceMap];
    auto load_wasm_source_map = isolate->wasm_load_source_map_callback();
    auto source_map = native_module_->GetWasmSourceMap();
    if (!source_map && symbol.type == WasmDebugSymbols::Type::SourceMap &&
        !symbol.external_url.is_empty() && load_wasm_source_map) {
      ModuleWireBytes wire_bytes(native_module_->wire_bytes());
      WasmName external_url = wire_bytes.GetNameOrNull(symbol.external_url);
      std::string external_url_string(external_url.data(), external_url.size());
      HandleScope scope(isolate);
      v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
      Local<v8::String> source_map_str =
          load_wasm_source_map(v8_isolate, external_url_string.c_str());
      native_module_->SetWasmSourceMap(
          std::make_unique<WasmModuleSourceMap>(v8_isolate, source_map_str));
    }
  }

  // Record source positions before adding code, otherwise when code is added,
  // there are no source positions to associate with the added code.
  if (!source_positions().empty()) {
    LOG_CODE_EVENT(isolate, WasmCodeLinePosInfoRecordEvent(instruction_start(),
                                                           source_positions()));
  }

  int code_offset = 0;
  if (!IsAnonymous()) {
    code_offset = native_module_->module()->functions[index_].code.offset();
  }
  PROFILE(isolate, CodeCreateEvent(LogEventListener::CodeTag::kFunction, this,
                                   name, source_url, code_offset, script_id));
}

namespace {
bool ProtectedInstructionDataCompare(const ProtectedInstructionData& left,
                                     const ProtectedInstructionData& right) {
  return left.instr_offset < right.instr_offset;
}
}  // namespace

bool WasmCode::IsProtectedInstruction(Address pc) {
  base::Vector<const trap_handler::ProtectedInstructionData> instructions =
      protected_instructions();
  ProtectedInstructionData offset{
      static_cast<uint32_t>(pc - instruction_start())};
  return std::binary_search(instructions.begin(), instructions.end(), offset,
                            ProtectedInstructionDataCompare);
}

void WasmCode::Validate() const {
  // The packing strategy for {tagged_parameter_slots} only works if both the
  // max number of parameters and their max combined stack slot usage fits into
  // their respective half of the result value.
  static_assert(wasm::kV8MaxWasmFunctionParams <
                std::numeric_limits<uint16_t>::max());
  static constexpr int kMaxSlotsPerParam = 4;  // S128 on 32-bit platforms.
  static_assert(wasm::kV8MaxWasmFunctionParams * kMaxSlotsPerParam <
                std::numeric_limits<uint16_t>::max());

#ifdef DEBUG
  NativeModule::CallIndirectTargetMap function_index_map;
  if (native_module_) {
    function_index_map =
        native_module_->CreateIndirectCallTargetToFunctionIndexMap();
  }
  // Scope for foreign WasmCode pointers.
  WasmCodeRefScope code_ref_scope;
  // We expect certain relocation info modes to never appear in {WasmCode}
  // objects or to be restricted to a small set of valid values. Hence the
  // iteration below does not use a mask, but visits all relocation data.
  for (RelocIterator it(instructions(), reloc_info(), constant_pool());
       !it.done(); it.next()) {
    RelocInfo::Mode mode = it.rinfo()->rmode();
    switch (mode) {
      case RelocInfo::WASM_CALL: {
        Address target = it.rinfo()->wasm_call_address();
        WasmCode* code = native_module_->Lookup(target);
        CHECK_NOT_NULL(code);
        CHECK_EQ(WasmCode::kJumpTable, code->kind());
        CHECK(code->contains(target));
        break;
      }
      case RelocInfo::WASM_STUB_CALL: {
        Address target = it.rinfo()->wasm_stub_call_address();
        WasmCode* code = native_module_->Lookup(target);
        CHECK_NOT_NULL(code);
        CHECK_EQ(WasmCode::kJumpTable, code->kind());
        CHECK(code->contains(target));
        break;
      }
      case RelocInfo::WASM_CANONICAL_SIG_ID: {
        uint32_t sig_id = it.rinfo()->wasm_canonical_sig_id();
        CHECK_LE(sig_id, GetTypeCanonicalizer()->GetCurrentNumberOfTypes());
        break;
      }
      case RelocInfo::WASM_INDIRECT_CALL_TARGET: {
        WasmCodePointer call_target = it.rinfo()->wasm_indirect_call_target();
        uint32_t function_index = function_index_map.at(call_target);
        CHECK_EQ(call_target,
                 native_module_->GetIndirectCallTarget(function_index));
        break;
      }
      case RelocInfo::INTERNAL_REFERENCE:
      case RelocInfo::INTERNAL_REFERENCE_ENCODED: {
        Address target = it.rinfo()->target_internal_reference();
        CHECK(contains(target));
        break;
      }
      case RelocInfo::EXTERNAL_REFERENCE:
      case RelocInfo::CONST_POOL:
      case RelocInfo::VENEER_POOL:
        // These are OK to appear.
        break;
      default:
        FATAL("Unexpected mode: %d", mode);
    }
  }
#endif
}

void WasmCode::MaybePrint() const {
  // Determines whether flags want this code to be printed.
  bool function_index_matches =
      (!IsAnonymous() &&
       v8_flags.print_wasm_code_function_index == static_cast<int>(index()));
  if (v8_flags.print_code ||
      (kind() == kWasmFunction
           ? (v8_flags.print_wasm_code || function_index_matches)
           : v8_flags.print_wasm_stub_code.value())) {
    std::string name = DebugName();
    Print(name.c_str());
  }
}

void WasmCode::Print(const char* name) const {
  StdoutStream os;
  os << "--- WebAssembly code ---\n";
  Disassemble(name, os);
  if (native_module_ && native_module_->HasDebugInfo()) {
    if (auto* debug_side_table =
            native_module_->GetDebugInfo()->GetDebugSideTableIfExists(this)) {
      debug_side_table->Print(os);
    }
  }
  os << "--- End code ---\n";
}

void WasmCode::Disassemble(const char* name, std::ostream& os,
                           Address current_pc) const {
  if (name) os << "name: " << name << "\n";
  if (!IsAnonymous()) os << "index: " << index() << "\n";
  os << "kind: " << GetWasmCodeKindAsString(kind()) << "\n";
  if (kind() == kWasmFunction) {
    DCHECK(is_liftoff() || tier() == ExecutionTier::kTurbofan);
    const char* compiler =
        is_liftoff() ? (for_debugging() ? "Liftoff (debug)" : "Liftoff")
                     : "TurboFan";
    os << "compiler: " << compiler << "\n";
  }
  size_t padding = instructions().size() - unpadded_binary_size_;
  os << "Body (size = " << instructions().size() << " = "
     << unpadded_binary_size_ << " + " << padding << " padding)\n";

  int instruction_size = unpadded_binary_size_;
  if (constant_pool_offset_ < instruction_size) {
    instruction_size = constant_pool_offset_;
  }
  if (safepoint_table_offset_ && safepoint_table_offset_ < instruction_size) {
    instruction_size = safepoint_table_offset_;
  }
  if (handler_table_offset_ < instruction_size) {
    instruction_size = handler_table_offset_;
  }
  DCHECK_LT(0, instruction_size);

#ifdef ENABLE_DISASSEMBLER
  os << "Instructions (size = " << instruction_size << ")\n";
  Disassembler::Decode(nullptr, os, instructions().begin(),
                       instructions().begin() + instruction_size,
                       CodeReference(this), current_pc);
  os << "\n";

  if (handler_table_size() > 0) {
    HandlerTable table(this);
    os << "Exception Handler Table (size = " << table.NumberOfReturnEntries()
       << "):\n";
    table.HandlerTableReturnPrint(os);
    os << "\n";
  }

  if (protected_instructions_size_ > 0) {
    os << "Protected instructions:\n pc offset\n";
    for (auto& data : protected_instructions()) {
      os << std::setw(10) << std::hex << data.instr_offset << std::setw(10)
         << "\n";
    }
    os << "\n";
  }

  if (!source_positions().empty()) {
    os << "Source positions:\n pc offset  position\n";
    for (SourcePositionTableIterator it(source_positions()); !it.done();
         it.Advance()) {
      os << std::setw(10) << std::hex << it.code_offset() << std::dec
         << std::setw(10) << it.source_position().ScriptOffset()
         << (it.is_statement() ? "  statement" : "") << "\n";
    }
    os << "\n";
  }

  if (deopt_data_size_ > 0) {
    // TODO(mliedtke): It'd be more readable to format this as a table.
    WasmDeoptView view(deopt_data());
    const WasmDeoptData data = view.GetDeoptData();
    os << "Deopt exits (entries = " << data.entry_count
       << ", byte size = " << deopt_data_size_ << ")\n";
    uint32_t deopt_offset = data.deopt_exit_start_offset;
    for (uint32_t i = 0; i < data.entry_count; ++i) {
      WasmDeoptEntry entry = view.GetDeoptEntry(i);
      os << std::hex << deopt_offset << std::dec
         << ": function offset = " << entry.bytecode_offset
         << ", translation = " << entry.translation_index << '\n';
      deopt_offset += Deoptimizer::kEagerDeoptExitSize;
    }
    os << '\n';
  }

  if (safepoint_table_offset_ > 0) {
    SafepointTable table(this);
    table.Print(os);
    os << "\n";
  }

  os << "RelocInfo (size = " << reloc_info().size() << ")\n";
  for (RelocIterator it(instructions(), reloc_info(), constant_pool());
       !it.done(); it.next()) {
    it.rinfo()->Print(nullptr, os);
  }
  os << "\n";
#else   // !ENABLE_DISASSEMBLER
  os << "Instructions (size = " << instruction_size << ", "
     << static_cast<void*>(instructions().begin()) << "-"
     << static_cast<void*>(instructions().begin() + instruction_size) << ")\n";
#endif  // !ENABLE_DISASSEMBLER
}

const char* GetWasmCodeKindAsString(WasmCode::Kind kind) {
  switch (kind) {
    case WasmCode::kWasmFunction:
      return "wasm function";
    case WasmCode::kWasmToCapiWrapper:
      return "wasm-to-capi";
    case WasmCode::kWasmToJsWrapper:
      return "wasm-to-js";
#if V8_ENABLE_DRUMBRAKE
    case WasmCode::kInterpreterEntry:
      return "interpreter entry";
#endif  // V8_ENABLE_DRUMBRAKE
    case WasmCode::kJumpTable:
      return "jump table";
  }
  return "unknown kind";
}

// static
bool WasmCode::ShouldAllocateCodePointerHandle(int index, Kind kind) {
  return index == kAnonymousFuncIndex && kind != kJumpTable;
}

// static
WasmCodePointerTable::Handle WasmCode::MaybeAllocateCodePointerHandle(
    NativeModule* native_module, int index, Kind kind, Address address) {
  if (index != kAnonymousFuncIndex) {
    DCHECK(!ShouldAllocateCodePointerHandle(index, kind));
    return native_module->GetCodePointerHandle(index);
  }
  switch (kind) {
    case kWasmFunction:
    case kWasmToCapiWrapper:
    case kWasmToJsWrapper:
      DCHECK(ShouldAllocateCodePointerHandle(index, kind));
      return GetProcessWideWasmCodePointerTable()->AllocateAndInitializeEntry(
          address);
    case kJumpTable:
      DCHECK(!ShouldAllocateCodePointerHandle(index, kind));
      return WasmCodePointerTable::kInvalidHandle;
  }
}

WasmCode::~WasmCode() {
  if (has_trap_handler_index()) {
    trap_handler::ReleaseHandlerData(trap_handler_index());
  }

  // Free the code_pointer_handle_ only if we allocated it.
  if (ShouldAllocateCodePointerHandle(index_, kind())) {
    GetProcessWideWasmCodePointerTable()->FreeEntry(code_pointer_handle_);
  }
}

V8_WARN_UNUSED_RESULT bool WasmCode::DecRefOnPotentiallyDeadCode() {
  if (GetWasmEngine()->AddPotentiallyDeadCode(this)) {
    // The code just became potentially dead. The ref count we wanted to
    // decrement is now transferred to the set of potentially dead code, and
    // will be decremented when the next GC is run.
    return false;
  }
  // If we reach here, the code was already potentially dead. Decrement the ref
  // count, and return true if it drops to zero.
  // This can happen when there were temporary C++ references (e.g. while
  // walking a stack) to code objects that are otherwise dead, and this
  // temporary reference is now the last reference.

  return DecRefOnDeadCode();
}

// static
void WasmCode::DecrementRefCount(base::Vector<WasmCode* const> code_vec) {
  // Decrement the ref counter of all given code objects. Keep the ones whose
  // ref count drops to zero.
  WasmEngine::DeadCodeMap dead_code;
  std::vector<WasmCode*> dead_wrappers;
  for (WasmCode* code : code_vec) {
    if (!code->DecRef()) continue;  // Remaining references.
    NativeModule* native_module = code->native_module();
    if (native_module != nullptr) {
      dead_code[native_module].push_back(code);
    } else {
      dead_wrappers.push_back(code);
    }
  }

  if (dead_code.empty() && dead_wrappers.empty()) return;

  GetWasmEngine()->FreeDeadCode(dead_code, dead_wrappers);
}

SourcePosition WasmCode::GetSourcePositionBefore(int code_offset) {
  SourcePosition position;
  for (SourcePositionTableIterator iterator(source_positions());
       !iterator.done() && iterator.code_offset() < code_offset;
       iterator.Advance()) {
    position = iterator.source_position();
  }
  return position;
}

int WasmCode::GetSourceOffsetBefore(int code_offset) {
  return GetSourcePositionBefore(code_offset).ScriptOffset();
}

std::tuple<int, bool, SourcePosition> WasmCode::GetInliningPosition(
    int inlining_id) const {
  const size_t elem_size = sizeof(int) + sizeof(bool) + sizeof(SourcePosition);
  const uint8_t* start = inlining_positions().begin() + elem_size * inlining_id;
  DCHECK_LE(start, inlining_positions().end());
  std::tuple<int, bool, SourcePosition> result;
  std::memcpy(&std::get<0>(result), start, sizeof std::get<0>(result));
  std::memcpy(&std::get<1>(result), start + sizeof std::get<0>(result),
              sizeof std::get<1>(result));
  std::memcpy(&std::get<2>(result),
              start + sizeof std::get<0>(result) + sizeof std::get<1>(result),
              sizeof std::get<2>(result));
  return result;
}

size_t WasmCode::EstimateCurrentMemoryConsumption() const {
  UPDATE_WHEN_CLASS_CHANGES(WasmCode, 104);
  size_t result = sizeof(WasmCode);
  // For meta_data_.
  result += protected_instructions_size_ + reloc_info_size_ +
            source_positions_size_ + inlining_positions_size_ +
            deopt_data_size_;
  return result;
}

WasmCodeAllocator::WasmCodeAllocator(std::shared_ptr<Counters> async_counters)
    : async_counters_(std::move(async_counters)) {
  owned_code_space_.reserve(4);
}

WasmCodeAllocator::~WasmCodeAllocator() {
  GetWasmCodeManager()->FreeNativeModule(base::VectorOf(owned_code_space_),
                                         committed_code_space());
}

void WasmCodeAllocator::Init(VirtualMemory code_space) {
  DCHECK(owned_code_space_.empty());
  DCHECK(free_code_space_.IsEmpty());
  free_code_space_.Merge(code_space.region());
  owned_code_space_.emplace_back(std::move(code_space));
  async_counters_->wasm_module_num_code_spaces()->AddSample(1);
}

namespace {
// On Windows, we cannot commit a region that straddles different reservations
// of virtual memory. Because we bump-allocate, and because, if we need more
// memory, we append that memory at the end of the owned_code_space_ list, we
// traverse that list in reverse order to find the reservation(s) that guide how
// to chunk the region to commit.
#if V8_OS_WIN
constexpr bool kNeedsToSplitRangeByReservations = true;
#else
constexpr bool kNeedsToSplitRangeByReservations = false;
#endif

base::SmallVector<base::AddressRegion, 1> SplitRangeByReservationsIfNeeded(
    base::AddressRegion range,
    const std::vector<VirtualMemory>& owned_code_space) {
  if (!kNeedsToSplitRangeByReservations) return {range};

  base::SmallVector<base::AddressRegion, 1> split_ranges;
  size_t missing_begin = range.begin();
  size_t missing_end = range.end();
  for (auto& vmem : base::Reversed(owned_code_space)) {
    Address overlap_begin = std::max(missing_begin, vmem.address());
    Address overlap_end = std::min(missing_end, vmem.end());
    if (overlap_begin >= overlap_end) continue;
    split_ranges.emplace_back(overlap_begin, overlap_end - overlap_begin);
    // Opportunistically reduce the missing range. This might terminate the loop
    // early.
    if (missing_begin == overlap_begin) missing_begin = overlap_end;
    if (missing_end == overlap_end) missing_end = overlap_begin;
    if (missing_begin >= missing_end) break;
  }
#ifdef ENABLE_SLOW_DCHECKS
  // The returned vector should cover the full range.
  size_t total_split_size = 0;
  for (auto split : split_ranges) total_split_size += split.size();
  DCHECK_EQ(range.size(), total_split_size);
#endif
  return split_ranges;
}

int NumWasmFunctionsInFarJumpTable(uint32_t num_declared_functions) {
  return NativeModule::kNeedsFarJumpsBetweenCodeSpaces
             ? static_cast<int>(num_declared_functions)
             : 0;
}

// Returns an overapproximation of the code size overhead per new code space
// created by the jump tables.
size_t OverheadPerCodeSpace(uint32_t num_declared_functions) {
  // Overhead for the jump table.
  size_t overhead = RoundUp<kCodeAlignment>(
      JumpTableAssembler::SizeForNumberOfSlots(num_declared_functions));

#if defined(V8_OS_WIN64)
  // On Win64, we need to reserve some pages at the beginning of an executable
  // space. See {AddCodeSpace}.
  overhead += Heap::GetCodeRangeReservedAreaSize();
#endif  // V8_OS_WIN64

  // Overhead for the far jump table.
  overhead +=
      RoundUp<kCodeAlignment>(JumpTableAssembler::SizeForNumberOfFarJumpSlots(
          BuiltinLookup::BuiltinCount(),
          NumWasmFunctionsInFarJumpTable(num_declared_functions)));

  return overhead;
}

// Returns an estimate how much code space should be reserved. This can be
// smaller than the passed-in {code_size_estimate}, see comments in the code.
size_t ReservationSize(size_t code_size_estimate, int num_declared_functions,
                       size_t total_reserved) {
  size_t overhead = OverheadPerCodeSpace(num_declared_functions);

  // Reserve the maximum of
  //   a) needed size + overhead (this is the minimum needed)
  //   b) 2 * overhead (to not waste too much space by overhead)
  //   c) 1/4 of current total reservation size (to grow exponentially)
  // For the minimum size we only take the overhead into account and not the
  // code space estimate, for two reasons:
  //  - The code space estimate is only an estimate; we might actually need less
  //    space later.
  //  - When called at module construction time we pass the estimate for all
  //    code in the module; this can still be split up into multiple spaces
  //    later.
  size_t minimum_size = 2 * overhead;
  size_t suggested_size =
      std::max(std::max(RoundUp<kCodeAlignment>(code_size_estimate) + overhead,
                        minimum_size),
               total_reserved / 4);

  const size_t max_code_space_size =
      size_t{v8_flags.wasm_max_code_space_size_mb} * MB;
  if (V8_UNLIKELY(minimum_size > max_code_space_size)) {
    auto oom_detail = base::FormattedString{}
                      << "required reservation minimum (" << minimum_size
                      << ") is bigger than supported maximum ("
                      << max_code_space_size << ")";
    V8::FatalProcessOutOfMemory(nullptr,
                                "Exceeding maximum wasm code space size",
                                oom_detail.PrintToArray().data());
    UNREACHABLE();
  }

  // Limit by the maximum code space size.
  size_t reserve_size = std::min(max_code_space_size, suggested_size);

  return reserve_size;
}

// Sentinel value to be used for {AllocateForCodeInRegion} for specifying no
// restriction on the region to allocate in.
constexpr base::AddressRegion kUnrestrictedRegion{
    kNullAddress, std::numeric_limits<size_t>::max()};

}  // namespace

void WasmCodeAllocator::InitializeCodeRange(NativeModule* native_module,
                                            base::AddressRegion region) {
#if defined(V8_OS_WIN64)
  // On some platforms, specifically Win64, we need to reserve some pages at
  // the beginning of an executable space.
  // See src/heap/spaces.cc, MemoryAllocator::InitializeCodePageAllocator() and
  // https://cs.chromium.org/chromium/src/components/crash/content/app/crashpad_win.cc?rcl=fd680447881449fba2edcf0589320e7253719212&l=204
  // for details.
  if (WasmCodeManager::CanRegisterUnwindInfoForNonABICompliantCodeRange()) {
    size_t size = Heap::GetCodeRangeReservedAreaSize();
    DCHECK_LT(0, size);
    base::Vector<uint8_t> padding =
        AllocateForCodeInRegion(native_module, size, region);
    CHECK_EQ(reinterpret_cast<Address>(padding.begin()), region.begin());
    win64_unwindinfo::RegisterNonABICompliantCodeRange(
        reinterpret_cast<void*>(region.begin()), region.size());
  }
#endif  // V8_OS_WIN64
}

base::Vector<uint8_t> WasmCodeAllocator::AllocateForCode(
    NativeModule* native_module, size_t size) {
  return AllocateForCodeInRegion(native_module, size, kUnrestrictedRegion);
}

base::Vector<uint8_t> WasmCodeAllocator::AllocateForWrapper(size_t size) {
  return AllocateForCodeInRegion(nullptr, size, kUnrestrictedRegion);
}

// {native_module} may be {nullptr} when allocating wrapper code.
base::Vector<uint8_t> WasmCodeAllocator::AllocateForCodeInRegion(
    NativeModule* native_module, size_t size, base::AddressRegion region) {
  DCHECK_LT(0, size);
  auto* code_manager = GetWasmCodeManager();
  size = RoundUp<kCodeAlignment>(size);
  base::AddressRegion code_space =
      free_code_space_.AllocateInRegion(size, region);
  if (V8_UNLIKELY(code_space.is_empty())) {
    // Only allocations without a specific region are allowed to fail. Otherwise
    // the region must have been allocated big enough to hold all initial
    // allocations (jump tables etc).
    CHECK_EQ(kUnrestrictedRegion, region);

    size_t total_reserved = 0;
    for (auto& vmem : owned_code_space_) total_reserved += vmem.size();
    uint32_t num_functions =
        native_module ? native_module->module()->num_declared_functions : 0;
    size_t reserve_size = ReservationSize(size, num_functions, total_reserved);
    if (reserve_size < size) {
      auto oom_detail = base::FormattedString{}
                        << "cannot reserve space for " << size
                        << "bytes of code (maximum reservation size is "
                        << reserve_size << ")";
      V8::FatalProcessOutOfMemory(nullptr, "Grow wasm code space",
                                  oom_detail.PrintToArray().data());
    }
    VirtualMemory new_mem = code_manager->TryAllocate(reserve_size);
    if (!new_mem.IsReserved()) {
      auto oom_detail = base::FormattedString{}
                        << "cannot allocate more code space (" << reserve_size
                        << " bytes, currently " << total_reserved << ")";
      V8::FatalProcessOutOfMemory(nullptr, "Grow wasm code space",
                                  oom_detail.PrintToArray().data());
      UNREACHABLE();
    }

    base::AddressRegion new_region = new_mem.region();
    free_code_space_.Merge(new_region);
    owned_code_space_.emplace_back(std::move(new_mem));
    InitializeCodeRange(native_module, new_region);
    if (native_module) {
      code_manager->AssignRange(new_region, native_module);
      native_module->AddCodeSpaceLocked(new_region);

      async_counters_->wasm_module_num_code_spaces()->AddSample(
          static_cast<int>(owned_code_space_.size()));
    }

    code_space = free_code_space_.Allocate(size);
    CHECK(!code_space.is_empty());
  }
  const Address commit_page_size = CommitPageSize();
  Address commit_start = RoundUp(code_space.begin(), commit_page_size);
  Address commit_end = RoundUp(code_space.end(), commit_page_size);
  // {commit_start} will be either code_space.start or the start of the next
  // page. {commit_end} will be the start of the page after the one in which
  // the allocation ends.
  // We start from an aligned start, and we know we allocated vmem in
  // page multiples.
  // We just need to commit what's not committed. The page in which we
  // start is already committed (or we start at the beginning of a page).
  // The end needs to be committed all through the end of the page.
  if (commit_start < commit_end) {
    for (base::AddressRegion split_range : SplitRangeByReservationsIfNeeded(
             {commit_start, commit_end - commit_start}, owned_code_space_)) {
      code_manager->Commit(split_range);
    }
    committed_code_space_.fetch_add(commit_end - commit_start);
    // Committed code cannot grow bigger than maximum code space size.
    DCHECK_LE(committed_code_space_.load(),
              v8_flags.wasm_max_committed_code_mb * MB);
  }
  DCHECK(IsAligned(code_space.begin(), kCodeAlignment));
  generated_code_size_.fetch_add(code_space.size(), std::memory_order_relaxed);

  TRACE_HEAP("Code alloc for %p: 0x%" PRIxPTR ",+%zu\n", this,
             code_space.begin(), size);
  return {reinterpret_cast<uint8_t*>(code_space.begin()), code_space.size()};
}

void WasmCodeAllocator::FreeCode(base::Vector<WasmCode* const> codes) {
  // Zap code area and collect freed code regions.
  DisjointAllocationPool freed_regions;
  size_t code_size = 0;
  for (WasmCode* code : codes) {
    code_size += code->instructions().size();
    freed_regions.Merge(base::AddressRegion{code->instruction_start(),
                                            code->instructions().size()});
    ThreadIsolation::UnregisterWasmAllocation(code->instruction_start(),
                                              code->instructions().size());
  }
  freed_code_size_.fetch_add(code_size);

  // Merge {freed_regions} into {freed_code_space_} and put all ranges of full
  // pages to decommit into {regions_to_decommit} (decommitting is expensive,
  // so try to merge regions before decommitting).
  DisjointAllocationPool regions_to_decommit;
  size_t commit_page_size = CommitPageSize();
  for (auto region : freed_regions.regions()) {
    auto merged_region = freed_code_space_.Merge(region);
    Address discard_start =
        std::max(RoundUp(merged_region.begin(), commit_page_size),
                 RoundDown(region.begin(), commit_page_size));
    Address discard_end =
        std::min(RoundDown(merged_region.end(), commit_page_size),
                 RoundUp(region.end(), commit_page_size));
    if (discard_start >= discard_end) continue;
    regions_to_decommit.Merge({discard_start, discard_end - discard_start});
  }

  auto* code_manager = GetWasmCodeManager();
  for (auto region : regions_to_decommit.regions()) {
    [[maybe_unused]] size_t old_committed =
        committed_code_space_.fetch_sub(region.size());
    DCHECK_GE(old_committed, region.size());
    for (base::AddressRegion split_range :
         SplitRangeByReservationsIfNeeded(region, owned_code_space_)) {
      code_manager->Decommit(split_range);
    }
  }
}

size_t WasmCodeAllocator::GetNumCodeSpaces() const {
  return owned_code_space_.size();
}

NativeModule::NativeModule(WasmEnabledFeatures enabled_features,
                           WasmDetectedFeatures detected_features,
                           CompileTimeImports compile_imports,
                           DynamicTiering dynamic_tiering,
                           VirtualMemory code_space,
                           std::shared_ptr<const WasmModule> module,
                           std::shared_ptr<Counters> async_counters,
                           std::shared_ptr<NativeModule>* shared_this)
    : engine_scope_(
          GetWasmEngine()->GetBarrierForBackgroundCompile()->TryLock()),
      code_allocator_(async_counters),
      enabled_features_(enabled_features),
      compile_imports_(std::move(compile_imports)),
      module_(std::move(module)),
      fast_api_targets_(
          new std::atomic<Address>[module_->num_imported_functions]()),
      fast_api_signatures_(
          new std::atomic<
              const MachineSignature*>[module_->num_imported_functions]()) {
  DCHECK(engine_scope_);
  // We receive a pointer to an empty {std::shared_ptr}, and install ourselve
  // there.
  DCHECK_NOT_NULL(shared_this);
  DCHECK_NULL(*shared_this);
  shared_this->reset(this);
  compilation_state_ =
      CompilationState::New(*shared_this, std::move(async_counters),
                            dynamic_tiering, detected_features);
  compilation_state_->InitCompileJob();
  DCHECK_NOT_NULL(module_);
  if (module_->num_declared_functions > 0) {
    code_table_ =
        std::make_unique<WasmCode*[]>(module_->num_declared_functions);
    InitializeCodePointerTableHandles(module_->num_declared_functions);
    tiering_budgets_ = std::make_unique<std::atomic<uint32_t>[]>(
        module_->num_declared_functions);
    // The tiering budget is accessed directly from generated code.
    static_assert(sizeof(*tiering_budgets_.get()) == sizeof(uint32_t));

    std::fill_n(tiering_budgets_.get(), module_->num_declared_functions,
                v8_flags.wasm_tiering_budget);
  }

  if (v8_flags.wasm_jitless) return;

  // Even though there cannot be another thread using this object (since we
  // are just constructing it), we need to hold the mutex to fulfill the
  // precondition of {WasmCodeAllocator::Init}, which calls
  // {NativeModule::AddCodeSpaceLocked}.
  base::RecursiveMutexGuard guard{&allocation_mutex_};
  auto initial_region = code_space.region();
  code_allocator_.Init(std::move(code_space));
  code_allocator_.InitializeCodeRange(this, initial_region);
  AddCodeSpaceLocked(initial_region);
}

void NativeModule::ReserveCodeTableForTesting(uint32_t max_functions) {
  if (v8_flags.wasm_jitless) return;

  WasmCodeRefScope code_ref_scope;
  CHECK_LE(module_->num_declared_functions, max_functions);
  auto new_table = std::make_unique<WasmCode*[]>(max_functions);
  if (module_->num_declared_functions > 0) {
    memcpy(new_table.get(), code_table_.get(),
           module_->num_declared_functions * sizeof(WasmCode*));
  }
  code_table_ = std::move(new_table);
  InitializeCodePointerTableHandles(max_functions);

  base::RecursiveMutexGuard guard(&allocation_mutex_);
  CHECK_EQ(1, code_space_data_.size());
  base::AddressRegion single_code_space_region = code_space_data_[0].region;
  // Re-allocate the near and far jump tables.
  main_jump_table_ = CreateEmptyJumpTableInRegionLocked(
      JumpTableAssembler::SizeForNumberOfSlots(max_functions),
      single_code_space_region, JumpTableType::kJumpTable);
  CHECK(
      single_code_space_region.contains(main_jump_table_->instruction_start()));
  main_far_jump_table_ = CreateEmptyJumpTableInRegionLocked(
      JumpTableAssembler::SizeForNumberOfFarJumpSlots(
          BuiltinLookup::BuiltinCount(),
          NumWasmFunctionsInFarJumpTable(max_functions)),
      single_code_space_region, JumpTableType::kFarJumpTable);
  CHECK(single_code_space_region.contains(
      main_far_jump_table_->instruction_start()));
  code_space_data_[0].jump_table = main_jump_table_;
  InitializeJumpTableForLazyCompilation(max_functions);
}

void NativeModule::LogWasmCodes(Isolate* isolate, Tagged<Script> script) {
  DisallowGarbageCollection no_gc;
  if (!WasmCode::ShouldBeLogged(isolate)) return;

  TRACE_EVENT1("v8.wasm", "wasm.LogWasmCodes", "functions",
               module_->num_declared_functions);

  Tagged<Object> url_obj = script->name();
  DCHECK(IsString(url_obj) || IsUndefined(url_obj));
  std::unique_ptr<char[]> source_url =
      IsString(url_obj) ? Cast<String>(url_obj)->ToCString()
                        : std::unique_ptr<char[]>(new char[1]{'\0'});

  // Log all owned code, not just the current entries in the code table. This
  // will also include import wrappers.
  WasmCodeRefScope code_ref_scope;
  for (auto& code : SnapshotAllOwnedCode()) {
    code->LogCode(isolate, source_url.get(), script->id());
  }
}

WasmCode* NativeModule::AddCodeForTesting(DirectHandle<Code> code) {
  const size_t relocation_size = code->relocation_size();
  base::OwnedVector<uint8_t> reloc_info;
  if (relocation_size > 0) {
    reloc_info = base::OwnedVector<uint8_t>::Of(
        base::Vector<uint8_t>{code->relocation_start(), relocation_size});
  }
  DirectHandle<TrustedByteArray> source_pos_table(
      code->source_position_table(), code->instruction_stream()->GetIsolate());
  int source_pos_len = source_pos_table->length();
  auto source_pos = base::OwnedVector<uint8_t>::NewForOverwrite(source_pos_len);
  if (source_pos_len > 0) {
    MemCopy(source_pos.begin(), source_pos_table->begin(), source_pos_len);
  }

  static_assert(InstructionStream::kOnHeapBodyIsContiguous);
  base::Vector<const uint8_t> instructions(
      reinterpret_cast<uint8_t*>(code->body_start()),
      static_cast<size_t>(code->body_size()));
  const int stack_slots = code->stack_slots();

  // Metadata offsets in InstructionStream objects are relative to the start of
  // the metadata section, whereas WasmCode expects offsets relative to
  // instruction_start.
  const int base_offset = code->instruction_size();
  // TODO(jgruber,v8:8758): Remove this translation. It exists only because
  // InstructionStream objects contains real offsets but WasmCode expects an
  // offset of 0 to mean 'empty'.
  const int safepoint_table_offset =
      code->has_safepoint_table() ? base_offset + code->safepoint_table_offset()
                                  : 0;
  const int handler_table_offset = base_offset + code->handler_table_offset();
  const int constant_pool_offset = base_offset + code->constant_pool_offset();
  const int code_comments_offset = base_offset + code->code_comments_offset();

  base::RecursiveMutexGuard guard{&allocation_mutex_};
  base::Vector<uint8_t> dst_code_bytes =
      code_allocator_.AllocateForCode(this, instructions.size());
  {
    WritableJitAllocation jit_allocation =
        ThreadIsolation::RegisterJitAllocation(
            reinterpret_cast<Address>(dst_code_bytes.begin()),
            dst_code_bytes.size(),
            ThreadIsolation::JitAllocationType::kWasmCode, true);
    jit_allocation.CopyCode(0, instructions.begin(), instructions.size());

    // Apply the relocation delta by iterating over the RelocInfo.
    intptr_t delta = reinterpret_cast<Address>(dst_code_bytes.begin()) -
                     code->instruction_start();
    int mode_mask = RelocInfo::kApplyMask |
                    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET);
    auto jump_tables_ref =
        FindJumpTablesForRegionLocked(base::AddressRegionOf(dst_code_bytes));
    Address dst_code_addr = reinterpret_cast<Address>(dst_code_bytes.begin());
    Address constant_pool_start = dst_code_addr + constant_pool_offset;
    RelocIterator orig_it(*code, mode_mask);
    for (WritableRelocIterator it(jit_allocation, dst_code_bytes,
                                  reloc_info.as_vector(), constant_pool_start,
                                  mode_mask);
         !it.done(); it.next(), orig_it.next()) {
      RelocInfo::Mode mode = it.rinfo()->rmode();
      if (RelocInfo::IsWasmStubCall(mode)) {
        uint32_t stub_call_tag = orig_it.rinfo()->wasm_call_tag();
        DCHECK_LT(stub_call_tag,
                  static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
        Builtin builtin = static_cast<Builtin>(stub_call_tag);
        Address entry = GetJumpTableEntryForBuiltin(builtin, jump_tables_ref);
        it.rinfo()->set_wasm_stub_call_address(entry);
      } else if (RelocInfo::IsWasmIndirectCallTarget(mode)) {
        Address function_index = it.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target =
            GetIndirectCallTarget(base::checked_cast<uint32_t>(function_index));
        it.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } else {
        it.rinfo()->apply(delta);
      }
    }
  }

  // Flush the i-cache after relocation.
  FlushInstructionCache(dst_code_bytes.begin(), dst_code_bytes.size());

  std::unique_ptr<WasmCode> new_code{
      new WasmCode{this,                     // native_module
                   kAnonymousFuncIndex,      // index
                   dst_code_bytes,           // instructions
                   stack_slots,              // stack_slots
                   0,                        // ool_spills
                   0,                        // tagged_parameter_slots
                   safepoint_table_offset,   // safepoint_table_offset
                   handler_table_offset,     // handler_table_offset
                   constant_pool_offset,     // constant_pool_offset
                   code_comments_offset,     // code_comments_offset
                   instructions.length(),    // unpadded_binary_size
                   {},                       // protected_instructions
                   reloc_info.as_vector(),   // reloc_info
                   source_pos.as_vector(),   // source positions
                   {},                       // inlining positions
                   {},                       // deopt data
                   WasmCode::kWasmFunction,  // kind
                   ExecutionTier::kNone,     // tier
                   kNotForDebugging}};       // for_debugging
  new_code->MaybePrint();
  new_code->Validate();

  return PublishCodeLocked(std::move(new_code));
}

void NativeModule::InitializeJumpTableForLazyCompilation(
    uint32_t num_wasm_functions) {
  if (!num_wasm_functions) return;
  allocation_mutex_.AssertHeld();

  DCHECK_NULL(lazy_compile_table_);
  lazy_compile_table_ = CreateEmptyJumpTableLocked(
      JumpTableAssembler::SizeForNumberOfLazyFunctions(num_wasm_functions),
      JumpTableType::kLazyCompileTable);

  CHECK_EQ(1, code_space_data_.size());
  const CodeSpaceData& code_space_data = code_space_data_[0];
  DCHECK_NOT_NULL(code_space_data.jump_table);
  DCHECK_NOT_NULL(code_space_data.far_jump_table);

  Address compile_lazy_address =
      code_space_data.far_jump_table->instruction_start() +
      JumpTableAssembler::FarJumpSlotIndexToOffset(
          BuiltinLookup::JumptableIndexForBuiltin(Builtin::kWasmCompileLazy));

  JumpTableAssembler::GenerateLazyCompileTable(
      lazy_compile_table_->instruction_start(), num_wasm_functions,
      module_->num_imported_functions, compile_lazy_address);

  JumpTableAssembler::InitializeJumpsToLazyCompileTable(
      code_space_data.jump_table->instruction_start(), num_wasm_functions,
      lazy_compile_table_->instruction_start());

  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  WasmCodePointerTable::WriteScope write_scope(
      "Initialize WasmCodePointerTable");
  DCHECK_LE(num_wasm_functions, code_pointer_handles_size_);
  for (uint32_t i = 0; i < num_wasm_functions; i++) {
    code_pointer_table->SetEntrypointWithWriteScope(
        code_pointer_handles_[i],
        lazy_compile_table_->instruction_start() +
            JumpTableAssembler::LazyCompileSlotIndexToOffset(i),
        write_scope);
  }
}

void NativeModule::UseLazyStubLocked(uint32_t func_index) {
  allocation_mutex_.AssertHeld();
  DCHECK_LE(module_->num_imported_functions, func_index);
  DCHECK_LT(func_index,
            module_->num_imported_functions + module_->num_declared_functions);
  // Avoid opening a new write scope per function. The caller should hold the
  // scope instead.

  DCHECK_NOT_NULL(lazy_compile_table_);

  // Add jump table entry for jump to the lazy compile stub.
  uint32_t slot_index = declared_function_index(module(), func_index);
  DCHECK_NULL(code_table_[slot_index]);
  Address lazy_compile_target =
      lazy_compile_table_->instruction_start() +
      JumpTableAssembler::LazyCompileSlotIndexToOffset(slot_index);
  PatchJumpTablesLocked(slot_index, lazy_compile_target);
}

std::unique_ptr<WasmCode> NativeModule::AddCode(
    int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
    uint32_t tagged_parameter_slots,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier, ForDebugging for_debugging) {
  base::Vector<uint8_t> code_space;
  NativeModule::JumpTablesRef jump_table_ref;
  {
    base::RecursiveMutexGuard guard{&allocation_mutex_};
    code_space = code_allocator_.AllocateForCode(this, desc.instr_size);
    jump_table_ref =
        FindJumpTablesForRegionLocked(base::AddressRegionOf(code_space));
  }
  // Only Liftoff code can have the {frame_has_feedback_slot} bit set.
  DCHECK_NE(tier, ExecutionTier::kLiftoff);
  bool frame_has_feedback_slot = false;
  ThreadIsolation::RegisterJitAllocation(
      reinterpret_cast<Address>(code_space.begin()), code_space.size(),
      ThreadIsolation::JitAllocationType::kWasmCode);
  return AddCodeWithCodeSpace(
      index, desc, stack_slots, ool_spill_count, tagged_parameter_slots,
      protected_instructions_data, source_position_table, inlining_positions,
      deopt_data, kind, tier, for_debugging, frame_has_feedback_slot,
      code_space, jump_table_ref);
}

void NativeModule::FreeCodePointerTableHandles() {
  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  for (uint32_t i = 0; i < code_pointer_handles_size_; i++) {
    code_pointer_table->FreeEntry(code_pointer_handles_[i]);
  }

  code_pointer_handles_.reset();
  code_pointer_handles_size_ = 0;
}

void NativeModule::InitializeCodePointerTableHandles(
    uint32_t num_wasm_functions) {
  if (code_pointer_handles_size_ != 0) {
    // During testing, we might already have code pointer handles allocated.
    FreeCodePointerTableHandles();
  }
  code_pointer_handles_ =
      std::make_unique<WasmCodePointerTable::Handle[]>(num_wasm_functions);
  code_pointer_handles_size_ = num_wasm_functions;

  WasmCodePointerTable* code_pointer_table =
      GetProcessWideWasmCodePointerTable();
  for (uint32_t i = 0; i < num_wasm_functions; i++) {
    code_pointer_handles_[i] = code_pointer_table->AllocateUninitializedEntry();
  }
}

std::unique_ptr<WasmCode> NativeModule::AddCodeWithCodeSpace(
    int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
    uint32_t tagged_parameter_slots,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier, ForDebugging for_debugging,
    bool frame_has_feedback_slot, base::Vector<uint8_t> dst_code_bytes,
    const JumpTablesRef& jump_tables) {
  base::Vector<uint8_t> reloc_info{
      desc.buffer + desc.buffer_size - desc.reloc_size,
      static_cast<size_t>(desc.reloc_size)};
  UpdateCodeSize(desc.instr_size, tier, for_debugging);

  // TODO(jgruber,v8:8758): Remove this translation. It exists only because
  // CodeDesc contains real offsets but WasmCode expects an offset of 0 to mean
  // 'empty'.
  const int safepoint_table_offset =
      desc.safepoint_table_size == 0 ? 0 : desc.safepoint_table_offset;
  const int handler_table_offset = desc.handler_table_offset;
  const int constant_pool_offset = desc.constant_pool_offset;
  const int code_comments_offset = desc.code_comments_offset;
  const int instr_size = desc.instr_size;

  {
    WritableJitAllocation jit_allocation = ThreadIsolation::LookupJitAllocation(
        reinterpret_cast<Address>(dst_code_bytes.begin()),
        dst_code_bytes.size(), ThreadIsolation::JitAllocationType::kWasmCode,
        true);
    jit_allocation.CopyCode(0, desc.buffer, desc.instr_size);

    // Apply the relocation delta by iterating over the RelocInfo.
    intptr_t delta = dst_code_bytes.begin() - desc.buffer;
    int mode_mask = RelocInfo::kApplyMask |
                    RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
                    RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET);
    Address code_start = reinterpret_cast<Address>(dst_code_bytes.begin());
    Address constant_pool_start = code_start + constant_pool_offset;

    for (WritableRelocIterator it(jit_allocation, dst_code_bytes, reloc_info,
                                  constant_pool_start, mode_mask);
         !it.done(); it.next()) {
      RelocInfo::Mode mode = it.rinfo()->rmode();
      if (RelocInfo::IsWasmCall(mode)) {
        uint32_t call_tag = it.rinfo()->wasm_call_tag();
        Address target = GetNearCallTargetForFunction(call_tag, jump_tables);
        it.rinfo()->set_wasm_call_address(target);
      } else if (RelocInfo::IsWasmStubCall(mode)) {
        uint32_t stub_call_tag = it.rinfo()->wasm_call_tag();
        DCHECK_LT(stub_call_tag,
                  static_cast<uint32_t>(Builtin::kFirstBytecodeHandler));
        Builtin builtin = static_cast<Builtin>(stub_call_tag);
        Address entry = GetJumpTableEntryForBuiltin(builtin, jump_tables);
        it.rinfo()->set_wasm_stub_call_address(entry);
      } else if (RelocInfo::IsWasmIndirectCallTarget(mode)) {
        Address function_index = it.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target =
            GetIndirectCallTarget(base::checked_cast<uint32_t>(function_index));
        it.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } else {
        it.rinfo()->apply(delta);
      }
    }
  }

  // Flush the i-cache after relocation.
  FlushInstructionCache(dst_code_bytes.begin(), dst_code_bytes.size());

  // Liftoff code will not be relocated or serialized, thus do not store any
  // relocation information.
  if (tier == ExecutionTier::kLiftoff) reloc_info = {};

  std::unique_ptr<WasmCode> code{new WasmCode{this,
                                              index,
                                              dst_code_bytes,
                                              stack_slots,
                                              ool_spill_count,
                                              tagged_parameter_slots,
                                              safepoint_table_offset,
                                              handler_table_offset,
                                              constant_pool_offset,
                                              code_comments_offset,
                                              instr_size,
                                              protected_instructions_data,
                                              reloc_info,
                                              source_position_table,
                                              inlining_positions,
                                              deopt_data,
                                              kind,
                                              tier,
                                              for_debugging,
                                              frame_has_feedback_slot}};

  code->MaybePrint();
  code->Validate();

  return code;
}

WasmCode* NativeModule::PublishCode(std::unique_ptr<WasmCode> code,
                                    AssumptionsJournal* assumptions) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.PublishCode");
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  if (assumptions != nullptr) {
    // Acquiring the lock is expensive, so callers should only pass non-empty
    // assumptions journals.
    DCHECK(!assumptions->empty());
    // Only Turbofan makes assumptions.
    DCHECK_EQ(ExecutionTier::kTurbofan, code->tier());
    WellKnownImportsList& current = module_->type_feedback.well_known_imports;
    for (auto [import_index, status] : assumptions->import_statuses()) {
      if (current.get(import_index) != status) {
        compilation_state_->AllowAnotherTopTierJob(code->index());
        return nullptr;
      }
    }
  }
  return PublishCodeLocked(std::move(code));
}

std::vector<WasmCode*> NativeModule::PublishCode(
    base::Vector<std::unique_ptr<WasmCode>> codes) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.PublishCode", "number", codes.size());
  std::vector<WasmCode*> published_code;
  published_code.reserve(codes.size());
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  // The published code is put into the top-most surrounding {WasmCodeRefScope}.
  for (auto& code : codes) {
    published_code.push_back(PublishCodeLocked(std::move(code)));
  }
  return published_code;
}

void NativeModule::UpdateWellKnownImports(
    base::Vector<WellKnownImport> entries) {
  // The {~WasmCodeRefScope} destructor must run after releasing the {lock},
  // to avoid lock order inversion.
  WasmCodeRefScope ref_scope;
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  WellKnownImportsList::UpdateResult result =
      module_->type_feedback.well_known_imports.Update(entries);
  if (result == WellKnownImportsList::UpdateResult::kFoundIncompatibility) {
    RemoveCompiledCode(NativeModule::RemoveFilter::kRemoveTurbofanCode);
  }
}

WasmCode::Kind GetCodeKind(const WasmCompilationResult& result) {
  switch (result.kind) {
    case WasmCompilationResult::kWasmToJsWrapper:
      return WasmCode::Kind::kWasmToJsWrapper;
#if V8_ENABLE_DRUMBRAKE
    case WasmCompilationResult::kInterpreterEntry:
      return WasmCode::Kind::kInterpreterEntry;
#endif  // V8_ENABLE_DRUMBRAKE
    case WasmCompilationResult::kFunction:
      return WasmCode::Kind::kWasmFunction;
    default:
      UNREACHABLE();
  }
}

WasmCode* NativeModule::PublishCodeLocked(
    std::unique_ptr<WasmCode> owned_code) {
  allocation_mutex_.AssertHeld();

  WasmCode* code = owned_code.get();
  new_owned_code_.emplace_back(std::move(owned_code));

  // Add the code to the surrounding code ref scope, so the returned pointer is
  // guaranteed to be valid.
  WasmCodeRefScope::AddRef(code);

  if (code->index() < static_cast<int>(module_->num_imported_functions)) {
    return code;
  }

  DCHECK_LT(code->index(), num_functions());

  code->RegisterTrapHandlerData();

  // Assume an order of execution tiers that represents the quality of their
  // generated code.
  static_assert(ExecutionTier::kNone < ExecutionTier::kLiftoff &&
                    ExecutionTier::kLiftoff < ExecutionTier::kTurbofan,
                "Assume an order on execution tiers");

  uint32_t slot_idx = declared_function_index(module(), code->index());
  WasmCode* prior_code = code_table_[slot_idx];
  // If we are tiered down, install all debugging code (except for stepping
  // code, which is only used for a single frame and never installed in the
  // code table of jump table). Otherwise, install code if it was compiled
  // with a higher tier.
  static_assert(
      kForDebugging > kNotForDebugging && kWithBreakpoints > kForDebugging,
      "for_debugging is ordered");

  if (should_update_code_table(code, prior_code)) {
    code_table_[slot_idx] = code;
    if (prior_code) {
      WasmCodeRefScope::AddRef(prior_code);
      // The code is added to the current {WasmCodeRefScope}, hence the ref
      // count cannot drop to zero here.
      prior_code->DecRefOnLiveCode();
    }

    PatchJumpTablesLocked(slot_idx, code->instruction_start());
  } else {
    // The code tables does not hold a reference to the code, hence decrement
    // the initial ref count of 1. The code was added to the
    // {WasmCodeRefScope} though, so it cannot die here.
    code->DecRefOnLiveCode();
  }

  return code;
}

bool NativeModule::should_update_code_table(WasmCode* new_code,
                                            WasmCode* prior_code) const {
  if (new_code->for_debugging() == kForStepping) {
    // Never install stepping code.
    return false;
  }
  if (debug_state_ == kDebugging) {
    if (new_code->for_debugging() == kNotForDebugging) {
      // In debug state, only install debug code.
      return false;
    }
    if (prior_code && prior_code->for_debugging() > new_code->for_debugging()) {
      // In debug state, install breakpoints over normal debug code.
      return false;
    }
  }
  // In kNoDebugging:
  // Install if the tier is higher than before or we replace debugging code with
  // non-debugging code.
  // Also allow installing a lower tier if deopt support is enabled and the
  // prior code has deopt data. (The check for deopt_data is needed as with
  // compilation hints, both baseline and top tier compilation run concurrently
  // in the background and can finish in any order.)
  if (prior_code && !prior_code->for_debugging() &&
      prior_code->tier() > new_code->tier() &&
      (!v8_flags.wasm_deopt || prior_code->deopt_data().empty())) {
    return false;
  }
  return true;
}

void NativeModule::ReinstallDebugCode(WasmCode* code) {
  base::RecursiveMutexGuard lock(&allocation_mutex_);

  DCHECK_EQ(this, code->native_module());
  DCHECK_EQ(kWithBreakpoints, code->for_debugging());
  DCHECK(!code->IsAnonymous());
  DCHECK_LE(module_->num_imported_functions, code->index());
  DCHECK_LT(code->index(), num_functions());

  // If the module is tiered up by now, do not reinstall debug code.
  if (debug_state_ != kDebugging) return;

  uint32_t slot_idx = declared_function_index(module(), code->index());
  if (WasmCode* prior_code = code_table_[slot_idx]) {
    WasmCodeRefScope::AddRef(prior_code);
    // The code is added to the current {WasmCodeRefScope}, hence the ref
    // count cannot drop to zero here.
    prior_code->DecRefOnLiveCode();
  }
  code_table_[slot_idx] = code;
  code->IncRef();

  PatchJumpTablesLocked(slot_idx, code->instruction_start());
}

std::pair<base::Vector<uint8_t>, NativeModule::JumpTablesRef>
NativeModule::AllocateForDeserializedCode(size_t total_code_size) {
  base::RecursiveMutexGuard guard{&allocation_mutex_};
  base::Vector<uint8_t> code_space =
      code_allocator_.AllocateForCode(this, total_code_size);
  auto jump_tables =
      FindJumpTablesForRegionLocked(base::AddressRegionOf(code_space));
  return {code_space, jump_tables};
}

std::unique_ptr<WasmCode> NativeModule::AddDeserializedCode(
    int index, base::Vector<uint8_t> instructions, int stack_slots,
    int ool_spills, uint32_t tagged_parameter_slots, int safepoint_table_offset,
    int handler_table_offset, int constant_pool_offset,
    int code_comments_offset, int unpadded_binary_size,
    base::Vector<const uint8_t> protected_instructions_data,
    base::Vector<const uint8_t> reloc_info,
    base::Vector<const uint8_t> source_position_table,
    base::Vector<const uint8_t> inlining_positions,
    base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
    ExecutionTier tier) {
  UpdateCodeSize(instructions.size(), tier, kNotForDebugging);

  return std::unique_ptr<WasmCode>{new WasmCode{
      this, index, instructions, stack_slots, ool_spills,
      tagged_parameter_slots, safepoint_table_offset, handler_table_offset,
      constant_pool_offset, code_comments_offset, unpadded_binary_size,
      protected_instructions_data, reloc_info, source_position_table,
      inlining_positions, deopt_data, kind, tier, kNotForDebugging}};
}

std::pair<std::vector<WasmCode*>, std::vector<WellKnownImport>>
NativeModule::SnapshotCodeTable() const {
  base::RecursiveMutexGuard lock(&allocation_mutex_);
  WasmCode** start = code_table_.get();
  WasmCode** end = start + module_->num_declared_functions;
  for (WasmCode* code : base::VectorOf(start, end - start)) {
    if (code) WasmCodeRefScope::AddRef(code);
  }
  std::vector<WellKnownImport> import_statuses(module_->num_imported_functions);
  for (uint32_t i = 0; i < module_->num
```