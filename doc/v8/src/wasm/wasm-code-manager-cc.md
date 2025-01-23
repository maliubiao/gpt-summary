Response:

### 提示词
```
这是目录为v8/src/wasm/wasm-code-manager.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```