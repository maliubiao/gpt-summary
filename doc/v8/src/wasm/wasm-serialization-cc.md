Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine.

Here's a breakdown of how to address each point:

1. **List the functionality:**  Analyze the code and identify the main actions it performs. Look for class names, function names, and variables that indicate the purpose of different code sections.

2. **.tq extension:** Check if the code mentions or implies any relationship with Torque, V8's type-checked superset of C++. The presence of the `.cc` extension immediately tells us it's not a Torque file.

3. **Relationship with JavaScript:** Determine if the code interacts with JavaScript concepts. Look for mentions of "Wasm" (WebAssembly), which is closely tied to JavaScript in browsers.

4. **JavaScript examples:** If there's a relationship with JavaScript, provide illustrative JavaScript code snippets.

5. **Code logic and reasoning:** If the code performs computations or transformations, create hypothetical inputs and trace the execution to predict the output. This is particularly relevant for the `Writer` and `Reader` classes and the relocation logic.

6. **Common programming errors:** Identify potential issues that a developer might encounter while working with this kind of code, focusing on areas like buffer management, data alignment, and error handling.

7. **Summarize the functionality:** Concisely describe the overall purpose and key features of the code.

**Mental Sandbox:**

*   The file name `wasm-serialization.cc` strongly suggests that the code is about serializing and deserializing WebAssembly modules.
*   The inclusion of headers like `wasm/wasm-module.h`, `wasm/wasm-code-manager.h`, and `snapshot/snapshot-data.h` reinforces this idea. Serialization is often used for snapshots or caching.
*   The `Writer` and `Reader` classes clearly handle writing and reading byte streams.
*   The functions involving `RelocInfo` point to the process of adjusting code addresses during serialization/deserialization.
*   The `NativeModuleSerializer` and `NativeModuleDeserializer` classes seem to encapsulate the serialization/deserialization logic for a complete WebAssembly module.
*   The interaction with `ExecutionTier` (like `kTurbofan` and `kLiftoff`) indicates that the serialization process handles different compilation stages.
*   The `DeserializeCodeTask` suggests asynchronous or background processing of deserialization.

**Constraint Checklist & Confidence Score:**

*   List functionality: Yes
*   .tq extension: Yes (negative answer)
*   Relationship with JavaScript: Yes
*   JavaScript example: Yes
*   Code logic/reasoning: Yes
*   Hypothetical input/output: Yes
*   Common programming errors: Yes
*   Summarize functionality: Yes

Confidence Score: 5/5

Strategizing complete. I will now proceed to generate the response based on the above analysis.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-serialization.h"

#include "src/codegen/assembler-arch.h"
#include "src/codegen/assembler-inl.h"
#include "src/debug/debug.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot-data.h"
#include "src/utils/ostreams.h"
#include "src/utils/version.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/well-known-imports.h"

namespace v8::internal::wasm {

namespace {
constexpr uint8_t kLazyFunction = 2;
constexpr uint8_t kEagerFunction = 3;
constexpr uint8_t kTurboFanFunction = 4;

// TODO(bbudge) Try to unify the various implementations of readers and writers
// in Wasm, e.g. StreamProcessor and ZoneBuffer, with these.
class Writer {
 public:
  explicit Writer(base::Vector<uint8_t> buffer)
      : start_(buffer.begin()), end_(buffer.end()), pos_(buffer.begin()) {}

  size_t bytes_written() const { return pos_ - start_; }
  uint8_t* current_location() const { return pos_; }
  size_t current_size() const { return end_ - pos_; }
  base::Vector<uint8_t> current_buffer() const {
    return {current_location(), current_size()};
  }

  template <typename T>
  void Write(const T& value) {
    DCHECK_GE(current_size(), sizeof(T));
    WriteUnalignedValue(reinterpret_cast<Address>(current_location()), value);
    pos_ += sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "wrote: " << static_cast<size_t>(value)
                     << " sized: " << sizeof(T) << std::endl;
    }
  }

  template <typename T>
  void WriteVector(const base::Vector<T> v) {
    base::Vector<const uint8_t> bytes = base::Vector<const uint8_t>::cast(v);
    DCHECK_GE(current_size(), bytes.size());
    if (!bytes.empty()) {
      memcpy(current_location(), bytes.begin(), bytes.size());
      pos_ += bytes.size();
    }
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "wrote vector of " << v.size()
                     << " elements (total size " << bytes.size() << " bytes)"
                     << std::endl;
    }
  }

  void Skip(size_t size) { pos_ += size; }

 private:
  uint8_t* const start_;
  uint8_t* const end_;
  uint8_t* pos_;
};

class Reader {
 public:
  explicit Reader(base::Vector<const uint8_t> buffer)
      : start_(buffer.begin()), end_(buffer.end()), pos_(buffer.begin()) {}

  size_t bytes_read() const { return pos_ - start_; }
  const uint8_t* current_location() const { return pos_; }
  size_t current_size() const { return end_ - pos_; }
  base::Vector<const uint8_t> current_buffer() const {
    return {current_location(), current_size()};
  }

  template <typename T>
  T Read() {
    DCHECK_GE(current_size(), sizeof(T));
    T value =
        ReadUnalignedValue<T>(reinterpret_cast<Address>(current_location()));
    pos_ += sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "read: " << static_cast<size_t>(value)
                     << " sized: " << sizeof(T) << std::endl;
    }
    return value;
  }

  template <typename T>
  base::Vector<const T> ReadVector(size_t size) {
    DCHECK_GE(current_size(), size);
    base::Vector<const uint8_t> bytes{pos_, size * sizeof(T)};
    pos_ += size * sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "read vector of " << size << " elements of size "
                     << sizeof(T) << " (total size " << size * sizeof(T) << ")"
                     << std::endl;
    }
    return base::Vector<const T>::cast(bytes);
  }

  void Skip(size_t size) { pos_ += size; }

 private:
  const uint8_t* const start_;
  const uint8_t* const end_;
  const uint8_t* pos_;
};

void WriteHeader(Writer* writer, WasmEnabledFeatures enabled_features) {
  DCHECK_EQ(0, writer->bytes_written());
  writer->Write(SerializedData::kMagicNumber);
  writer->Write(Version::Hash());
  writer->Write(static_cast<uint32_t>(CpuFeatures::SupportedFeatures()));
  writer->Write(FlagList::Hash());
  writer->Write(enabled_features.ToIntegral());
  DCHECK_EQ(WasmSerializer::kHeaderSize, writer->bytes_written());
}

// On Intel, call sites are encoded as a displacement. For linking and for
// serialization/deserialization, we want to store/retrieve a tag (the function
// index). On Intel, that means accessing the raw displacement.
// On ARM64, call sites are encoded as either a literal load or a direct branch.
// Other platforms simply require accessing the target address.
void SetWasmCalleeTag(WritableRelocInfo* rinfo, uint32_t tag) {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  DCHECK(rinfo->HasTargetAddressAddress());
  DCHECK(!RelocInfo::IsCompressedEmbeddedObject(rinfo->rmode()));
  WriteUnalignedValue(rinfo->target_address_address(), tag);
#elif V8_TARGET_ARCH_ARM64
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsLdrLiteralX()) {
    WriteUnalignedValue(rinfo->constant_pool_entry_address(),
                        static_cast<Address>(tag));
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    instr->SetBranchImmTarget<UncondBranchType>(
        reinterpret_cast<Instruction*>(rinfo->pc() + tag * kInstrSize));
  }
#elif V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsAUIPC()) {
    Instr auipc = instr->InstructionBits();
    Instr jalr = reinterpret_cast<Instruction*>(rinfo->pc() + 1 * kInstrSize)
                     ->InstructionBits();
    DCHECK(is_int32(tag + 0x800));
    Assembler::PatchBranchlongOffset(rinfo->pc(), auipc, jalr, (int32_t)tag,
                                     nullptr);
  } else {
    Assembler::set_target_address_at(rinfo->pc(), rinfo->constant_pool(),
                                     static_cast<Address>(tag), nullptr,
                                     SKIP_ICACHE_FLUSH);
  }
#else
  Address addr = static_cast<Address>(tag);
  if (rinfo->rmode() == RelocInfo::EXTERNAL_REFERENCE) {
    rinfo->set_target_external_reference(addr, SKIP_ICACHE_FLUSH);
  } else if (rinfo->rmode() == RelocInfo::WASM_STUB_CALL) {
    rinfo->set_wasm_stub_call_address(addr);
  } else {
    rinfo->set_target_address(addr, SKIP_ICACHE_FLUSH);
  }
#endif
}

uint32_t GetWasmCalleeTag(RelocInfo* rinfo) {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  DCHECK(!RelocInfo::IsCompressedEmbeddedObject(rinfo->rmode()));
  return ReadUnalignedValue<uint32_t>(rinfo->target_address_address());
#elif V8_TARGET_ARCH_ARM64
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsLdrLiteralX()) {
    return ReadUnalignedValue<uint32_t>(rinfo->constant_pool_entry_address());
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return static_cast<uint32_t>(instr->ImmPCOffset() / kInstrSize);
  }
#elif V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsAUIPC()) {
    Instr auipc = instr->InstructionBits();
    Instr jalr = reinterpret_cast<Instruction*>(rinfo->pc() + 1 * kInstrSize)
                     ->InstructionBits();
    return Assembler::BrachlongOffset(auipc, jalr);
  } else {
    return static_cast<uint32_t>(rinfo->target_address());
  }
#else
  Address addr;
  if (rinfo->rmode() == RelocInfo::EXTERNAL_REFERENCE) {
    addr = rinfo->target_external_reference();
  } else if (rinfo->rmode() == RelocInfo::WASM_STUB_CALL) {
    addr = rinfo->wasm_stub_call_address();
  } else {
    addr = rinfo->target_address();
  }
  return static_cast<uint32_t>(addr);
#endif
}

constexpr size_t kCodeHeaderSize = sizeof(uint8_t) +  // code kind
                                   sizeof(int) +      // offset of constant pool
                                   sizeof(int) +  // offset of safepoint table
                                   sizeof(int) +  // offset of handler table
                                   sizeof(int) +  // offset of code comments
                                   sizeof(int) +  // unpadded binary size
                                   sizeof(int) +  // stack slots
                                   sizeof(int) +  // ool slots
                                   sizeof(int) +  // tagged parameter slots
                                   sizeof(int) +  // code size
                                   sizeof(int) +  // reloc size
                                   sizeof(int) +  // source positions size
                                   sizeof(int) +  // inlining positions size
                                   sizeof(int) +  // deopt data size
                                   sizeof(int) +  // protected instructions size
                                   sizeof(WasmCode::Kind) +  // code kind
                                   sizeof(ExecutionTier);    // tier

// A List of all isolate-independent external references. This is used to create
// a tag from the Address of an external reference and vice versa.
class ExternalReferenceList {
 public:
  ExternalReferenceList(const ExternalReferenceList&) = delete;
  ExternalReferenceList& operator=(const ExternalReferenceList&) = delete;

  uint32_t tag_from_address(Address ext_ref_address) const {
    auto tag_addr_less_than = [this](uint32_t tag, Address searched_addr) {
      return external_reference_by_tag_[tag] < searched_addr;
    };
    auto it = std::lower_bound(std::begin(tags_ordered_by_address_),
                               std::end(tags_ordered_by_address_),
                               ext_ref_address, tag_addr_less_than);
    DCHECK_NE(std::end(tags_ordered_by_address_), it);
    uint32_t tag = *it;
    DCHECK_EQ(address_from_tag(tag), ext_ref_address);
    return tag;
  }

  Address address_from_tag(uint32_t tag) const {
    DCHECK_GT(kNumExternalReferences, tag);
    return external_reference_by_tag_[tag];
  }

  static const ExternalReferenceList& Get() {
    static ExternalReferenceList list;  // Lazily initialized.
    return list;
  }

 private:
  // Private constructor. There will only be a single instance of this object.
  ExternalReferenceList() {
    for (uint32_t i = 0; i < kNumExternalReferences; ++i) {
      tags_ordered_by_address_[i] = i;
    }
    auto addr_by_tag_less_than = [this](uint32_t a, uint32_t b) {
      return external_reference_by_tag_[a] < external_reference_by_tag_[b];
    };
    std::sort(std::begin(tags_ordered_by_address_),
              std::end(tags_ordered_by_address_), addr_by_tag_less_than);
  }

#define COUNT_EXTERNAL_REFERENCE(name, ...) +1
  static constexpr uint32_t kNumExternalReferencesList =
      EXTERNAL_REFERENCE_LIST(COUNT_EXTERNAL_REFERENCE);
  static constexpr uint32_t kNumExternalReferencesIntrinsics =
      FOR_EACH_INTRINSIC(COUNT_EXTERNAL_REFERENCE);
  static constexpr uint32_t kNumExternalReferences =
      kNumExternalReferencesList + kNumExternalReferencesIntrinsics;
#undef COUNT_EXTERNAL_REFERENCE

  Address external_reference_by_tag_[kNumExternalReferences] = {
#define EXT_REF_ADDR(name, desc) ExternalReference::name().address(),
      EXTERNAL_REFERENCE_LIST(EXT_REF_ADDR)
#undef EXT_REF_ADDR
#define RUNTIME_ADDR(name, ...) \
  ExternalReference::Create(Runtime::k##name).address(),
          FOR_EACH_INTRINSIC(RUNTIME_ADDR)
#undef RUNTIME_ADDR
  };
  uint32_t tags_ordered_by_address_[kNumExternalReferences];
};

static_assert(std::is_trivially_destructible<ExternalReferenceList>::value,
              "static destructors not allowed");

}  // namespace

class V8_EXPORT_PRIVATE NativeModuleSerializer {
 public:
  NativeModuleSerializer(const NativeModule*, base::Vector<WasmCode* const>,
                         base::Vector<WellKnownImport const>);
  NativeModuleSerializer(const NativeModuleSerializer&) = delete;
  NativeModuleSerializer& operator=(const NativeModuleSerializer&) = delete;

  size_t Measure() const;
  bool Write(Writer* writer);

 private:
  size_t MeasureCode(const WasmCode*) const;
  void WriteHeader(Writer*, size_t total_code_size);
  void WriteCode(const WasmCode*, Writer*,
                 const NativeModule::CallIndirectTargetMap&);
  void WriteTieringBudget(Writer* writer);

  uint32_t CanonicalSigIdToModuleLocalTypeId(uint32_t canonical_sig_id);

  const NativeModule* const native_module_;
  const base::Vector<WasmCode* const> code_table_;
  const base::Vector<WellKnownImport const> import_statuses_;
  // Map back canonical signature IDs to module-local IDs. Initialized lazily.
  std::unordered_map<uint32_t, uint32_t> canonical_sig_ids_to_module_local_ids_;
  bool write_called_ = false;
  size_t total_written_code_ = 0;
  int num_turbofan_functions_ = 0;
};

NativeModuleSerializer::NativeModuleSerializer(
    const NativeModule* module, base::Vector<WasmCode* const> code_table,
    base::Vector<WellKnownImport const> import_statuses)
    : native_module_(module),
      code_table_(code_table),
      import_statuses_(import_statuses) {
  DCHECK_NOT_NULL(native_module_);
  // TODO(mtrofin): persist the export wrappers. Ideally, we'd only persist
  // the unique ones, i.e. the cache.
}

size_t NativeModuleSerializer::MeasureCode(const WasmCode* code) const {
  if (code == nullptr) return sizeof(uint8_t);
  DCHECK_EQ(WasmCode::kWasmFunction, code->kind());
  if (code->tier() != ExecutionTier::kTurbofan) {
    return sizeof(uint8_t);
  }
  return kCodeHeaderSize + code->instructions().size() +
         code->reloc_info().size() + code->source_positions().size() +
         code->inlining_positions().size() +
         code->protected_instructions_data().size() + code->deopt_data().size();
}

size_t NativeModuleSerializer::Measure() const {
  // From {WriteHeader}:
  size_t size = sizeof(WasmDetectedFeatures::StorageType) +
                sizeof(size_t) +  // total code size
                sizeof(bool) +    // all functions validated
                sizeof(typename CompileTimeImportFlags::StorageType) +
                sizeof(uint32_t) +  // length of constants_module.
                native_module_->compile_imports().constants_module().size() +
                import_statuses_.size() * sizeof(WellKnownImport);

  // From {WriteCode}, called repeatedly.
  for (WasmCode* code : code_table_) {
    size += MeasureCode(code);
  }

  // Tiering budget, wrote in {Write} directly.
  size += native_module_->module()->num_declared_functions * sizeof(uint32_t);

  return size;
}

void NativeModuleSerializer::WriteHeader(Writer* writer,
                                         size_t total_code_size) {
  // TODO(eholk): We need to properly preserve the flag whether the trap
  // handler was used or not when serializing.

  // Serialize the set of detected features; this contains
  // - all features detected during module decoding,
  // - all features detected during function body decoding (if lazy validation
  //   is disabled), and
  // - some features detected during compilation; some might still be missing
  //   because installing code and publishing detected features is not atomic.
  writer->Write(
      native_module_->compilation_state()->detected_features().ToIntegral());

  writer->Write(total_code_size);

  // We do not ship lazy validation, so in most cases all functions will be
  // validated. Thus only write out a single bit instead of serializing the
  // information per function.
  const bool fully_validated = !v8_flags.wasm_lazy_validation;
  writer->Write(fully_validated);
#ifdef DEBUG
  if (fully_validated) {
    const WasmModule* module = native_module_->module();
    for (auto& function : module->declared_functions()) {
      DCHECK(module->function_was_validated(function.func_index));
    }
  }
#endif

  const CompileTimeImports& compile_imports = native_module_->compile_imports();
  const std::string& constants_module = compile_imports.constants_module();
  writer->Write(compile_imports.flags().ToIntegral());
  writer->Write(static_cast<uint32_t>(constants_module.size()));
  writer->WriteVector(base::VectorOf(constants_module));
  writer->WriteVector(base::VectorOf(import_statuses_));
}

void NativeModuleSerializer::WriteCode(
    const WasmCode* code, Writer* writer,
    const NativeModule::CallIndirectTargetMap& function_index_map) {
  if (code == nullptr) {
    writer->Write(kLazyFunction);
    return;
  }

  DCHECK_EQ(WasmCode::kWasmFunction, code->kind());
  // Only serialize TurboFan code, as Liftoff code can contain breakpoints or
  // non-relocatable constants.
  if (code->tier() != ExecutionTier::kTurbofan) {
    // We check if the function has been executed already. If so, we serialize
    // it as {kEagerFunction} so that upon deserialization the function will
    // get eagerly compiled with Liftoff (if enabled). If the function has not
    // been executed yet, we serialize it as {kLazyFunction}, and the function
    // will not get compiled upon deserialization.
    NativeModule* native_module = code->native_module();
    uint32_t budget = native_module
                          ->tiering_budget_array()[declared_function_index(
                              native_module->module(), code->index())]
                          .load(std::memory_order_relaxed);
    writer->Write(budget == static_cast<uint32_t>(v8_flags.wasm_tiering_budget)
                      ? kLazyFunction
                      : kEagerFunction);
    return;
  }

  ++num_turbofan_functions_;
  writer->Write(kTurboFanFunction);
  // Write the size of the entire code section, followed by the code header.
  writer->Write(code->constant_pool_offset());
  writer->Write(code->safepoint_table_offset());
  writer->Write(code->handler_table_offset());
  writer->Write(code->code_comments_offset());
  writer->Write(code->unpadded_binary_size());
  writer->Write(code->stack_slots());
  writer->Write(code->ool_spills());
  writer->Write(code->raw_tagged_parameter_slots_for_serialization());
  writer->Write(code->instructions().length());
  writer->Write(code->reloc_info().length());
  writer->Write(code->source_positions().length());
  writer->Write(code->inlining_positions().length());
  writer->Write(code->deopt_data().length());
  writer->Write(code->protected_instructions_data().length());
  writer->Write(code->kind());
  writer->Write(code->tier());

  // Get a pointer to the destination buffer, to hold relocated code.
  uint8_t* serialized_code_start = writer->current_buffer().begin();
  uint8_t* code_start = serialized_code_start;
  size_t code_size = code->instructions().size();
  writer->Skip(code_size);
  // Write the reloc info, source positions, inlining positions and protected
  // code.
  writer->WriteVector(code->reloc_info());
  writer->WriteVector(code->source_positions());
  writer->WriteVector(code->inlining_positions());
  writer->WriteVector(code->deopt_data());
  writer->WriteVector(code->protected_instructions_data());
#if V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_PPC64 || \
    V8_TARGET_ARCH_S390X || V8_TARGET_ARCH_RISCV32 || V8_TARGET_ARCH_RISCV64
  // On platforms that don't support misaligned word stores, copy to an aligned
  // buffer if necessary so we can relocate the serialized code.
  std::unique_ptr<uint8_t[]> aligned_buffer;
  if (!IsAligned(reinterpret_cast<Address>(serialized_code_start),
                 kSystemPointerSize)) {
    // 'uint8_t' does not guarantee an alignment but seems to work well enough
    // in practice.
    aligned_buffer.reset(new uint8_t[code_size]);
    code_start = aligned_buffer.get();
  }
#endif
  memcpy(code_start, code->instructions().begin(), code_size);
  // Relocate the code.
  constexpr int kMask =
      RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
      RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
      RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID) |
      RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET) |
      RelocInfo::ModeMask(RelocInfo::EXTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);
  RelocIterator orig_iter(code->instructions(), code->reloc_info(),
                          code->constant_pool(), kMask);

  WritableJitAllocation jit_allocation =
      WritableJitAllocation::ForNonExecutableMemory(
          reinterpret_cast<Address>(code_start), code->instructions().size(),
          ThreadIsolation::JitAllocationType::kWasmCode);
  for (WritableRelocIterator iter(
           jit_allocation, {code_start, code->instructions().size()},
           code->reloc_info(),
           reinterpret_cast<Address>(code_start) + code->constant_pool_offset(),
           kMask);
       !iter.done(); iter.next(), orig_iter.next()) {
    RelocInfo::Mode mode = orig_iter.rinfo()->rmode();
    switch (mode) {
      case RelocInfo::WASM_CALL: {
        Address orig_target = orig_iter.rinfo()->wasm_call_address();
        uint32_t tag =
            native_module_->GetFunctionIndexFromJumpTableSlot(orig_target);
        SetWasmCalleeTag(iter.rinfo(), tag);
      } break;
      case RelocInfo::WASM_STUB_CALL: {
        Address target = orig_iter.rinfo()->wasm_stub_call_address();
        uint32_t tag = static_cast<uint32_t>(
            native_module_->GetBuiltinInJumptableSlot(target));
        SetWasmCalleeTag(iter.rinfo(), tag);
      } break;
      case RelocInfo::WASM_CANONICAL_SIG_ID: {
        uint32_t canonical_sig_id = orig_iter.rinfo()->wasm_canonical_sig_id();
        uint32_t module_local_sig_id =
            CanonicalSigIdToModuleLocalTypeId(canonical_sig_id);
        iter.rinfo()->set_wasm_canonical_sig_id(module_local_sig_id);
      } break;
      case RelocInfo::WASM_INDIRECT_CALL_TARGET: {
        WasmCodePointer target = orig_iter.rinfo()->wasm_indirect_call_target();
        uint32_t function_index = function_index_map.at(target);
        iter.rinfo()->set_wasm_indirect_call_target(function_index,
                                                    SKIP_ICACHE_FLUSH);
      } break;
      case RelocInfo::EXTERNAL_REFERENCE: {
        Address orig_target = orig_iter.rinfo()->target_external_reference();
        uint32_t ext_ref_tag =
            ExternalReferenceList::Get().tag_from_address(orig_target);
        SetWasmCalleeTag(iter.rinfo(), ext_ref_tag);
      } break;
      case RelocInfo::INTERNAL_REFERENCE:
      case RelocInfo::INTERNAL_REFERENCE_ENCODED: {
        Address orig_target = orig_iter.rinfo()->target_internal_reference();
        Address offset = orig_target - code->instruction_start();
        Assembler::deserialization_set_target_internal_reference_at(
            iter.rinfo()->pc(), offset, mode);
      } break;
      default:
        UNREACHABLE();
    }
  }
  // If we copied to an aligned buffer, copy code into serialized buffer.
  if (code_start != serialized_code_start) {
    memcpy(serialized_code_start, code_start, code_size);
  }
  total_written_code_ += code_size;
}

void NativeModuleSerializer::WriteTieringBudget(Writer* writer) {
  for (size_t i = 0; i < native_module_->module()->num_declared_functions;
       ++i) {
    writer->Write(native_module_->tiering_budget_array()[i].load(
        std::memory_order_relaxed));
  }
}

uint32_t NativeModuleSerializer::CanonicalSigIdToModuleLocalTypeId(
    uint32_t canonical_sig_id) {
  if (canonical_sig_ids_to_module_local_ids_.empty()) {
    const WasmModule* module = native_module_->module();
    DCHECK_GE(kMaxUInt32, module->isorecursive_canonical_type_ids.size());
    size_t num_types = module->types.size();
    DCHECK_EQ(num_types, module->isorecursive_canonical_type_ids.size());
    for (uint32_t local_id = 0; local_id < num_types; ++local_id) {
      // Only add function signatures.
      if (!module->has_signature(ModuleTypeIndex{local_id})) continue;
      CanonicalTypeIndex canonical_id =
          module->canonical_sig_id(ModuleTypeIndex{local_id});
      // Try to emplace, skip if an entry exists already. It does not matter
      // which local type ID we use if multiple types got canonicalized to the
      // same ID.
      canonical_sig_ids_to_module_local_ids_.emplace(
          std::make_pair(canonical_id.index, local_id));
    }
  }
  auto it = canonical_sig_ids_to_module_local_ids_.find(canonical_sig_id);
  DCHECK_NE(canonical_sig_ids_to_module_local_ids_.end(), it);
  return it->second;
}

bool NativeModuleSerializer::Write(Writer* writer) {
  DCHECK(!write_called_);
  write_called_ = true;

  size_t total_code_size = 0;
  for (WasmCode* code : code_table_) {
    if (code && code->tier() == ExecutionTier::kTurbofan) {
      DCHECK(IsAligned(code->instructions().size(), kCodeAlignment));
      total_code_size += code->instructions().size();
    }
  }
  WriteHeader(writer, total_code_size);

  NativeModule::CallIndirectTargetMap function_index_map =
      native_module_->CreateIndirectCallTargetToFunctionIndexMap();
  for (WasmCode* code : code_table_) {
    WriteCode(code, writer, function_index_map);
  }
  // No TurboFan-compiled functions in jitless mode.
  if (!v8_flags.wasm_jitless) {

### 提示词
```
这是目录为v8/src/wasm/wasm-serialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-serialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-serialization.h"

#include "src/codegen/assembler-arch.h"
#include "src/codegen/assembler-inl.h"
#include "src/debug/debug.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot-data.h"
#include "src/utils/ostreams.h"
#include "src/utils/version.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/module-compiler.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-result.h"
#include "src/wasm/well-known-imports.h"

namespace v8::internal::wasm {

namespace {
constexpr uint8_t kLazyFunction = 2;
constexpr uint8_t kEagerFunction = 3;
constexpr uint8_t kTurboFanFunction = 4;

// TODO(bbudge) Try to unify the various implementations of readers and writers
// in Wasm, e.g. StreamProcessor and ZoneBuffer, with these.
class Writer {
 public:
  explicit Writer(base::Vector<uint8_t> buffer)
      : start_(buffer.begin()), end_(buffer.end()), pos_(buffer.begin()) {}

  size_t bytes_written() const { return pos_ - start_; }
  uint8_t* current_location() const { return pos_; }
  size_t current_size() const { return end_ - pos_; }
  base::Vector<uint8_t> current_buffer() const {
    return {current_location(), current_size()};
  }

  template <typename T>
  void Write(const T& value) {
    DCHECK_GE(current_size(), sizeof(T));
    WriteUnalignedValue(reinterpret_cast<Address>(current_location()), value);
    pos_ += sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "wrote: " << static_cast<size_t>(value)
                     << " sized: " << sizeof(T) << std::endl;
    }
  }

  template <typename T>
  void WriteVector(const base::Vector<T> v) {
    base::Vector<const uint8_t> bytes = base::Vector<const uint8_t>::cast(v);
    DCHECK_GE(current_size(), bytes.size());
    if (!bytes.empty()) {
      memcpy(current_location(), bytes.begin(), bytes.size());
      pos_ += bytes.size();
    }
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "wrote vector of " << v.size()
                     << " elements (total size " << bytes.size() << " bytes)"
                     << std::endl;
    }
  }

  void Skip(size_t size) { pos_ += size; }

 private:
  uint8_t* const start_;
  uint8_t* const end_;
  uint8_t* pos_;
};

class Reader {
 public:
  explicit Reader(base::Vector<const uint8_t> buffer)
      : start_(buffer.begin()), end_(buffer.end()), pos_(buffer.begin()) {}

  size_t bytes_read() const { return pos_ - start_; }
  const uint8_t* current_location() const { return pos_; }
  size_t current_size() const { return end_ - pos_; }
  base::Vector<const uint8_t> current_buffer() const {
    return {current_location(), current_size()};
  }

  template <typename T>
  T Read() {
    DCHECK_GE(current_size(), sizeof(T));
    T value =
        ReadUnalignedValue<T>(reinterpret_cast<Address>(current_location()));
    pos_ += sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "read: " << static_cast<size_t>(value)
                     << " sized: " << sizeof(T) << std::endl;
    }
    return value;
  }

  template <typename T>
  base::Vector<const T> ReadVector(size_t size) {
    DCHECK_GE(current_size(), size);
    base::Vector<const uint8_t> bytes{pos_, size * sizeof(T)};
    pos_ += size * sizeof(T);
    if (v8_flags.trace_wasm_serialization) {
      StdoutStream{} << "read vector of " << size << " elements of size "
                     << sizeof(T) << " (total size " << size * sizeof(T) << ")"
                     << std::endl;
    }
    return base::Vector<const T>::cast(bytes);
  }

  void Skip(size_t size) { pos_ += size; }

 private:
  const uint8_t* const start_;
  const uint8_t* const end_;
  const uint8_t* pos_;
};

void WriteHeader(Writer* writer, WasmEnabledFeatures enabled_features) {
  DCHECK_EQ(0, writer->bytes_written());
  writer->Write(SerializedData::kMagicNumber);
  writer->Write(Version::Hash());
  writer->Write(static_cast<uint32_t>(CpuFeatures::SupportedFeatures()));
  writer->Write(FlagList::Hash());
  writer->Write(enabled_features.ToIntegral());
  DCHECK_EQ(WasmSerializer::kHeaderSize, writer->bytes_written());
}

// On Intel, call sites are encoded as a displacement. For linking and for
// serialization/deserialization, we want to store/retrieve a tag (the function
// index). On Intel, that means accessing the raw displacement.
// On ARM64, call sites are encoded as either a literal load or a direct branch.
// Other platforms simply require accessing the target address.
void SetWasmCalleeTag(WritableRelocInfo* rinfo, uint32_t tag) {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  DCHECK(rinfo->HasTargetAddressAddress());
  DCHECK(!RelocInfo::IsCompressedEmbeddedObject(rinfo->rmode()));
  WriteUnalignedValue(rinfo->target_address_address(), tag);
#elif V8_TARGET_ARCH_ARM64
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsLdrLiteralX()) {
    WriteUnalignedValue(rinfo->constant_pool_entry_address(),
                        static_cast<Address>(tag));
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    instr->SetBranchImmTarget<UncondBranchType>(
        reinterpret_cast<Instruction*>(rinfo->pc() + tag * kInstrSize));
  }
#elif V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsAUIPC()) {
    Instr auipc = instr->InstructionBits();
    Instr jalr = reinterpret_cast<Instruction*>(rinfo->pc() + 1 * kInstrSize)
                     ->InstructionBits();
    DCHECK(is_int32(tag + 0x800));
    Assembler::PatchBranchlongOffset(rinfo->pc(), auipc, jalr, (int32_t)tag,
                                     nullptr);
  } else {
    Assembler::set_target_address_at(rinfo->pc(), rinfo->constant_pool(),
                                     static_cast<Address>(tag), nullptr,
                                     SKIP_ICACHE_FLUSH);
  }
#else
  Address addr = static_cast<Address>(tag);
  if (rinfo->rmode() == RelocInfo::EXTERNAL_REFERENCE) {
    rinfo->set_target_external_reference(addr, SKIP_ICACHE_FLUSH);
  } else if (rinfo->rmode() == RelocInfo::WASM_STUB_CALL) {
    rinfo->set_wasm_stub_call_address(addr);
  } else {
    rinfo->set_target_address(addr, SKIP_ICACHE_FLUSH);
  }
#endif
}

uint32_t GetWasmCalleeTag(RelocInfo* rinfo) {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  DCHECK(!RelocInfo::IsCompressedEmbeddedObject(rinfo->rmode()));
  return ReadUnalignedValue<uint32_t>(rinfo->target_address_address());
#elif V8_TARGET_ARCH_ARM64
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsLdrLiteralX()) {
    return ReadUnalignedValue<uint32_t>(rinfo->constant_pool_entry_address());
  } else {
    DCHECK(instr->IsBranchAndLink() || instr->IsUnconditionalBranch());
    return static_cast<uint32_t>(instr->ImmPCOffset() / kInstrSize);
  }
#elif V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
  Instruction* instr = reinterpret_cast<Instruction*>(rinfo->pc());
  if (instr->IsAUIPC()) {
    Instr auipc = instr->InstructionBits();
    Instr jalr = reinterpret_cast<Instruction*>(rinfo->pc() + 1 * kInstrSize)
                     ->InstructionBits();
    return Assembler::BrachlongOffset(auipc, jalr);
  } else {
    return static_cast<uint32_t>(rinfo->target_address());
  }
#else
  Address addr;
  if (rinfo->rmode() == RelocInfo::EXTERNAL_REFERENCE) {
    addr = rinfo->target_external_reference();
  } else if (rinfo->rmode() == RelocInfo::WASM_STUB_CALL) {
    addr = rinfo->wasm_stub_call_address();
  } else {
    addr = rinfo->target_address();
  }
  return static_cast<uint32_t>(addr);
#endif
}

constexpr size_t kCodeHeaderSize = sizeof(uint8_t) +  // code kind
                                   sizeof(int) +      // offset of constant pool
                                   sizeof(int) +  // offset of safepoint table
                                   sizeof(int) +  // offset of handler table
                                   sizeof(int) +  // offset of code comments
                                   sizeof(int) +  // unpadded binary size
                                   sizeof(int) +  // stack slots
                                   sizeof(int) +  // ool slots
                                   sizeof(int) +  // tagged parameter slots
                                   sizeof(int) +  // code size
                                   sizeof(int) +  // reloc size
                                   sizeof(int) +  // source positions size
                                   sizeof(int) +  // inlining positions size
                                   sizeof(int) +  // deopt data size
                                   sizeof(int) +  // protected instructions size
                                   sizeof(WasmCode::Kind) +  // code kind
                                   sizeof(ExecutionTier);    // tier

// A List of all isolate-independent external references. This is used to create
// a tag from the Address of an external reference and vice versa.
class ExternalReferenceList {
 public:
  ExternalReferenceList(const ExternalReferenceList&) = delete;
  ExternalReferenceList& operator=(const ExternalReferenceList&) = delete;

  uint32_t tag_from_address(Address ext_ref_address) const {
    auto tag_addr_less_than = [this](uint32_t tag, Address searched_addr) {
      return external_reference_by_tag_[tag] < searched_addr;
    };
    auto it = std::lower_bound(std::begin(tags_ordered_by_address_),
                               std::end(tags_ordered_by_address_),
                               ext_ref_address, tag_addr_less_than);
    DCHECK_NE(std::end(tags_ordered_by_address_), it);
    uint32_t tag = *it;
    DCHECK_EQ(address_from_tag(tag), ext_ref_address);
    return tag;
  }

  Address address_from_tag(uint32_t tag) const {
    DCHECK_GT(kNumExternalReferences, tag);
    return external_reference_by_tag_[tag];
  }

  static const ExternalReferenceList& Get() {
    static ExternalReferenceList list;  // Lazily initialized.
    return list;
  }

 private:
  // Private constructor. There will only be a single instance of this object.
  ExternalReferenceList() {
    for (uint32_t i = 0; i < kNumExternalReferences; ++i) {
      tags_ordered_by_address_[i] = i;
    }
    auto addr_by_tag_less_than = [this](uint32_t a, uint32_t b) {
      return external_reference_by_tag_[a] < external_reference_by_tag_[b];
    };
    std::sort(std::begin(tags_ordered_by_address_),
              std::end(tags_ordered_by_address_), addr_by_tag_less_than);
  }

#define COUNT_EXTERNAL_REFERENCE(name, ...) +1
  static constexpr uint32_t kNumExternalReferencesList =
      EXTERNAL_REFERENCE_LIST(COUNT_EXTERNAL_REFERENCE);
  static constexpr uint32_t kNumExternalReferencesIntrinsics =
      FOR_EACH_INTRINSIC(COUNT_EXTERNAL_REFERENCE);
  static constexpr uint32_t kNumExternalReferences =
      kNumExternalReferencesList + kNumExternalReferencesIntrinsics;
#undef COUNT_EXTERNAL_REFERENCE

  Address external_reference_by_tag_[kNumExternalReferences] = {
#define EXT_REF_ADDR(name, desc) ExternalReference::name().address(),
      EXTERNAL_REFERENCE_LIST(EXT_REF_ADDR)
#undef EXT_REF_ADDR
#define RUNTIME_ADDR(name, ...) \
  ExternalReference::Create(Runtime::k##name).address(),
          FOR_EACH_INTRINSIC(RUNTIME_ADDR)
#undef RUNTIME_ADDR
  };
  uint32_t tags_ordered_by_address_[kNumExternalReferences];
};

static_assert(std::is_trivially_destructible<ExternalReferenceList>::value,
              "static destructors not allowed");

}  // namespace

class V8_EXPORT_PRIVATE NativeModuleSerializer {
 public:
  NativeModuleSerializer(const NativeModule*, base::Vector<WasmCode* const>,
                         base::Vector<WellKnownImport const>);
  NativeModuleSerializer(const NativeModuleSerializer&) = delete;
  NativeModuleSerializer& operator=(const NativeModuleSerializer&) = delete;

  size_t Measure() const;
  bool Write(Writer* writer);

 private:
  size_t MeasureCode(const WasmCode*) const;
  void WriteHeader(Writer*, size_t total_code_size);
  void WriteCode(const WasmCode*, Writer*,
                 const NativeModule::CallIndirectTargetMap&);
  void WriteTieringBudget(Writer* writer);

  uint32_t CanonicalSigIdToModuleLocalTypeId(uint32_t canonical_sig_id);

  const NativeModule* const native_module_;
  const base::Vector<WasmCode* const> code_table_;
  const base::Vector<WellKnownImport const> import_statuses_;
  // Map back canonical signature IDs to module-local IDs. Initialized lazily.
  std::unordered_map<uint32_t, uint32_t> canonical_sig_ids_to_module_local_ids_;
  bool write_called_ = false;
  size_t total_written_code_ = 0;
  int num_turbofan_functions_ = 0;
};

NativeModuleSerializer::NativeModuleSerializer(
    const NativeModule* module, base::Vector<WasmCode* const> code_table,
    base::Vector<WellKnownImport const> import_statuses)
    : native_module_(module),
      code_table_(code_table),
      import_statuses_(import_statuses) {
  DCHECK_NOT_NULL(native_module_);
  // TODO(mtrofin): persist the export wrappers. Ideally, we'd only persist
  // the unique ones, i.e. the cache.
}

size_t NativeModuleSerializer::MeasureCode(const WasmCode* code) const {
  if (code == nullptr) return sizeof(uint8_t);
  DCHECK_EQ(WasmCode::kWasmFunction, code->kind());
  if (code->tier() != ExecutionTier::kTurbofan) {
    return sizeof(uint8_t);
  }
  return kCodeHeaderSize + code->instructions().size() +
         code->reloc_info().size() + code->source_positions().size() +
         code->inlining_positions().size() +
         code->protected_instructions_data().size() + code->deopt_data().size();
}

size_t NativeModuleSerializer::Measure() const {
  // From {WriteHeader}:
  size_t size = sizeof(WasmDetectedFeatures::StorageType) +
                sizeof(size_t) +  // total code size
                sizeof(bool) +    // all functions validated
                sizeof(typename CompileTimeImportFlags::StorageType) +
                sizeof(uint32_t) +  // length of constants_module.
                native_module_->compile_imports().constants_module().size() +
                import_statuses_.size() * sizeof(WellKnownImport);

  // From {WriteCode}, called repeatedly.
  for (WasmCode* code : code_table_) {
    size += MeasureCode(code);
  }

  // Tiering budget, wrote in {Write} directly.
  size += native_module_->module()->num_declared_functions * sizeof(uint32_t);

  return size;
}

void NativeModuleSerializer::WriteHeader(Writer* writer,
                                         size_t total_code_size) {
  // TODO(eholk): We need to properly preserve the flag whether the trap
  // handler was used or not when serializing.

  // Serialize the set of detected features; this contains
  // - all features detected during module decoding,
  // - all features detected during function body decoding (if lazy validation
  //   is disabled), and
  // - some features detected during compilation; some might still be missing
  //   because installing code and publishing detected features is not atomic.
  writer->Write(
      native_module_->compilation_state()->detected_features().ToIntegral());

  writer->Write(total_code_size);

  // We do not ship lazy validation, so in most cases all functions will be
  // validated. Thus only write out a single bit instead of serializing the
  // information per function.
  const bool fully_validated = !v8_flags.wasm_lazy_validation;
  writer->Write(fully_validated);
#ifdef DEBUG
  if (fully_validated) {
    const WasmModule* module = native_module_->module();
    for (auto& function : module->declared_functions()) {
      DCHECK(module->function_was_validated(function.func_index));
    }
  }
#endif

  const CompileTimeImports& compile_imports = native_module_->compile_imports();
  const std::string& constants_module = compile_imports.constants_module();
  writer->Write(compile_imports.flags().ToIntegral());
  writer->Write(static_cast<uint32_t>(constants_module.size()));
  writer->WriteVector(base::VectorOf(constants_module));
  writer->WriteVector(base::VectorOf(import_statuses_));
}

void NativeModuleSerializer::WriteCode(
    const WasmCode* code, Writer* writer,
    const NativeModule::CallIndirectTargetMap& function_index_map) {
  if (code == nullptr) {
    writer->Write(kLazyFunction);
    return;
  }

  DCHECK_EQ(WasmCode::kWasmFunction, code->kind());
  // Only serialize TurboFan code, as Liftoff code can contain breakpoints or
  // non-relocatable constants.
  if (code->tier() != ExecutionTier::kTurbofan) {
    // We check if the function has been executed already. If so, we serialize
    // it as {kEagerFunction} so that upon deserialization the function will
    // get eagerly compiled with Liftoff (if enabled). If the function has not
    // been executed yet, we serialize it as {kLazyFunction}, and the function
    // will not get compiled upon deserialization.
    NativeModule* native_module = code->native_module();
    uint32_t budget = native_module
                          ->tiering_budget_array()[declared_function_index(
                              native_module->module(), code->index())]
                          .load(std::memory_order_relaxed);
    writer->Write(budget == static_cast<uint32_t>(v8_flags.wasm_tiering_budget)
                      ? kLazyFunction
                      : kEagerFunction);
    return;
  }

  ++num_turbofan_functions_;
  writer->Write(kTurboFanFunction);
  // Write the size of the entire code section, followed by the code header.
  writer->Write(code->constant_pool_offset());
  writer->Write(code->safepoint_table_offset());
  writer->Write(code->handler_table_offset());
  writer->Write(code->code_comments_offset());
  writer->Write(code->unpadded_binary_size());
  writer->Write(code->stack_slots());
  writer->Write(code->ool_spills());
  writer->Write(code->raw_tagged_parameter_slots_for_serialization());
  writer->Write(code->instructions().length());
  writer->Write(code->reloc_info().length());
  writer->Write(code->source_positions().length());
  writer->Write(code->inlining_positions().length());
  writer->Write(code->deopt_data().length());
  writer->Write(code->protected_instructions_data().length());
  writer->Write(code->kind());
  writer->Write(code->tier());

  // Get a pointer to the destination buffer, to hold relocated code.
  uint8_t* serialized_code_start = writer->current_buffer().begin();
  uint8_t* code_start = serialized_code_start;
  size_t code_size = code->instructions().size();
  writer->Skip(code_size);
  // Write the reloc info, source positions, inlining positions and protected
  // code.
  writer->WriteVector(code->reloc_info());
  writer->WriteVector(code->source_positions());
  writer->WriteVector(code->inlining_positions());
  writer->WriteVector(code->deopt_data());
  writer->WriteVector(code->protected_instructions_data());
#if V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_PPC64 || \
    V8_TARGET_ARCH_S390X || V8_TARGET_ARCH_RISCV32 || V8_TARGET_ARCH_RISCV64
  // On platforms that don't support misaligned word stores, copy to an aligned
  // buffer if necessary so we can relocate the serialized code.
  std::unique_ptr<uint8_t[]> aligned_buffer;
  if (!IsAligned(reinterpret_cast<Address>(serialized_code_start),
                 kSystemPointerSize)) {
    // 'uint8_t' does not guarantee an alignment but seems to work well enough
    // in practice.
    aligned_buffer.reset(new uint8_t[code_size]);
    code_start = aligned_buffer.get();
  }
#endif
  memcpy(code_start, code->instructions().begin(), code_size);
  // Relocate the code.
  constexpr int kMask =
      RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
      RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
      RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID) |
      RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET) |
      RelocInfo::ModeMask(RelocInfo::EXTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
      RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);
  RelocIterator orig_iter(code->instructions(), code->reloc_info(),
                          code->constant_pool(), kMask);

  WritableJitAllocation jit_allocation =
      WritableJitAllocation::ForNonExecutableMemory(
          reinterpret_cast<Address>(code_start), code->instructions().size(),
          ThreadIsolation::JitAllocationType::kWasmCode);
  for (WritableRelocIterator iter(
           jit_allocation, {code_start, code->instructions().size()},
           code->reloc_info(),
           reinterpret_cast<Address>(code_start) + code->constant_pool_offset(),
           kMask);
       !iter.done(); iter.next(), orig_iter.next()) {
    RelocInfo::Mode mode = orig_iter.rinfo()->rmode();
    switch (mode) {
      case RelocInfo::WASM_CALL: {
        Address orig_target = orig_iter.rinfo()->wasm_call_address();
        uint32_t tag =
            native_module_->GetFunctionIndexFromJumpTableSlot(orig_target);
        SetWasmCalleeTag(iter.rinfo(), tag);
      } break;
      case RelocInfo::WASM_STUB_CALL: {
        Address target = orig_iter.rinfo()->wasm_stub_call_address();
        uint32_t tag = static_cast<uint32_t>(
            native_module_->GetBuiltinInJumptableSlot(target));
        SetWasmCalleeTag(iter.rinfo(), tag);
      } break;
      case RelocInfo::WASM_CANONICAL_SIG_ID: {
        uint32_t canonical_sig_id = orig_iter.rinfo()->wasm_canonical_sig_id();
        uint32_t module_local_sig_id =
            CanonicalSigIdToModuleLocalTypeId(canonical_sig_id);
        iter.rinfo()->set_wasm_canonical_sig_id(module_local_sig_id);
      } break;
      case RelocInfo::WASM_INDIRECT_CALL_TARGET: {
        WasmCodePointer target = orig_iter.rinfo()->wasm_indirect_call_target();
        uint32_t function_index = function_index_map.at(target);
        iter.rinfo()->set_wasm_indirect_call_target(function_index,
                                                    SKIP_ICACHE_FLUSH);
      } break;
      case RelocInfo::EXTERNAL_REFERENCE: {
        Address orig_target = orig_iter.rinfo()->target_external_reference();
        uint32_t ext_ref_tag =
            ExternalReferenceList::Get().tag_from_address(orig_target);
        SetWasmCalleeTag(iter.rinfo(), ext_ref_tag);
      } break;
      case RelocInfo::INTERNAL_REFERENCE:
      case RelocInfo::INTERNAL_REFERENCE_ENCODED: {
        Address orig_target = orig_iter.rinfo()->target_internal_reference();
        Address offset = orig_target - code->instruction_start();
        Assembler::deserialization_set_target_internal_reference_at(
            iter.rinfo()->pc(), offset, mode);
      } break;
      default:
        UNREACHABLE();
    }
  }
  // If we copied to an aligned buffer, copy code into serialized buffer.
  if (code_start != serialized_code_start) {
    memcpy(serialized_code_start, code_start, code_size);
  }
  total_written_code_ += code_size;
}

void NativeModuleSerializer::WriteTieringBudget(Writer* writer) {
  for (size_t i = 0; i < native_module_->module()->num_declared_functions;
       ++i) {
    writer->Write(native_module_->tiering_budget_array()[i].load(
        std::memory_order_relaxed));
  }
}

uint32_t NativeModuleSerializer::CanonicalSigIdToModuleLocalTypeId(
    uint32_t canonical_sig_id) {
  if (canonical_sig_ids_to_module_local_ids_.empty()) {
    const WasmModule* module = native_module_->module();
    DCHECK_GE(kMaxUInt32, module->isorecursive_canonical_type_ids.size());
    size_t num_types = module->types.size();
    DCHECK_EQ(num_types, module->isorecursive_canonical_type_ids.size());
    for (uint32_t local_id = 0; local_id < num_types; ++local_id) {
      // Only add function signatures.
      if (!module->has_signature(ModuleTypeIndex{local_id})) continue;
      CanonicalTypeIndex canonical_id =
          module->canonical_sig_id(ModuleTypeIndex{local_id});
      // Try to emplace, skip if an entry exists already. It does not matter
      // which local type ID we use if multiple types got canonicalized to the
      // same ID.
      canonical_sig_ids_to_module_local_ids_.emplace(
          std::make_pair(canonical_id.index, local_id));
    }
  }
  auto it = canonical_sig_ids_to_module_local_ids_.find(canonical_sig_id);
  DCHECK_NE(canonical_sig_ids_to_module_local_ids_.end(), it);
  return it->second;
}

bool NativeModuleSerializer::Write(Writer* writer) {
  DCHECK(!write_called_);
  write_called_ = true;

  size_t total_code_size = 0;
  for (WasmCode* code : code_table_) {
    if (code && code->tier() == ExecutionTier::kTurbofan) {
      DCHECK(IsAligned(code->instructions().size(), kCodeAlignment));
      total_code_size += code->instructions().size();
    }
  }
  WriteHeader(writer, total_code_size);

  NativeModule::CallIndirectTargetMap function_index_map =
      native_module_->CreateIndirectCallTargetToFunctionIndexMap();
  for (WasmCode* code : code_table_) {
    WriteCode(code, writer, function_index_map);
  }
  // No TurboFan-compiled functions in jitless mode.
  if (!v8_flags.wasm_jitless) {
    // If not a single function was written, serialization was not successful.
    if (num_turbofan_functions_ == 0) return false;
  }

  // Make sure that the serialized total code size was correct.
  CHECK_EQ(total_written_code_, total_code_size);

  WriteTieringBudget(writer);
  return true;
}

WasmSerializer::WasmSerializer(NativeModule* native_module)
    : native_module_(native_module) {
  std::tie(code_table_, import_statuses_) = native_module->SnapshotCodeTable();
}

size_t WasmSerializer::GetSerializedNativeModuleSize() const {
  NativeModuleSerializer serializer(native_module_, base::VectorOf(code_table_),
                                    base::VectorOf(import_statuses_));
  return kHeaderSize + serializer.Measure();
}

bool WasmSerializer::SerializeNativeModule(base::Vector<uint8_t> buffer) const {
  NativeModuleSerializer serializer(native_module_, base::VectorOf(code_table_),
                                    base::VectorOf(import_statuses_));
  size_t measured_size = kHeaderSize + serializer.Measure();
  if (buffer.size() < measured_size) return false;

  Writer writer(buffer);
  WriteHeader(&writer, native_module_->enabled_features());

  if (!serializer.Write(&writer)) return false;
  DCHECK_EQ(measured_size, writer.bytes_written());
  return true;
}

struct DeserializationUnit {
  base::Vector<const uint8_t> src_code_buffer;
  std::unique_ptr<WasmCode> code;
  NativeModule::JumpTablesRef jump_tables;
};

class DeserializationQueue {
 public:
  void Add(std::vector<DeserializationUnit> batch) {
    DCHECK(!batch.empty());
    base::MutexGuard guard(&mutex_);
    queue_.emplace(std::move(batch));
  }

  std::vector<DeserializationUnit> Pop() {
    base::MutexGuard guard(&mutex_);
    if (queue_.empty()) return {};
    auto batch = std::move(queue_.front());
    queue_.pop();
    return batch;
  }

  std::vector<DeserializationUnit> PopAll() {
    base::MutexGuard guard(&mutex_);
    if (queue_.empty()) return {};
    auto units = std::move(queue_.front());
    queue_.pop();
    while (!queue_.empty()) {
      units.insert(units.end(), std::make_move_iterator(queue_.front().begin()),
                   std::make_move_iterator(queue_.front().end()));
      queue_.pop();
    }
    return units;
  }

  size_t NumBatches() const {
    base::MutexGuard guard(&mutex_);
    return queue_.size();
  }

 private:
  mutable base::Mutex mutex_;
  std::queue<std::vector<DeserializationUnit>> queue_;
};

class V8_EXPORT_PRIVATE NativeModuleDeserializer {
 public:
  explicit NativeModuleDeserializer(NativeModule*);
  NativeModuleDeserializer(const NativeModuleDeserializer&) = delete;
  NativeModuleDeserializer& operator=(const NativeModuleDeserializer&) = delete;

  bool Read(Reader* reader);

  base::Vector<const int> lazy_functions() {
    return base::VectorOf(lazy_functions_);
  }

  base::Vector<const int> eager_functions() {
    return base::VectorOf(eager_functions_);
  }

 private:
  friend class DeserializeCodeTask;

  void ReadHeader(Reader* reader);
  DeserializationUnit ReadCode(int fn_index, Reader* reader);
  void ReadTieringBudget(Reader* reader);
  void CopyAndRelocate(const DeserializationUnit& unit);
  void Publish(std::vector<DeserializationUnit> batch);

  NativeModule* const native_module_;
#ifdef DEBUG
  bool read_called_ = false;
#endif

  // Updated in {ReadCode}.
  size_t remaining_code_size_ = 0;
  bool all_functions_validated_ = false;
  CompileTimeImports compile_imports_;
  base::Vector<uint8_t> current_code_space_;
  NativeModule::JumpTablesRef current_jump_tables_;
  std::vector<int> lazy_functions_;
  std::vector<int> eager_functions_;
};

class DeserializeCodeTask : public JobTask {
 public:
  DeserializeCodeTask(NativeModuleDeserializer* deserializer,
                      DeserializationQueue* reloc_queue)
      : deserializer_(deserializer), reloc_queue_(reloc_queue) {}

  void Run(JobDelegate* delegate) override {
    bool finished = false;
    while (!finished) {
      // Repeatedly publish everything that was copied already.
      finished = TryPublishing(delegate);

      auto batch = reloc_queue_->Pop();
      if (batch.empty()) break;
      for (const auto& unit : batch) {
        deserializer_->CopyAndRelocate(unit);
      }
      publish_queue_.Add(std::move(batch));
      delegate->NotifyConcurrencyIncrease();
    }
  }

  size_t GetMaxConcurrency(size_t /* worker_count */) const override {
    // Number of copy&reloc batches, plus 1 if there is also something to
    // publish.
    bool publish = publishing_.load(std::memory_order_relaxed) == false &&
                   publish_queue_.NumBatches() > 0;
    return reloc_queue_->NumBatches() + (publish ? 1 : 0);
  }

 private:
  bool TryPublishing(JobDelegate* delegate) {
    // Publishing is sequential, so only start publishing if no one else is.
    if (publishing_.exchange(true, std::memory_order_relaxed)) return false;

    WasmCodeRefScope code_scope;
    while (true) {
      bool yield = false;
      while (!yield) {
        auto to_publish = publish_queue_.PopAll();
        if (to_publish.empty()) break;
        deserializer_->Publish(std::move(to_publish));
        yield = delegate->ShouldYield();
      }
      publishing_.store(false, std::memory_order_relaxed);
      if (yield) return true;
      // After finishing publishing, check again if new work arrived in the mean
      // time. If so, continue publishing.
      if (publish_queue_.NumBatches() == 0) break;
      if (publishing_.exchange(true, std::memory_order_relaxed)) break;
      // We successfully reset {publishing_} from {false} to {true}.
    }
    return false;
  }

  NativeModuleDeserializer* const deserializer_;
  DeserializationQueue* const reloc_queue_;
  DeserializationQueue publish_queue_;
  std::atomic<bool> publishing_{false};
};

NativeModuleDeserializer::NativeModuleDeserializer(NativeModule* native_module)
    : native_module_(native_module) {}

bool NativeModuleDeserializer::Read(Reader* reader) {
  DCHECK(!read_called_);
#ifdef DEBUG
  read_called_ = true;
#endif

  ReadHeader(reader);
  if (compile_imports_.compare(native_module_->compile_imports()) != 0) {
    return false;
  }

  uint32_t total_fns = native_module_->num_functions();
  uint32_t first_wasm_fn = native_module_->num_imported_functions();

  if (all_functions_validated_) {
    native_module_->module()->set_all_functions_validated();
  }

  WasmCodeRefScope wasm_code_ref_scope;

  DeserializationQueue reloc_queue;

  // Create a new job without any workers; those are spawned on
  // {NotifyConcurrencyIncrease}.
  std::unique_ptr<JobHandle> job_handle = V8::GetCurrentPlatform()->CreateJob(
      TaskPriority::kUserVisible,
      std::make_unique<DeserializeCodeTask>(this, &reloc_queue));

  // Choose a batch size such that we do not create too small batches (>=100k
  // code bytes), but also not too many (<=100 batches).
  constexpr size_t kMinBatchSizeInBytes = 100000;
  size_t batch_limit =
      std::max(kMinBatchSizeInBytes, remaining_code_size_ / 100);

  std::vector<DeserializationUnit> batch;
  size_t batch_size = 0;
  for (uint32_t i = first_wasm_fn; i < total_fns; ++i) {
    DeserializationUnit unit = ReadCode(i, reader);
    if (!unit.code) continue;
    batch_size += unit.code->instructions().size();
    batch.emplace_back(std::move(unit));
    if (batch_size >= batch
```