Response: Let's break down the thought process for analyzing this C++ file.

1. **Identify the Core Goal:** The filename `wasm-serialization.cc` immediately suggests the primary function: handling the serialization and deserialization of WebAssembly modules. The presence of `Writer` and `Reader` classes reinforces this.

2. **Scan for Key Data Structures:** Look for classes and structs that represent the data being serialized. `NativeModule`, `WasmCode`, `WasmModuleObject` are prominent. These give clues about the scope of the serialization.

3. **Trace the Serialization Process:** Focus on the `WasmSerializer` class and its `SerializeNativeModule` method. Observe the `NativeModuleSerializer` being used. Analyze the `Measure()` and `Write()` methods within `NativeModuleSerializer`. Notice how it iterates through `code_table_` and calls `WriteCode()`. This starts to reveal the order and types of data being written.

4. **Trace the Deserialization Process:**  Focus on the `DeserializeNativeModule` function. Observe the `NativeModuleDeserializer` being used. Analyze the `Read()` method and its calls to `ReadHeader()` and `ReadCode()`. Note the use of a `DeserializationQueue` and a `DeserializeCodeTask`, hinting at asynchronous or multi-threaded deserialization.

5. **Analyze the `Writer` and `Reader`:** These are fundamental for serialization. Understand their basic operations (`Write`, `Read`, `Skip`). Note the template nature allowing them to handle various data types. The `trace_wasm_serialization` flag is a helpful debugging indicator.

6. **Examine the `WriteCode` and `ReadCode` methods in Detail:** These are the workhorses for serializing and deserializing individual function code. Pay attention to *what* data is being written/read (code header, instructions, reloc info, etc.) and *how* it's being handled (relocation, tagging of call sites). The different code kinds (`kLazyFunction`, `kEagerFunction`, `kTurboFanFunction`) are important.

7. **Focus on Relocation:**  The code involving `RelocInfo`, `WritableRelocInfo`, and the platform-specific `#if V8_TARGET_ARCH_*` blocks is crucial. Understand that serialization needs to adjust pointers and addresses so that the code can be loaded at a different memory location. The tagging of WASM calls and external references is a key aspect of this.

8. **Connect to JavaScript:** Think about how WebAssembly is used in JavaScript. The `WebAssembly.instantiate` and `WebAssembly.compile` methods are the primary entry points. Serialization allows saving a compiled module to disk or sending it over a network, enabling faster loading later. The example should demonstrate this basic scenario.

9. **Summarize the Functionality:**  Based on the above analysis, formulate a high-level description of the file's purpose. Emphasize the serialization and deserialization of WASM modules, including code, metadata, and the handling of relocations.

10. **Explain the Relationship to JavaScript:** Clearly articulate how this C++ code supports JavaScript functionality. Focus on the performance benefits of caching and the developer experience of faster loading.

11. **Construct the JavaScript Example:** Create a simple, illustrative JavaScript example that demonstrates the serialization and deserialization process using the browser's WebAssembly API. The example should show fetching WASM bytecode, compiling/instantiating, serializing, and then deserializing and instantiating again.

12. **Refine and Organize:**  Review the entire explanation for clarity, accuracy, and completeness. Ensure logical flow and use clear language. Break down complex concepts into smaller, understandable parts. Use formatting (like bullet points or code blocks) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file just handles the raw bytecode. **Correction:**  Realize it also handles metadata, relocation information, and different compilation tiers.
* **Confusion with different writers/readers:** Notice `Writer`/`Reader` and also things like `StreamProcessor`. **Clarification:** Focus on the `Writer`/`Reader` in this specific file and acknowledge that other serialization mechanisms exist in the broader V8 codebase.
* **Overlooking architecture-specific code:** Initially might gloss over the `#if V8_TARGET_ARCH_*`. **Correction:** Recognize that relocation is platform-dependent and these blocks handle those variations.
* **Not making the JavaScript connection clear enough:**  The initial explanation might be too technical. **Refinement:**  Explicitly link the C++ code to the `WebAssembly` API and the benefits it provides to JavaScript developers.
* **Simplifying the JavaScript example:** Start with a very basic example and gradually add complexity if needed. Focus on demonstrating the core concept of serialization and deserialization.

By following these steps, iteratively analyzing the code, and refining the understanding, you can arrive at a comprehensive and accurate explanation of the C++ file's functionality and its relationship to JavaScript.
这个 C++ 源代码文件 `v8/src/wasm/wasm-serialization.cc` 的主要功能是 **实现 WebAssembly 模块的序列化和反序列化**。

更具体地说，它负责将编译后的 WebAssembly 模块（`NativeModule`），包括其代码、元数据和优化信息，转换为可以存储或传输的字节流，并在需要时将其还原回原始状态。

以下是该文件的一些关键功能点：

* **定义了 `Writer` 和 `Reader` 类**: 这两个辅助类用于处理字节流的写入和读取操作，提供了方便的方法来写入和读取不同类型的数据。
* **实现了 `NativeModuleSerializer` 类**: 该类负责将 `NativeModule` 对象序列化为字节流。这包括：
    * 写入模块的元数据，例如编译时特性、常量等。
    * 遍历模块中的每个 WebAssembly 函数 (`WasmCode`)，并决定是否需要序列化其编译后的代码。
    * 如果需要序列化代码，则写入代码头信息（例如，代码大小、重定位信息偏移量等）和实际的机器码指令。
    * 处理代码中的重定位信息，将内部引用和外部引用转换为可序列化的格式。
    * 写入分层编译的预算信息。
* **实现了 `NativeModuleDeserializer` 类**: 该类负责从字节流反序列化 `NativeModule` 对象。这包括：
    * 读取模块的元数据。
    * 逐个读取序列化的 WebAssembly 函数代码，并将其加载到内存中。
    * 根据重定位信息，修复加载后的代码中的地址和引用。
    * 处理分层编译的预算信息。
* **定义了 `WasmSerializer` 类**:  作为序列化的入口点，它负责创建 `NativeModuleSerializer` 并执行序列化过程。
* **定义了 `DeserializeNativeModule` 函数**:  作为反序列化的入口点，它负责读取字节流头部，创建 `NativeModuleDeserializer` 并执行反序列化过程。
* **处理不同编译层级的函数**:  代码区分了 `kLazyFunction`、`kEagerFunction` 和 `kTurboFanFunction`，允许只序列化特定编译层级的函数代码，或者根据函数的执行情况选择是否序列化。这对于优化内存使用和启动速度非常重要。
* **处理重定位信息**:  这是序列化和反序列化的关键部分。由于代码在内存中的地址在不同的执行环境中可能不同，因此需要记录代码中需要调整的地址信息（重定位信息），并在反序列化时根据实际加载地址进行调整。
* **支持外部引用和内部引用**:  代码能够序列化和反序列化对外部函数和数据的引用，以及模块内部的函数和数据的引用。
* **版本控制**:  通过写入和检查头部信息中的 magic number 和 V8 版本哈希，确保序列化的数据与当前 V8 版本兼容。

**与 JavaScript 的功能关系以及 JavaScript 示例**

这个 C++ 文件直接支持了 JavaScript 中 `WebAssembly` API 的以下功能：

* **`WebAssembly.Module` 的缓存**:  V8 引擎可以将编译后的 `WebAssembly.Module` 对象序列化到缓存中（例如，HTTP 缓存或 IndexedDB），以便在下次加载相同的模块时可以快速反序列化，而无需重新编译。这显著提高了 WebAssembly 模块的加载速度，尤其是在重复访问的情况下。
* **`WebAssembly.compileStreaming` 和 `WebAssembly.instantiateStreaming` 的优化**: 虽然没有直接的 API 暴露给 JavaScript，但 V8 内部使用序列化技术来优化流式编译和实例化过程。例如，可以先反序列化模块的元数据，以便更快地启动实例化过程。

**JavaScript 示例:**

以下 JavaScript 代码演示了如何使用 `WebAssembly` API 来加载、编译和缓存 WebAssembly 模块：

```javascript
async function loadAndCacheWasm(url) {
  try {
    // 尝试从缓存中加载模块
    const cachedModuleResponse = await caches.match(url);
    if (cachedModuleResponse) {
      const cachedModuleBuffer = await cachedModuleResponse.arrayBuffer();
      const wasmModule = await WebAssembly.compile(cachedModuleBuffer);
      console.log("Loaded WASM module from cache!");
      return wasmModule;
    }

    // 如果缓存中没有，则从网络加载并编译
    const response = await fetch(url);
    const wasmBuffer = await response.arrayBuffer();
    const wasmModule = await WebAssembly.compile(wasmBuffer);

    // 将编译后的模块放入缓存
    const cache = await caches.open('wasm-cache');
    const newResponse = new Response(wasmBuffer, { headers: { 'Content-Type': 'application/wasm' } });
    cache.put(url, newResponse);
    console.log("Loaded and cached WASM module from network!");
    return wasmModule;

  } catch (error) {
    console.error("Error loading WASM module:", error);
  }
}

async function instantiateWasm(wasmModule) {
  try {
    const instance = await WebAssembly.instantiate(wasmModule);
    return instance;
  } catch (error) {
    console.error("Error instantiating WASM module:", error);
  }
}

async function runWasm() {
  const wasmModule = await loadAndCacheWasm('my-wasm-module.wasm');
  if (wasmModule) {
    const instance = await instantiateWasm(wasmModule);
    // 使用 WebAssembly 实例
    console.log(instance.exports.add(5, 3));
  }
}

runWasm();
```

**在这个示例中，当浏览器第一次加载 `my-wasm-module.wasm` 时，V8 引擎会在后台使用 `wasm-serialization.cc` 中的代码将编译后的 `WebAssembly.Module` 对象序列化并存储到浏览器的 HTTP 缓存中。 当下次访问相同的页面或应用再次加载该模块时，V8 引擎会尝试从缓存中反序列化该模块，从而避免了重新编译的开销，提高了加载速度。**

总而言之，`v8/src/wasm/wasm-serialization.cc` 是 V8 引擎中实现 WebAssembly 模块持久化和快速加载的关键组件，它通过序列化和反序列化技术，极大地提升了 WebAssembly 应用的性能和用户体验。

Prompt: 
```
这是目录为v8/src/wasm/wasm-serialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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
    if (batch_size >= batch_limit) {
      reloc_queue.Add(std::move(batch));
      DCHECK(batch.empty());
      batch_size = 0;
      job_handle->NotifyConcurrencyIncrease();
    }
  }

  // We should have read the expected amount of code now, and should have fully
  // utilized the allocated code space.
  DCHECK_EQ(0, remaining_code_size_);
  DCHECK_EQ(0, current_code_space_.size());

  if (!batch.empty()) {
    reloc_queue.Add(std::move(batch));
    job_handle->NotifyConcurrencyIncrease();
  }

  // Wait for all tasks to finish, while participating in their work.
  job_handle->Join();

  ReadTieringBudget(reader);
  return reader->current_size() == 0;
}

void NativeModuleDeserializer::ReadHeader(Reader* reader) {
  WasmDetectedFeatures detected_features = WasmDetectedFeatures::FromIntegral(
      reader->Read<WasmDetectedFeatures::StorageType>());
  // Ignore the return value of UpdateDetectedFeatures; all features will be
  // published after deserialization anyway.
  USE(native_module_->compilation_state()->UpdateDetectedFeatures(
      detected_features));

  remaining_code_size_ = reader->Read<size_t>();

  all_functions_validated_ = reader->Read<bool>();

  auto compile_imports_flags =
      reader->Read<CompileTimeImportFlags::StorageType>();
  uint32_t constants_module_size = reader->Read<uint32_t>();
  base::Vector<const char> constants_module_data =
      reader->ReadVector<char>(constants_module_size);
  compile_imports_ = CompileTimeImports::FromSerialized(compile_imports_flags,
                                                        constants_module_data);

  uint32_t imported = native_module_->module()->num_imported_functions;
  if (imported > 0) {
    base::Vector<const WellKnownImport> well_known_imports =
        reader->ReadVector<WellKnownImport>(imported);
    native_module_->module()->type_feedback.well_known_imports.Initialize(
        well_known_imports);
  }
}

DeserializationUnit NativeModuleDeserializer::ReadCode(int fn_index,
                                                       Reader* reader) {
  uint8_t code_kind = reader->Read<uint8_t>();
  if (code_kind == kLazyFunction) {
    lazy_functions_.push_back(fn_index);
    return {};
  }
  if (code_kind == kEagerFunction) {
    eager_functions_.push_back(fn_index);
    return {};
  }

  int constant_pool_offset = reader->Read<int>();
  int safepoint_table_offset = reader->Read<int>();
  int handler_table_offset = reader->Read<int>();
  int code_comment_offset = reader->Read<int>();
  int unpadded_binary_size = reader->Read<int>();
  int stack_slot_count = reader->Read<int>();
  int ool_spill_count = reader->Read<int>();
  uint32_t tagged_parameter_slots = reader->Read<uint32_t>();
  int code_size = reader->Read<int>();
  int reloc_size = reader->Read<int>();
  int source_position_size = reader->Read<int>();
  int inlining_position_size = reader->Read<int>();
  int deopt_data_size = reader->Read<int>();
  // TODO(mliedtke): protected_instructions_data is the first part of the
  // meta_data_ array. Ideally the sizes would be in the same order...
  int protected_instructions_size = reader->Read<int>();
  WasmCode::Kind kind = reader->Read<WasmCode::Kind>();
  ExecutionTier tier = reader->Read<ExecutionTier>();

  DCHECK(IsAligned(code_size, kCodeAlignment));
  DCHECK_GE(remaining_code_size_, code_size);
  if (current_code_space_.size() < static_cast<size_t>(code_size)) {
    // Allocate the next code space. Don't allocate more than 90% of
    // {kMaxCodeSpaceSize}, to leave some space for jump tables.
    size_t max_reservation = RoundUp<kCodeAlignment>(
        v8_flags.wasm_max_code_space_size_mb * MB * 9 / 10);
    size_t code_space_size = std::min(max_reservation, remaining_code_size_);
    std::tie(current_code_space_, current_jump_tables_) =
        native_module_->AllocateForDeserializedCode(code_space_size);
    DCHECK_EQ(current_code_space_.size(), code_space_size);
    CHECK(current_jump_tables_.is_valid());
  }

  DeserializationUnit unit;
  unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size);
  auto reloc_info = reader->ReadVector<uint8_t>(reloc_size);
  auto source_pos = reader->ReadVector<uint8_t>(source_position_size);
  auto inlining_pos = reader->ReadVector<uint8_t>(inlining_position_size);
  auto deopt_data = reader->ReadVector<uint8_t>(deopt_data_size);
  auto protected_instructions =
      reader->ReadVector<uint8_t>(protected_instructions_size);

  base::Vector<uint8_t> instructions =
      current_code_space_.SubVector(0, code_size);
  current_code_space_ += code_size;
  remaining_code_size_ -= code_size;

  unit.code = native_module_->AddDeserializedCode(
      fn_index, instructions, stack_slot_count, ool_spill_count,
      tagged_parameter_slots, safepoint_table_offset, handler_table_offset,
      constant_pool_offset, code_comment_offset, unpadded_binary_size,
      protected_instructions, reloc_info, source_pos, inlining_pos, deopt_data,
      kind, tier);
  unit.jump_tables = current_jump_tables_;
  return unit;
}

void NativeModuleDeserializer::CopyAndRelocate(
    const DeserializationUnit& unit) {
  WritableJitAllocation jit_allocation = ThreadIsolation::RegisterJitAllocation(
      reinterpret_cast<Address>(unit.code->instructions().begin()),
      unit.code->instructions().size(),
      ThreadIsolation::JitAllocationType::kWasmCode, false);

  jit_allocation.CopyCode(0, unit.src_code_buffer.begin(),
                          unit.src_code_buffer.size());

  // Relocate the code.
  int kMask = RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
              RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL) |
              RelocInfo::ModeMask(RelocInfo::WASM_CANONICAL_SIG_ID) |
              RelocInfo::ModeMask(RelocInfo::WASM_INDIRECT_CALL_TARGET) |
              RelocInfo::ModeMask(RelocInfo::EXTERNAL_REFERENCE) |
              RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
              RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE_ENCODED);
  for (WritableRelocIterator iter(jit_allocation, unit.code->instructions(),
                                  unit.code->reloc_info(),
                                  unit.code->constant_pool(), kMask);
       !iter.done(); iter.next()) {
    RelocInfo::Mode mode = iter.rinfo()->rmode();
    switch (mode) {
      case RelocInfo::WASM_CALL: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address target =
            native_module_->GetNearCallTargetForFunction(tag, unit.jump_tables);
        iter.rinfo()->set_wasm_call_address(target);
        break;
      }
      case RelocInfo::WASM_STUB_CALL: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address target = native_module_->GetJumpTableEntryForBuiltin(
            static_cast<Builtin>(tag), unit.jump_tables);
        iter.rinfo()->set_wasm_stub_call_address(target);
        break;
      }
      case RelocInfo::WASM_CANONICAL_SIG_ID: {
        // This is intentional: in serialized code, we patched embedded
        // canonical signature IDs with their module-specific equivalents,
        // so although the accessor is called "wasm_canonical_sig_id()", what
        // we get back is actually a module-specific signature ID, which we
        // now need to translate back to a canonical ID.
        ModuleTypeIndex module_local_sig_id{
            iter.rinfo()->wasm_canonical_sig_id()};
        CanonicalTypeIndex canonical_sig_id =
            native_module_->module()->canonical_sig_id(module_local_sig_id);
        iter.rinfo()->set_wasm_canonical_sig_id(canonical_sig_id.index);
      } break;
      case RelocInfo::WASM_INDIRECT_CALL_TARGET: {
        Address function_index = iter.rinfo()->wasm_indirect_call_target();
        WasmCodePointer target = native_module_->GetIndirectCallTarget(
            base::checked_cast<uint32_t>(function_index));
        iter.rinfo()->set_wasm_indirect_call_target(target, SKIP_ICACHE_FLUSH);
      } break;
      case RelocInfo::EXTERNAL_REFERENCE: {
        uint32_t tag = GetWasmCalleeTag(iter.rinfo());
        Address address = ExternalReferenceList::Get().address_from_tag(tag);
        iter.rinfo()->set_target_external_reference(address, SKIP_ICACHE_FLUSH);
        break;
      }
      case RelocInfo::INTERNAL_REFERENCE:
      case RelocInfo::INTERNAL_REFERENCE_ENCODED: {
        Address offset = iter.rinfo()->target_internal_reference();
        Address target = unit.code->instruction_start() + offset;
        Assembler::deserialization_set_target_internal_reference_at(
            iter.rinfo()->pc(), target, mode);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  // Finally, flush the icache for that code.
  FlushInstructionCache(unit.code->instructions().begin(),
                        unit.code->instructions().size());
}

void NativeModuleDeserializer::ReadTieringBudget(Reader* reader) {
  size_t size_of_tiering_budget =
      native_module_->module()->num_declared_functions * sizeof(uint32_t);
  if (size_of_tiering_budget > reader->current_size()) {
    return;
  }
  base::Vector<const uint8_t> serialized_budget =
      reader->ReadVector<const uint8_t>(size_of_tiering_budget);

  memcpy(native_module_->tiering_budget_array(), serialized_budget.begin(),
         size_of_tiering_budget);
}

void NativeModuleDeserializer::Publish(std::vector<DeserializationUnit> batch) {
  DCHECK(!batch.empty());
  std::vector<std::unique_ptr<WasmCode>> codes;
  codes.reserve(batch.size());
  for (auto& unit : batch) {
    codes.emplace_back(std::move(unit).code);
  }
  auto published_codes = native_module_->PublishCode(base::VectorOf(codes));
  for (auto* wasm_code : published_codes) {
    wasm_code->MaybePrint();
    wasm_code->Validate();
  }
}

bool IsSupportedVersion(base::Vector<const uint8_t> header,
                        WasmEnabledFeatures enabled_features) {
  if (header.size() < WasmSerializer::kHeaderSize) return false;
  uint8_t current_version[WasmSerializer::kHeaderSize];
  Writer writer({current_version, WasmSerializer::kHeaderSize});
  WriteHeader(&writer, enabled_features);
  return memcmp(header.begin(), current_version, WasmSerializer::kHeaderSize) ==
         0;
}

MaybeHandle<WasmModuleObject> DeserializeNativeModule(
    Isolate* isolate, base::Vector<const uint8_t> data,
    base::Vector<const uint8_t> wire_bytes_vec,
    const CompileTimeImports& compile_imports,
    base::Vector<const char> source_url) {
  WasmEnabledFeatures enabled_features =
      WasmEnabledFeatures::FromIsolate(isolate);
  if (!IsWasmCodegenAllowed(isolate, isolate->native_context())) return {};
  if (!IsSupportedVersion(data, enabled_features)) return {};

  // Make the copy of the wire bytes early, so we use the same memory for
  // decoding, lookup in the native module cache, and insertion into the cache.
  auto owned_wire_bytes = base::OwnedVector<uint8_t>::Of(wire_bytes_vec);

  WasmDetectedFeatures detected_features;
  ModuleResult decode_result = DecodeWasmModule(
      enabled_features, owned_wire_bytes.as_vector(), false,
      i::wasm::kWasmOrigin, isolate->counters(), isolate->metrics_recorder(),
      isolate->GetOrRegisterRecorderContextId(isolate->native_context()),
      DecodingMethod::kDeserialize, &detected_features);
  if (decode_result.failed()) return {};
  std::shared_ptr<WasmModule> module = std::move(decode_result).value();
  CHECK_NOT_NULL(module);

  WasmEngine* wasm_engine = GetWasmEngine();
  auto shared_native_module = wasm_engine->MaybeGetNativeModule(
      module->origin, owned_wire_bytes.as_vector(), compile_imports, isolate);
  if (shared_native_module == nullptr) {
    const bool dynamic_tiering = v8_flags.wasm_dynamic_tiering;
    const bool include_liftoff = !dynamic_tiering;
    size_t code_size_estimate =
        wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
            module.get(), include_liftoff, DynamicTiering{dynamic_tiering});
    shared_native_module = wasm_engine->NewNativeModule(
        isolate, enabled_features, detected_features, compile_imports,
        std::move(module), code_size_estimate);
    // We have to assign a compilation ID here, as it is required for a
    // potential re-compilation, e.g. triggered by
    // {EnterDebuggingForIsolate}. The value is -2 so that it is different
    // than the compilation ID of actual compilations, and also different than
    // the sentinel value of the CompilationState.
    shared_native_module->compilation_state()->set_compilation_id(-2);
    shared_native_module->SetWireBytes(std::move(owned_wire_bytes));

    NativeModuleDeserializer deserializer(shared_native_module.get());
    Reader reader(data + WasmSerializer::kHeaderSize);
    bool error = !deserializer.Read(&reader);
    if (error) {
      wasm_engine->UpdateNativeModuleCache(
          error, std::move(shared_native_module), isolate);
      return {};
    }
    shared_native_module->compilation_state()->InitializeAfterDeserialization(
        deserializer.lazy_functions(), deserializer.eager_functions());
    wasm_engine->UpdateNativeModuleCache(error, shared_native_module, isolate);
    // Now publish the full set of detected features (read during
    // deserialization, so potentially more than from DecodeWasmModule above).
    detected_features =
        shared_native_module->compilation_state()->detected_features();
    PublishDetectedFeatures(detected_features, isolate, true);
  }

  DirectHandle<Script> script =
      wasm_engine->GetOrCreateScript(isolate, shared_native_module, source_url);
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(isolate, shared_native_module, script);

  // Finish the Wasm script now and make it public to the debugger.
  isolate->debug()->OnAfterCompile(script);

  // Log the code within the generated module for profiling.
  shared_native_module->LogWasmCodes(isolate, *script);

  return module_object;
}

}  // namespace v8::internal::wasm

"""

```