Response:
Let's break down the thought process for analyzing this C++ header file and answering the user's request.

1. **Initial Scan and Identification of Core Purpose:**  The first step is to quickly read through the code, looking for keywords and patterns. We see `#ifndef`, `#define`, `#include`, `namespace v8::internal::wasm`, `class`, and various data structures. The namespace immediately tells us this is related to WebAssembly within the V8 JavaScript engine. The class names like `WasmModuleBuilder` and `WasmFunctionBuilder` strongly suggest the purpose is to *construct* WebAssembly modules programmatically.

2. **Decomposition by Class:**  The code is well-structured into classes. The next logical step is to understand the role of each major class:

    * **`ZoneBuffer`:** This class clearly deals with memory management. The names of its methods (`write_u8`, `write_u32v`, `EnsureSpace`, `patch_u32v`) indicate it's a buffer specifically designed for writing binary data, likely in a little-endian format (given `base::WriteLittleEndianValue`). The `Zone* zone_` member suggests it's using V8's zone allocation system for memory management.

    * **`WasmFunctionBuilder`:** This class focuses on building individual WebAssembly functions. Method names like `SetSignature`, `AddLocal`, `EmitByte`, `EmitI32Const`, `EmitGetLocal` strongly point to its role in defining the structure and bytecode of a function. The presence of `asm_offsets_` hints at potential integration with asm.js.

    * **`WasmModuleBuilder`:** This is the central class for constructing an entire WebAssembly module. It contains collections of functions, globals, tables, memories, data segments, element segments, and type information. Methods like `AddImport`, `AddFunction`, `AddGlobal`, `AddExport`, `WriteTo` clearly demonstrate its responsibility in assembling the complete module. The nested `WasmElemSegment` class is also part of the module structure.

3. **Inferring Functionality from Methods:** Once the classes are understood, examine the methods within each class. For `WasmFunctionBuilder`, methods like `EmitByte`, `EmitI32V`, and the various `Emit...Const` methods reveal its role in generating the raw WebAssembly bytecode. The `SetSignature` method indicates associating a type signature with the function.

    For `WasmModuleBuilder`, the `Add...` methods are key. `AddImport` registers imported functions, `AddFunction` creates new function builders, `AddGlobal` adds global variables, `AddTable` creates tables, and so on. The `WriteTo` method is crucial as it signifies the final step of serializing the built module.

4. **Identifying Relationships Between Classes:** Observe how the classes interact. `WasmFunctionBuilder` has a member `WasmModuleBuilder* builder_`, indicating that a function builder is associated with a specific module builder. The `WasmModuleBuilder` has a collection of `WasmFunctionBuilder* functions_`, reinforcing this relationship.

5. **Connecting to WebAssembly Concepts:** At this stage, relate the C++ code to the core concepts of WebAssembly. "Signature" maps to function types. "Locals" are local variables within a function. "Globals" are module-level variables. "Tables" are for indirect function calls. "Memory" represents linear memory. "Imports" and "Exports" define the module's interface with the outside world. This helps solidify the understanding of the C++ code's purpose.

6. **Addressing Specific User Questions:**

    * **Functionality Listing:** Based on the analysis so far, summarize the main functionalities of each class. Focus on the actions they perform in the process of building a WebAssembly module.

    * **`.tq` Extension:** The prompt specifically asks about the `.tq` extension. A quick search or prior knowledge would confirm that `.tq` files are indeed used for V8's Torque language, and the code provided is C++ (`.h`).

    * **Relationship to JavaScript:**  Since WebAssembly is executed within a JavaScript engine, the `WasmModuleBuilder` is used to create modules that can be loaded and executed by JavaScript. Think about the `WebAssembly` JavaScript API. A simple example using `WebAssembly.Module` and a manually constructed binary array would illustrate this connection.

    * **Code Logic Inference:**  Focus on simpler methods like those in `ZoneBuffer`. For example, `write_u32v` writing variable-length integers is a clear piece of logic. Hypothesize an input (e.g., `150`) and manually trace the variable-length encoding to determine the output.

    * **Common Programming Errors:** Think about how a developer using this API might make mistakes. Incorrectly setting the signature, emitting the wrong opcode, or forgetting to add an export are all plausible errors. Illustrate with simplified (even pseudo-code) examples of how these errors could manifest.

7. **Refinement and Organization:** Finally, organize the information into a clear and structured answer. Use headings, bullet points, and code examples to make the explanation easy to understand. Ensure that all parts of the user's request are addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is `ZoneBuffer` just a standard buffer?
* **Correction:**  The `Zone* zone_` member is crucial. It signifies V8's specific memory management, not just a general-purpose buffer.

* **Initial thought:** Just list all the methods.
* **Refinement:** Group the methods by functionality (e.g., building, writing) for better clarity. Explain *what* the methods do, not just their names.

* **Initial thought:**  The JavaScript example should be complex.
* **Refinement:** Keep the JavaScript example simple and focused on the core interaction of creating and using a WebAssembly module, even if the binary data is basic. The goal is to illustrate the *connection*, not to be a comprehensive WebAssembly tutorial.

By following this iterative process of scanning, decomposing, inferring, connecting, and refining, we can effectively analyze the given C++ header file and provide a comprehensive and accurate answer to the user's request.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_MODULE_BUILDER_H_
#define V8_WASM_WASM_MODULE_BUILDER_H_

#include <optional>

#include "src/base/memory.h"
#include "src/base/platform/wrappers.h"
#include "src/base/vector.h"
#include "src/codegen/signature.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/local-decl-encoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-result.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::wasm {

class ZoneBuffer : public ZoneObject {
 public:
  // This struct is just a type tag for Zone::NewArray<T>(size_t) call.
  struct Buffer {};

  static constexpr size_t kInitialSize = 1024;
  explicit ZoneBuffer(Zone* zone, size_t initial = kInitialSize)
      : zone_(zone), buffer_(zone->AllocateArray<uint8_t, Buffer>(initial)) {
    pos_ = buffer_;
    end_ = buffer_ + initial;
  }

  void write_u8(uint8_t x) {
    EnsureSpace(1);
    *(pos_++) = x;
  }

  void write_u16(uint16_t x) {
    EnsureSpace(2);
    base::WriteLittleEndianValue<uint16_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 2;
  }

  void write_u32(uint32_t x) {
    EnsureSpace(4);
    base::WriteLittleEndianValue<uint32_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 4;
  }

  void write_u64(uint64_t x) {
    EnsureSpace(8);
    base::WriteLittleEndianValue<uint64_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 8;
  }

  void write_u32v(uint32_t val) {
    EnsureSpace(kMaxVarInt32Size);
    LEBHelper::write_u32v(&pos_, val);
  }

  void write_u32v(ModuleTypeIndex index) { write_u32v(index.index); }

  void write_i32v(int32_t val) {
    EnsureSpace(kMaxVarInt32Size);
    LEBHelper::write_i32v(&pos_, val);
  }

  void write_u64v(uint64_t val) {
    EnsureSpace(kMaxVarInt64Size);
    LEBHelper::write_u64v(&pos_, val);
  }

  void write_i64v(int64_t val) {
    EnsureSpace(kMaxVarInt64Size);
    LEBHelper::write_i64v(&pos_, val);
  }

  void write_size(size_t val) {
    EnsureSpace(kMaxVarInt32Size);
    DCHECK_EQ(val, static_cast<uint32_t>(val));
    LEBHelper::write_u32v(&pos_, static_cast<uint32_t>(val));
  }

  void write_f32(float val) { write_u32(base::bit_cast<uint32_t>(val)); }

  void write_f64(double val) { write_u64(base::bit_cast<uint64_t>(val)); }

  void write(const uint8_t* data, size_t size) {
    if (size == 0) return;
    EnsureSpace(size);
    memcpy(pos_, data, size);
    pos_ += size;
  }

  void write_string(base::Vector<const char> name) {
    write_size(name.length());
    write(reinterpret_cast<const uint8_t*>(name.begin()), name.length());
  }

  size_t reserve_u32v() {
    size_t off = offset();
    EnsureSpace(kMaxVarInt32Size);
    pos_ += kMaxVarInt32Size;
    return off;
  }

  // Patch a (padded) u32v at the given offset to be the given value.
  void patch_u32v(size_t offset, uint32_t val) {
    uint8_t* ptr = buffer_ + offset;
    for (size_t pos = 0; pos != kPaddedVarInt32Size; ++pos) {
      uint32_t next = val >> 7;
      uint8_t out = static_cast<uint8_t>(val & 0x7f);
      if (pos != kPaddedVarInt32Size - 1) {
        *(ptr++) = 0x80 | out;
        val = next;
      } else {
        *(ptr++) = out;
      }
    }
  }

  void patch_u8(size_t offset, uint8_t val) {
    DCHECK_GE(size(), offset);
    buffer_[offset] = val;
  }

  size_t offset() const { return static_cast<size_t>(pos_ - buffer_); }
  size_t size() const { return static_cast<size_t>(pos_ - buffer_); }
  uint8_t* data() const { return buffer_; }
  uint8_t* begin() const { return buffer_; }
  uint8_t* end() const { return pos_; }

  void EnsureSpace(size_t size) {
    if ((pos_ + size) > end_) {
      size_t new_size = size + (end_ - buffer_) * 2;
      uint8_t* new_buffer = zone_->AllocateArray<uint8_t, Buffer>(new_size);
      memcpy(new_buffer, buffer_, (pos_ - buffer_));
      pos_ = new_buffer + (pos_ - buffer_);
      buffer_ = new_buffer;
      end_ = new_buffer + new_size;
    }
    DCHECK(pos_ + size <= end_);
  }

  void Truncate(size_t size) {
    DCHECK_GE(offset(), size);
    pos_ = buffer_ + size;
  }

  uint8_t** pos_ptr() { return &pos_; }

 private:
  Zone* zone_;
  uint8_t* buffer_;
  uint8_t* pos_;
  uint8_t* end_;
};

class WasmModuleBuilder;

class V8_EXPORT_PRIVATE WasmFunctionBuilder : public ZoneObject {
 public:
  // Building methods.
  void SetSignature(const FunctionSig* sig);
  void SetSignature(ModuleTypeIndex sig_index);
  uint32_t AddLocal(ValueType type);
  void EmitByte(uint8_t b);
  void EmitI32V(int32_t val);
  // Some instructions need an "s33" heaptype immediate.
  void EmitI32V(ModuleTypeIndex index) { EmitI32V(index.index); }
  void EmitU32V(uint32_t val);
  // Some instructions need a u32 type index immediate.
  void EmitU32V(ModuleTypeIndex index) { EmitU32V(index.index); }
  void EmitU64V(uint64_t val);
  void EmitCode(const uint8_t* code, uint32_t code_size);
  void EmitCode(std::initializer_list<const uint8_t> code);
  void Emit(WasmOpcode opcode);
  void EmitWithPrefix(WasmOpcode opcode);
  void EmitGetLocal(uint32_t index);
  void EmitSetLocal(uint32_t index);
  void EmitTeeLocal(uint32_t index);
  void EmitI32Const(int32_t val);
  void EmitI64Const(int64_t val);
  void EmitF32Const(float val);
  void EmitF64Const(double val);
  void EmitS128Const(Simd128 val);
  void EmitWithU8(WasmOpcode opcode, const uint8_t immediate);
  void EmitWithU8U8(WasmOpcode opcode, const uint8_t imm1, const uint8_t imm2);
  void EmitWithI32V(WasmOpcode opcode, int32_t immediate);
  void EmitWithU32V(WasmOpcode opcode, uint32_t immediate);
  void EmitWithU32V(WasmOpcode opcode, ModuleTypeIndex index) {
    EmitWithU32V(opcode, index.index);
  }
  void EmitValueType(ValueType type);
  void EmitDirectCallIndex(uint32_t index);
  void EmitFromInitializerExpression(const WasmInitExpr& init_expr);
  void SetName(base::Vector<const char> name);
  void AddAsmWasmOffset(size_t call_position, size_t to_number_position);
  void SetAsmFunctionStartPosition(size_t function_position);
  void SetCompilationHint(WasmCompilationHintStrategy strategy,
                          WasmCompilationHintTier baseline,
                          WasmCompilationHintTier top_tier);

  size_t GetPosition() const { return body_.size(); }
  void FixupByte(size_t position, uint8_t value) {
    body_.patch_u8(position, value);
  }
  void DeleteCodeAfter(size_t position);

  void WriteSignature(ZoneBuffer* buffer) const;
  void WriteBody(ZoneBuffer* buffer) const;
  void WriteAsmWasmOffsetTable(ZoneBuffer* buffer) const;

  WasmModuleBuilder* builder() const { return builder_; }
  uint32_t func_index() const { return func_index_; }
  ModuleTypeIndex sig_index() const { return signature_index_; }
  inline const FunctionSig* signature() const;

 private:
  explicit WasmFunctionBuilder(WasmModuleBuilder* builder);
  friend class WasmModuleBuilder;
  friend Zone;

  struct DirectCallIndex {
    size_t offset;
    uint32_t direct_index;
  };

  WasmModuleBuilder* builder_;
  LocalDeclEncoder locals_;
  ModuleTypeIndex signature_index_;
  uint32_t func_index_;
  ZoneBuffer body_;
  base::Vector<const char> name_;
  ZoneVector<uint32_t> i32_temps_;
  ZoneVector<uint32_t> i64_temps_;
  ZoneVector<uint32_t> f32_temps_;
  ZoneVector<uint32_t> f64_temps_;
  ZoneVector<DirectCallIndex> direct_calls_;

  // Delta-encoded mapping from wasm bytes to asm.js source positions.
  ZoneBuffer asm_offsets_;
  uint32_t last_asm_byte_offset_ = 0;
  uint32_t last_asm_source_position_ = 0;
  uint32_t asm_func_start_source_position_ = 0;
  uint8_t hint_ = kNoCompilationHint;
};

class V8_EXPORT_PRIVATE WasmModuleBuilder : public ZoneObject {
 public:
  explicit WasmModuleBuilder(Zone* zone);
  WasmModuleBuilder(const WasmModuleBuilder&) = delete;
  WasmModuleBuilder& operator=(const WasmModuleBuilder&) = delete;

  // Static representation of wasm element segment (table initializer). This is
  // different than the version in wasm-module.h.
  class WasmElemSegment {
   public:
    // asm.js gives function indices starting with the first non-imported
    // function.
    enum FunctionIndexingMode {
      kRelativeToImports,
      kRelativeToDeclaredFunctions
    };
    enum Status {
      kStatusActive,      // copied automatically during instantiation.
      kStatusPassive,     // copied explicitly after instantiation.
      kStatusDeclarative  // purely declarative and never copied.
    };
    struct Entry {
      enum Kind { kGlobalGetEntry, kRefFuncEntry, kRefNullEntry } kind;
      uint32_t index;
      Entry(Kind kind, uint32_t index) : kind(kind), index(index) {}
      Entry() : kind(kRefNullEntry), index(0) {}
    };

    // Construct an active segment.
    WasmElemSegment(Zone* zone, ValueType type, uint32_t table_index,
                    WasmInitExpr offset)
        : type(type),
          table_index(table_index),
          offset(offset),
          entries(zone),
          status(kStatusActive) {
      DCHECK(IsValidOffsetKind(offset.kind()));
    }

    // Construct a passive or declarative segment, which has no table
    // index or offset.
    WasmElemSegment(Zone* zone, ValueType type, bool declarative,
                    WasmInitExpr offset)
        : type(type),
          table_index(0),
          offset(offset),
          entries(zone),
          status(declarative ? kStatusDeclarative : kStatusPassive) {
      DCHECK(IsValidOffsetKind(offset.kind()));
    }

    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(WasmElemSegment);

    ValueType type;
    uint32_t table_index;
    WasmInitExpr offset;
    FunctionIndexingMode indexing_mode = kRelativeToImports;
    ZoneVector<Entry> entries;
    Status status;

   private:
    // This ensures no {WasmInitExpr} with subexpressions is used, which would
    // cause a memory leak because those are stored in an std::vector. Such
    // offset would also be mistyped.
    bool IsValidOffsetKind(WasmInitExpr::Operator kind) {
      return kind == WasmInitExpr::kI32Const ||
             kind == WasmInitExpr::kI64Const ||
             kind == WasmInitExpr::kGlobalGet ||
             kind == WasmInitExpr::kRefNullConst;
    }
  };

  // Building methods.
  uint32_t AddImport(base::Vector<const char> name, const FunctionSig* sig,
                     base::Vector<const char> module = {});
  WasmFunctionBuilder* AddFunction(const FunctionSig* sig = nullptr);
  WasmFunctionBuilder* AddFunction(ModuleTypeIndex sig_index);
  uint32_t AddGlobal(ValueType type, bool mutability, WasmInitExpr init);
  uint32_t AddGlobalImport(base::Vector<const char> name, ValueType type,
                           bool mutability,
                           base::Vector<const char> module = {});
  void AddDataSegment(const uint8_t* data, uint32_t size, uint32_t dest);
  void AddPassiveDataSegment(const uint8_t* data, uint32_t size);
  // Add an element segment to this {WasmModuleBuilder}. {segment}'s enties
  // have to be initialized.
  uint32_t AddElementSegment(WasmElemSegment segment);
  // Helper method to create an active segment with one function. Assumes that
  // table segment at {table_index} is typed as funcref.
  void SetIndirectFunction(uint32_t table_index, uint32_t index_in_table,
                           uint32_t direct_function_index,
                           WasmElemSegment::FunctionIndexingMode indexing_mode);
  // Increase the starting size of the table at {table_index} by {count}. Also
  // increases the maximum table size if needed. Returns the former starting
  // size, or the maximum uint32_t value if the maximum table size has been
  // exceeded.
  uint32_t IncreaseTableMinSize(uint32_t table_index, uint32_t count);
  // Adds the signature to the module if it does not already exist.
  ModuleTypeIndex AddSignature(const FunctionSig* sig, bool is_final,
                               ModuleTypeIndex supertype = kNoSuperType);
  // Does not deduplicate function signatures.
  ModuleTypeIndex ForceAddSignature(const FunctionSig* sig, bool is_final,
                                    ModuleTypeIndex supertype = kNoSuperType);
  uint32_t AddTag(const FunctionSig* type);
  ModuleTypeIndex AddStructType(StructType* type, bool is_final,
                                ModuleTypeIndex supertype = kNoSuperType);
  ModuleTypeIndex AddArrayType(ArrayType* type, bool is_final,
                               ModuleTypeIndex supertype = kNoSuperType);
  uint32_t AddTable(ValueType type, uint32_t min_size);
  uint32_t AddTable(ValueType type, uint32_t min_size, uint32_t max_size,
                    AddressType address_type = AddressType::kI32);
  uint32_t AddTable(ValueType type, uint32_t min_size, uint32_t max_size,
                    WasmInitExpr init,
                    AddressType address_type = AddressType::kI32);
  uint32_t AddMemory(uint32_t min_pages);
  uint32_t AddMemory(uint32_t min_pages, uint32_t max_pages);
  uint32_t AddMemory64(uint32_t min_pages);
  uint32_t AddMemory64(uint32_t min_pages, uint32_t max_pages);
  void MarkStartFunction(WasmFunctionBuilder* builder);
  void AddExport(base::Vector<const char> name, ImportExportKindCode kind,
                 uint32_t index);
  void AddExport(base::Vector<const char> name, WasmFunctionBuilder* builder) {
    AddExport(name, kExternalFunction, builder->func_index());
  }
  uint32_t AddExportedGlobal(ValueType type, bool mutability, WasmInitExpr init,
                             base::Vector<const char> name);
  void ExportImportedFunction(base::Vector<const char> name, int import_index);

  void StartRecursiveTypeGroup() {
    DCHECK_EQ(current_recursive_group_start_, -1);
    current_recursive_group_start_ = static_cast<int>(types_.size());
  }

  void EndRecursiveTypeGroup() {
    // Make sure we are in a recursive group.
    DCHECK_NE(current_recursive_group_start_, -1);
    // Make sure the current recursive group has at least one element.
    DCHECK_GT(static_cast<int>(types_.size()), current_recursive_group_start_);
    recursive_groups_.emplace(
        current_recursive_group_start_,
        static_cast<uint32_t>(types_.size()) - current_recursive_group_start_);
    current_recursive_group_start_ = -1;
  }

  void AddRecursiveTypeGroup(uint32_t start, uint32_t size) {
    recursive_groups_.emplace(start, size);
  }

  // Writing methods.
  void WriteTo(ZoneBuffer* buffer) const;
  void WriteAsmJsOffsetTable(ZoneBuffer* buffer) const;

  Zone* zone() { return zone_; }

  ValueType GetTableType(uint32_t index) { return tables_[index].type; }

  bool IsSignature(uint32_t index) {
    return types_[index].kind == TypeDefinition::kFunction;
  }
  bool IsSignature(ModuleTypeIndex index) { return IsSignature(index.index); }

  const FunctionSig* GetSignature(uint32_t index) {
    DCHECK(types_[index].kind == TypeDefinition::kFunction);
    return types_[index].function_sig;
  }
  const FunctionSig* GetSignature(ModuleTypeIndex index) {
    return GetSignature(index.index);
  }

  bool IsStructType(uint32_t index) {
    return types_[index].kind == TypeDefinition::kStruct;
  }
  bool IsStructType(ModuleTypeIndex index) { return IsStructType(index.index); }
  const StructType* GetStructType(uint32_t index) {
    return types_[index].struct_type;
  }
  const StructType* GetStructType(ModuleTypeIndex index) {
    return GetStructType(index.index);
  }

  bool IsArrayType(uint32_t index) {
    return types_[index].kind == TypeDefinition::kArray;
  }
  bool IsArrayType(ModuleTypeIndex index) { return IsArrayType(index.index); }
  const ArrayType* GetArrayType(uint32_t index) {
    return types_[index].array_type;
  }
  const ArrayType* GetArrayType(ModuleTypeIndex index) {
    return GetArrayType(index.index);
  }

  ModuleTypeIndex GetSuperType(uint32_t index) {
    return types_[index].supertype;
  }

  WasmFunctionBuilder* GetFunction(uint32_t index) { return functions_[index]; }
  int NumTags() { return static_cast<int>(tags_.size()); }

  int NumTypes() { return static_cast<int>(types_.size()); }

  int NumTables() { return static_cast<int>(tables_.size()); }

  int NumMemories() { return static_cast<int>(memories_.size()); }

  int NumGlobals() { return static_cast<int>(globals_.size()); }

  int NumImportedFunctions() {
    return static_cast<int>(function_imports_.size());
  }
  int NumDeclaredFunctions() { return static_cast<int>(functions_.size()); }

  int NumDataSegments() { return static_cast<int>(data_segments_.size()); }

  bool IsMemory64(uint32_t index) { return memories_[index].is_memory64(); }

  bool IsTable64(uint32_t index) { return tables_[index].is_table64(); }

  const FunctionSig* GetTagType(int index) {
    return types_[tags_[index].index].function_sig;
  }

  ValueType GetGlobalType(uint32_t index) const { return globals_[index].type; }

  bool IsMutableGlobal(uint32_t index) const {
    return globals_[index].mutability;
  }

 private:
  struct WasmFunctionImport {
    base::Vector<const char> module;
    base::Vector<const char> name;
    ModuleTypeIndex sig_index;
  };

  struct WasmGlobalImport {
    base::Vector<const char> module;
    base::Vector<const char> name;
    // TODO(manoskouk): Extend to full value type.
    ValueTypeCode type_code;
    bool mutability;
  };

  struct WasmExport {
    base::Vector<const char> name;
    ImportExportKindCode kind;
    int index;  // Can be negative for re-exported imports.
  };

  struct WasmGlobal {
    ValueType type;
    bool mutability;
    WasmInitExpr init;
  };

  struct WasmTable {
    ValueType type;
    uint32_t min_size;
    uint32_t max_size = 0;
    bool has_maximum = false;
    bool is_shared = false;
    AddressType address_type = AddressType::kI32;
    std::optional<WasmInitExpr> init = {};

    bool is_table64() const { return address_type == AddressType::kI64; }
  };

  struct WasmMemory {
    uint32_t min_pages;
    uint32_t max_pages = 0;
    bool has_max_pages = false;
    bool is_shared = false;
    AddressType address_type = AddressType::kI32;

    bool is_memory64() const { return address_type == AddressType::kI64; }
  };

  struct WasmDataSegment {
    ZoneVector<uint8_t> data;
    uint32_t dest;
    bool is_active = true;
  };

  friend class WasmFunctionBuilder;
  Zone* zone_;
  ZoneVector<TypeDefinition> types_;
  ZoneVector<WasmFunctionImport> function_imports_;
  ZoneVector<WasmGlobalImport> global_imports_;
  ZoneVector<WasmExport> exports_;
  ZoneVector<WasmFunctionBuilder*> functions_;
  ZoneVector<WasmTable> tables_;
  ZoneVector<WasmMemory> memories_;
  ZoneVector<WasmDataSegment> data_segments_;
  ZoneVector<WasmElemSegment> element_segments_;
  ZoneVector<WasmGlobal> globals_;
  ZoneVector<ModuleTypeIndex> tags_;
  ZoneUnorderedMap<FunctionSig, ModuleTypeIndex> signature_map_;
  int current_recursive_group_start_;
  // first index -> size
  ZoneUnorderedMap<uint32_t, uint32_t> recursive_groups_;
  int start_function_index_;
#if DEBUG
  // Once AddExportedImport is called, no more imports can be added.
  bool adding_imports_allowed_ = true;
#endif
};

const FunctionSig* WasmFunctionBuilder::signature() const {
  return builder_->types_[signature_index_.index].function_sig;
}

}  // namespace v8::internal::wasm

#endif  // V8_WASM_WASM_MODULE_BUILDER_H_
```

### 功能列举

`v8/src/wasm/wasm-module-builder.h` 是 V8 引擎中用于构建 WebAssembly 模块的 C++ 头文件。它定义了两个主要的类：`WasmModuleBuilder` 和 `WasmFunctionBuilder`，以及一个辅助类 `ZoneBuffer` 和嵌套类 `WasmElemSegment`。 其主要功能如下：

**1. `ZoneBuffer`:**
   - 提供一个基于 V8 `Zone` 的动态字节缓冲区，用于高效地写入和管理 WebAssembly 模块的二进制数据。
   - 提供了写入不同大小和类型的原始数据（`u8`, `u16`, `u32`, `u64`, `f32`, `f64`）。
   - 提供了写入变长编码整数 (`u32v`, `i32v`, `u64v`, `i64v`) 的方法，这是 WebAssembly 二进制格式中常用的编码方式。
   - 允许预留空间并稍后进行填充 (`reserve_u32v`, `patch_u32v`, `patch_u8`)。
   - 可以写入字符串。
   - 可以动态调整缓冲区大小以容纳更多数据。

**2. `WasmFunctionBuilder`:**
   - 用于构建单个 WebAssembly 函数。
   - 可以设置函数的签名（参数和返回类型）。
   - 可以添加局部变量。
   - 提供了 `Emit...` 系列方法，用于生成 WebAssembly 指令的字节码，包括：
     - 发射原始字节码 (`EmitByte`, `EmitCode`).
     - 发射特定操作码 (`Emit`).
     - 发射带有立即数的指令 (`EmitWithU8`, `EmitWithI32V` 等).
     - 发射常见的操作，如获取/设置局部变量 (`EmitGetLocal`, `EmitSetLocal`).
     - 发射常量 (`EmitI32Const`, `EmitF64Const` 等).
   - 可以设置函数的名称（用于调试和元数据）。
   - 支持记录 asm.js 到 wasm 的偏移量映射。
   - 允许设置编译提示。
   - 可以将构建的函数签名、函数体和 asm.js 偏移量表写入 `ZoneBuffer`。

**3. `WasmModuleBuilder`:**
   - 用于构建完整的 WebAssembly 模块。
### 提示词
```
这是目录为v8/src/wasm/wasm-module-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-module-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_MODULE_BUILDER_H_
#define V8_WASM_WASM_MODULE_BUILDER_H_

#include <optional>

#include "src/base/memory.h"
#include "src/base/platform/wrappers.h"
#include "src/base/vector.h"
#include "src/codegen/signature.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/local-decl-encoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-result.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::wasm {

class ZoneBuffer : public ZoneObject {
 public:
  // This struct is just a type tag for Zone::NewArray<T>(size_t) call.
  struct Buffer {};

  static constexpr size_t kInitialSize = 1024;
  explicit ZoneBuffer(Zone* zone, size_t initial = kInitialSize)
      : zone_(zone), buffer_(zone->AllocateArray<uint8_t, Buffer>(initial)) {
    pos_ = buffer_;
    end_ = buffer_ + initial;
  }

  void write_u8(uint8_t x) {
    EnsureSpace(1);
    *(pos_++) = x;
  }

  void write_u16(uint16_t x) {
    EnsureSpace(2);
    base::WriteLittleEndianValue<uint16_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 2;
  }

  void write_u32(uint32_t x) {
    EnsureSpace(4);
    base::WriteLittleEndianValue<uint32_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 4;
  }

  void write_u64(uint64_t x) {
    EnsureSpace(8);
    base::WriteLittleEndianValue<uint64_t>(reinterpret_cast<Address>(pos_), x);
    pos_ += 8;
  }

  void write_u32v(uint32_t val) {
    EnsureSpace(kMaxVarInt32Size);
    LEBHelper::write_u32v(&pos_, val);
  }

  void write_u32v(ModuleTypeIndex index) { write_u32v(index.index); }

  void write_i32v(int32_t val) {
    EnsureSpace(kMaxVarInt32Size);
    LEBHelper::write_i32v(&pos_, val);
  }

  void write_u64v(uint64_t val) {
    EnsureSpace(kMaxVarInt64Size);
    LEBHelper::write_u64v(&pos_, val);
  }

  void write_i64v(int64_t val) {
    EnsureSpace(kMaxVarInt64Size);
    LEBHelper::write_i64v(&pos_, val);
  }

  void write_size(size_t val) {
    EnsureSpace(kMaxVarInt32Size);
    DCHECK_EQ(val, static_cast<uint32_t>(val));
    LEBHelper::write_u32v(&pos_, static_cast<uint32_t>(val));
  }

  void write_f32(float val) { write_u32(base::bit_cast<uint32_t>(val)); }

  void write_f64(double val) { write_u64(base::bit_cast<uint64_t>(val)); }

  void write(const uint8_t* data, size_t size) {
    if (size == 0) return;
    EnsureSpace(size);
    memcpy(pos_, data, size);
    pos_ += size;
  }

  void write_string(base::Vector<const char> name) {
    write_size(name.length());
    write(reinterpret_cast<const uint8_t*>(name.begin()), name.length());
  }

  size_t reserve_u32v() {
    size_t off = offset();
    EnsureSpace(kMaxVarInt32Size);
    pos_ += kMaxVarInt32Size;
    return off;
  }

  // Patch a (padded) u32v at the given offset to be the given value.
  void patch_u32v(size_t offset, uint32_t val) {
    uint8_t* ptr = buffer_ + offset;
    for (size_t pos = 0; pos != kPaddedVarInt32Size; ++pos) {
      uint32_t next = val >> 7;
      uint8_t out = static_cast<uint8_t>(val & 0x7f);
      if (pos != kPaddedVarInt32Size - 1) {
        *(ptr++) = 0x80 | out;
        val = next;
      } else {
        *(ptr++) = out;
      }
    }
  }

  void patch_u8(size_t offset, uint8_t val) {
    DCHECK_GE(size(), offset);
    buffer_[offset] = val;
  }

  size_t offset() const { return static_cast<size_t>(pos_ - buffer_); }
  size_t size() const { return static_cast<size_t>(pos_ - buffer_); }
  uint8_t* data() const { return buffer_; }
  uint8_t* begin() const { return buffer_; }
  uint8_t* end() const { return pos_; }

  void EnsureSpace(size_t size) {
    if ((pos_ + size) > end_) {
      size_t new_size = size + (end_ - buffer_) * 2;
      uint8_t* new_buffer = zone_->AllocateArray<uint8_t, Buffer>(new_size);
      memcpy(new_buffer, buffer_, (pos_ - buffer_));
      pos_ = new_buffer + (pos_ - buffer_);
      buffer_ = new_buffer;
      end_ = new_buffer + new_size;
    }
    DCHECK(pos_ + size <= end_);
  }

  void Truncate(size_t size) {
    DCHECK_GE(offset(), size);
    pos_ = buffer_ + size;
  }

  uint8_t** pos_ptr() { return &pos_; }

 private:
  Zone* zone_;
  uint8_t* buffer_;
  uint8_t* pos_;
  uint8_t* end_;
};

class WasmModuleBuilder;

class V8_EXPORT_PRIVATE WasmFunctionBuilder : public ZoneObject {
 public:
  // Building methods.
  void SetSignature(const FunctionSig* sig);
  void SetSignature(ModuleTypeIndex sig_index);
  uint32_t AddLocal(ValueType type);
  void EmitByte(uint8_t b);
  void EmitI32V(int32_t val);
  // Some instructions need an "s33" heaptype immediate.
  void EmitI32V(ModuleTypeIndex index) { EmitI32V(index.index); }
  void EmitU32V(uint32_t val);
  // Some instructions need a u32 type index immediate.
  void EmitU32V(ModuleTypeIndex index) { EmitU32V(index.index); }
  void EmitU64V(uint64_t val);
  void EmitCode(const uint8_t* code, uint32_t code_size);
  void EmitCode(std::initializer_list<const uint8_t> code);
  void Emit(WasmOpcode opcode);
  void EmitWithPrefix(WasmOpcode opcode);
  void EmitGetLocal(uint32_t index);
  void EmitSetLocal(uint32_t index);
  void EmitTeeLocal(uint32_t index);
  void EmitI32Const(int32_t val);
  void EmitI64Const(int64_t val);
  void EmitF32Const(float val);
  void EmitF64Const(double val);
  void EmitS128Const(Simd128 val);
  void EmitWithU8(WasmOpcode opcode, const uint8_t immediate);
  void EmitWithU8U8(WasmOpcode opcode, const uint8_t imm1, const uint8_t imm2);
  void EmitWithI32V(WasmOpcode opcode, int32_t immediate);
  void EmitWithU32V(WasmOpcode opcode, uint32_t immediate);
  void EmitWithU32V(WasmOpcode opcode, ModuleTypeIndex index) {
    EmitWithU32V(opcode, index.index);
  }
  void EmitValueType(ValueType type);
  void EmitDirectCallIndex(uint32_t index);
  void EmitFromInitializerExpression(const WasmInitExpr& init_expr);
  void SetName(base::Vector<const char> name);
  void AddAsmWasmOffset(size_t call_position, size_t to_number_position);
  void SetAsmFunctionStartPosition(size_t function_position);
  void SetCompilationHint(WasmCompilationHintStrategy strategy,
                          WasmCompilationHintTier baseline,
                          WasmCompilationHintTier top_tier);

  size_t GetPosition() const { return body_.size(); }
  void FixupByte(size_t position, uint8_t value) {
    body_.patch_u8(position, value);
  }
  void DeleteCodeAfter(size_t position);

  void WriteSignature(ZoneBuffer* buffer) const;
  void WriteBody(ZoneBuffer* buffer) const;
  void WriteAsmWasmOffsetTable(ZoneBuffer* buffer) const;

  WasmModuleBuilder* builder() const { return builder_; }
  uint32_t func_index() const { return func_index_; }
  ModuleTypeIndex sig_index() const { return signature_index_; }
  inline const FunctionSig* signature() const;

 private:
  explicit WasmFunctionBuilder(WasmModuleBuilder* builder);
  friend class WasmModuleBuilder;
  friend Zone;

  struct DirectCallIndex {
    size_t offset;
    uint32_t direct_index;
  };

  WasmModuleBuilder* builder_;
  LocalDeclEncoder locals_;
  ModuleTypeIndex signature_index_;
  uint32_t func_index_;
  ZoneBuffer body_;
  base::Vector<const char> name_;
  ZoneVector<uint32_t> i32_temps_;
  ZoneVector<uint32_t> i64_temps_;
  ZoneVector<uint32_t> f32_temps_;
  ZoneVector<uint32_t> f64_temps_;
  ZoneVector<DirectCallIndex> direct_calls_;

  // Delta-encoded mapping from wasm bytes to asm.js source positions.
  ZoneBuffer asm_offsets_;
  uint32_t last_asm_byte_offset_ = 0;
  uint32_t last_asm_source_position_ = 0;
  uint32_t asm_func_start_source_position_ = 0;
  uint8_t hint_ = kNoCompilationHint;
};

class V8_EXPORT_PRIVATE WasmModuleBuilder : public ZoneObject {
 public:
  explicit WasmModuleBuilder(Zone* zone);
  WasmModuleBuilder(const WasmModuleBuilder&) = delete;
  WasmModuleBuilder& operator=(const WasmModuleBuilder&) = delete;

  // Static representation of wasm element segment (table initializer). This is
  // different than the version in wasm-module.h.
  class WasmElemSegment {
   public:
    // asm.js gives function indices starting with the first non-imported
    // function.
    enum FunctionIndexingMode {
      kRelativeToImports,
      kRelativeToDeclaredFunctions
    };
    enum Status {
      kStatusActive,      // copied automatically during instantiation.
      kStatusPassive,     // copied explicitly after instantiation.
      kStatusDeclarative  // purely declarative and never copied.
    };
    struct Entry {
      enum Kind { kGlobalGetEntry, kRefFuncEntry, kRefNullEntry } kind;
      uint32_t index;
      Entry(Kind kind, uint32_t index) : kind(kind), index(index) {}
      Entry() : kind(kRefNullEntry), index(0) {}
    };

    // Construct an active segment.
    WasmElemSegment(Zone* zone, ValueType type, uint32_t table_index,
                    WasmInitExpr offset)
        : type(type),
          table_index(table_index),
          offset(offset),
          entries(zone),
          status(kStatusActive) {
      DCHECK(IsValidOffsetKind(offset.kind()));
    }

    // Construct a passive or declarative segment, which has no table
    // index or offset.
    WasmElemSegment(Zone* zone, ValueType type, bool declarative,
                    WasmInitExpr offset)
        : type(type),
          table_index(0),
          offset(offset),
          entries(zone),
          status(declarative ? kStatusDeclarative : kStatusPassive) {
      DCHECK(IsValidOffsetKind(offset.kind()));
    }

    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(WasmElemSegment);

    ValueType type;
    uint32_t table_index;
    WasmInitExpr offset;
    FunctionIndexingMode indexing_mode = kRelativeToImports;
    ZoneVector<Entry> entries;
    Status status;

   private:
    // This ensures no {WasmInitExpr} with subexpressions is used, which would
    // cause a memory leak because those are stored in an std::vector. Such
    // offset would also be mistyped.
    bool IsValidOffsetKind(WasmInitExpr::Operator kind) {
      return kind == WasmInitExpr::kI32Const ||
             kind == WasmInitExpr::kI64Const ||
             kind == WasmInitExpr::kGlobalGet ||
             kind == WasmInitExpr::kRefNullConst;
    }
  };

  // Building methods.
  uint32_t AddImport(base::Vector<const char> name, const FunctionSig* sig,
                     base::Vector<const char> module = {});
  WasmFunctionBuilder* AddFunction(const FunctionSig* sig = nullptr);
  WasmFunctionBuilder* AddFunction(ModuleTypeIndex sig_index);
  uint32_t AddGlobal(ValueType type, bool mutability, WasmInitExpr init);
  uint32_t AddGlobalImport(base::Vector<const char> name, ValueType type,
                           bool mutability,
                           base::Vector<const char> module = {});
  void AddDataSegment(const uint8_t* data, uint32_t size, uint32_t dest);
  void AddPassiveDataSegment(const uint8_t* data, uint32_t size);
  // Add an element segment to this {WasmModuleBuilder}. {segment}'s enties
  // have to be initialized.
  uint32_t AddElementSegment(WasmElemSegment segment);
  // Helper method to create an active segment with one function. Assumes that
  // table segment at {table_index} is typed as funcref.
  void SetIndirectFunction(uint32_t table_index, uint32_t index_in_table,
                           uint32_t direct_function_index,
                           WasmElemSegment::FunctionIndexingMode indexing_mode);
  // Increase the starting size of the table at {table_index} by {count}. Also
  // increases the maximum table size if needed. Returns the former starting
  // size, or the maximum uint32_t value if the maximum table size has been
  // exceeded.
  uint32_t IncreaseTableMinSize(uint32_t table_index, uint32_t count);
  // Adds the signature to the module if it does not already exist.
  ModuleTypeIndex AddSignature(const FunctionSig* sig, bool is_final,
                               ModuleTypeIndex supertype = kNoSuperType);
  // Does not deduplicate function signatures.
  ModuleTypeIndex ForceAddSignature(const FunctionSig* sig, bool is_final,
                                    ModuleTypeIndex supertype = kNoSuperType);
  uint32_t AddTag(const FunctionSig* type);
  ModuleTypeIndex AddStructType(StructType* type, bool is_final,
                                ModuleTypeIndex supertype = kNoSuperType);
  ModuleTypeIndex AddArrayType(ArrayType* type, bool is_final,
                               ModuleTypeIndex supertype = kNoSuperType);
  uint32_t AddTable(ValueType type, uint32_t min_size);
  uint32_t AddTable(ValueType type, uint32_t min_size, uint32_t max_size,
                    AddressType address_type = AddressType::kI32);
  uint32_t AddTable(ValueType type, uint32_t min_size, uint32_t max_size,
                    WasmInitExpr init,
                    AddressType address_type = AddressType::kI32);
  uint32_t AddMemory(uint32_t min_pages);
  uint32_t AddMemory(uint32_t min_pages, uint32_t max_pages);
  uint32_t AddMemory64(uint32_t min_pages);
  uint32_t AddMemory64(uint32_t min_pages, uint32_t max_pages);
  void MarkStartFunction(WasmFunctionBuilder* builder);
  void AddExport(base::Vector<const char> name, ImportExportKindCode kind,
                 uint32_t index);
  void AddExport(base::Vector<const char> name, WasmFunctionBuilder* builder) {
    AddExport(name, kExternalFunction, builder->func_index());
  }
  uint32_t AddExportedGlobal(ValueType type, bool mutability, WasmInitExpr init,
                             base::Vector<const char> name);
  void ExportImportedFunction(base::Vector<const char> name, int import_index);

  void StartRecursiveTypeGroup() {
    DCHECK_EQ(current_recursive_group_start_, -1);
    current_recursive_group_start_ = static_cast<int>(types_.size());
  }

  void EndRecursiveTypeGroup() {
    // Make sure we are in a recursive group.
    DCHECK_NE(current_recursive_group_start_, -1);
    // Make sure the current recursive group has at least one element.
    DCHECK_GT(static_cast<int>(types_.size()), current_recursive_group_start_);
    recursive_groups_.emplace(
        current_recursive_group_start_,
        static_cast<uint32_t>(types_.size()) - current_recursive_group_start_);
    current_recursive_group_start_ = -1;
  }

  void AddRecursiveTypeGroup(uint32_t start, uint32_t size) {
    recursive_groups_.emplace(start, size);
  }

  // Writing methods.
  void WriteTo(ZoneBuffer* buffer) const;
  void WriteAsmJsOffsetTable(ZoneBuffer* buffer) const;

  Zone* zone() { return zone_; }

  ValueType GetTableType(uint32_t index) { return tables_[index].type; }

  bool IsSignature(uint32_t index) {
    return types_[index].kind == TypeDefinition::kFunction;
  }
  bool IsSignature(ModuleTypeIndex index) { return IsSignature(index.index); }

  const FunctionSig* GetSignature(uint32_t index) {
    DCHECK(types_[index].kind == TypeDefinition::kFunction);
    return types_[index].function_sig;
  }
  const FunctionSig* GetSignature(ModuleTypeIndex index) {
    return GetSignature(index.index);
  }

  bool IsStructType(uint32_t index) {
    return types_[index].kind == TypeDefinition::kStruct;
  }
  bool IsStructType(ModuleTypeIndex index) { return IsStructType(index.index); }
  const StructType* GetStructType(uint32_t index) {
    return types_[index].struct_type;
  }
  const StructType* GetStructType(ModuleTypeIndex index) {
    return GetStructType(index.index);
  }

  bool IsArrayType(uint32_t index) {
    return types_[index].kind == TypeDefinition::kArray;
  }
  bool IsArrayType(ModuleTypeIndex index) { return IsArrayType(index.index); }
  const ArrayType* GetArrayType(uint32_t index) {
    return types_[index].array_type;
  }
  const ArrayType* GetArrayType(ModuleTypeIndex index) {
    return GetArrayType(index.index);
  }

  ModuleTypeIndex GetSuperType(uint32_t index) {
    return types_[index].supertype;
  }

  WasmFunctionBuilder* GetFunction(uint32_t index) { return functions_[index]; }
  int NumTags() { return static_cast<int>(tags_.size()); }

  int NumTypes() { return static_cast<int>(types_.size()); }

  int NumTables() { return static_cast<int>(tables_.size()); }

  int NumMemories() { return static_cast<int>(memories_.size()); }

  int NumGlobals() { return static_cast<int>(globals_.size()); }

  int NumImportedFunctions() {
    return static_cast<int>(function_imports_.size());
  }
  int NumDeclaredFunctions() { return static_cast<int>(functions_.size()); }

  int NumDataSegments() { return static_cast<int>(data_segments_.size()); }

  bool IsMemory64(uint32_t index) { return memories_[index].is_memory64(); }

  bool IsTable64(uint32_t index) { return tables_[index].is_table64(); }

  const FunctionSig* GetTagType(int index) {
    return types_[tags_[index].index].function_sig;
  }

  ValueType GetGlobalType(uint32_t index) const { return globals_[index].type; }

  bool IsMutableGlobal(uint32_t index) const {
    return globals_[index].mutability;
  }

 private:
  struct WasmFunctionImport {
    base::Vector<const char> module;
    base::Vector<const char> name;
    ModuleTypeIndex sig_index;
  };

  struct WasmGlobalImport {
    base::Vector<const char> module;
    base::Vector<const char> name;
    // TODO(manoskouk): Extend to full value type.
    ValueTypeCode type_code;
    bool mutability;
  };

  struct WasmExport {
    base::Vector<const char> name;
    ImportExportKindCode kind;
    int index;  // Can be negative for re-exported imports.
  };

  struct WasmGlobal {
    ValueType type;
    bool mutability;
    WasmInitExpr init;
  };

  struct WasmTable {
    ValueType type;
    uint32_t min_size;
    uint32_t max_size = 0;
    bool has_maximum = false;
    bool is_shared = false;
    AddressType address_type = AddressType::kI32;
    std::optional<WasmInitExpr> init = {};

    bool is_table64() const { return address_type == AddressType::kI64; }
  };

  struct WasmMemory {
    uint32_t min_pages;
    uint32_t max_pages = 0;
    bool has_max_pages = false;
    bool is_shared = false;
    AddressType address_type = AddressType::kI32;

    bool is_memory64() const { return address_type == AddressType::kI64; }
  };

  struct WasmDataSegment {
    ZoneVector<uint8_t> data;
    uint32_t dest;
    bool is_active = true;
  };

  friend class WasmFunctionBuilder;
  Zone* zone_;
  ZoneVector<TypeDefinition> types_;
  ZoneVector<WasmFunctionImport> function_imports_;
  ZoneVector<WasmGlobalImport> global_imports_;
  ZoneVector<WasmExport> exports_;
  ZoneVector<WasmFunctionBuilder*> functions_;
  ZoneVector<WasmTable> tables_;
  ZoneVector<WasmMemory> memories_;
  ZoneVector<WasmDataSegment> data_segments_;
  ZoneVector<WasmElemSegment> element_segments_;
  ZoneVector<WasmGlobal> globals_;
  ZoneVector<ModuleTypeIndex> tags_;
  ZoneUnorderedMap<FunctionSig, ModuleTypeIndex> signature_map_;
  int current_recursive_group_start_;
  // first index -> size
  ZoneUnorderedMap<uint32_t, uint32_t> recursive_groups_;
  int start_function_index_;
#if DEBUG
  // Once AddExportedImport is called, no more imports can be added.
  bool adding_imports_allowed_ = true;
#endif
};

const FunctionSig* WasmFunctionBuilder::signature() const {
  return builder_->types_[signature_index_.index].function_sig;
}

}  // namespace v8::internal::wasm

#endif  // V8_WASM_WASM_MODULE_BUILDER_H_
```