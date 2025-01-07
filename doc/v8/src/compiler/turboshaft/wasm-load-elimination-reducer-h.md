Response:
The user wants a summary of the C++ header file `v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h`. I need to extract the core functionality of this code, considering the provided hints about Torque, Javascript, and potential programming errors.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the Core Purpose:** The filename `wasm-load-elimination-reducer.h` immediately suggests its primary function: eliminating redundant load operations within WebAssembly code during the Turboshaft compilation phase. The "reducer" part indicates it's a compiler optimization pass.

2. **Scan for Key Data Structures:**  Look for classes and structs that define the core logic. `WasmMemoryAddress`, `KeyData`, `WasmMemoryContentTable`, and `WasmLoadEliminationAnalyzer` are prominent. These likely represent how memory access and load operations are tracked and analyzed.

3. **Analyze `WasmMemoryContentTable`:** This class seems central to tracking memory contents.
    * It stores information about memory locations (`WasmMemoryAddress`).
    * It uses a snapshot table (`ChangeTrackingSnapshotTable`) which suggests it maintains different states of memory during analysis, likely for handling control flow and loops.
    * The methods `Find`, `Insert`, and `Invalidate` are crucial for the load elimination logic. They determine if a load can be replaced by a previously seen value and update the table when memory is written to.
    * The concept of "non-aliasing objects" is introduced, indicating an attempt to reason about memory independence.

4. **Analyze `WasmLoadEliminationAnalyzer`:** This class orchestrates the load elimination process.
    * It uses the `WasmMemoryContentTable` to track memory.
    * It iterates through the blocks of the control flow graph.
    * It has methods for processing different Wasm operations (`ProcessStructGet`, `ProcessStructSet`, etc.).
    * The logic around loops (`LoopFinder`, revisiting blocks) is important for handling control flow.
    * The `replacements_` member suggests it keeps track of which load operations can be replaced.

5. **Consider the Hints:**
    * **`.tq` extension:** The code explicitly checks if WebAssembly is enabled (`#if !V8_ENABLE_WEBASSEMBLY`). Since the provided code is C++ and not Torque, this hint highlights a *potential* scenario (if the file had a different extension). I need to mention this but emphasize it's not the case here.
    * **Javascript Relationship:** Load elimination is an optimization that directly impacts the performance of WebAssembly, which is often used by JavaScript applications. I can provide a simple JavaScript example where WebAssembly is used and explain how this optimization improves its execution.
    * **Code Logic Inference:** The `Find` and `Insert` methods in `WasmMemoryContentTable` suggest a caching mechanism. If a `StructGet` operation with the same base, offset, and type is encountered again, the previously computed value can be reused. I can provide a simplified example of this.
    * **Common Programming Errors:**  Incorrectly assuming memory isn't modified between loads or not considering the mutability of memory locations are common errors this optimization helps with. I can illustrate this with a simple C++-like example (since the code is in that domain).

6. **Structure the Summary:** Organize the findings into logical sections:
    * Overall purpose.
    * Key components and their functions.
    * Explanation of how it relates to JavaScript.
    * Illustrative examples for code logic and potential errors.

7. **Refine and Elaborate:**  Add details about the snapshot mechanism, the handling of different Wasm operations, and the role of alias analysis. Ensure the language is clear and concise.

By following these steps, I can generate a comprehensive and accurate summary of the provided C++ header file.
这是 V8 引擎中 Turboshaft 编译管道的一个头文件，定义了一个用于 WebAssembly 代码的加载消除（Load Elimination）优化的组件。

**功能归纳:**

`v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h` 定义了 `WasmLoadEliminationAnalyzer` 和 `WasmLoadEliminationReducer` 两个主要类，用于在 Turboshaft 编译 WebAssembly 代码时执行加载消除优化。其核心功能是：

1. **跟踪 WebAssembly 内存内容:**  `WasmMemoryContentTable` 负责维护一个抽象的 WebAssembly 内存视图，记录了已知内存位置的值。它能跟踪特定内存地址（由基地址、偏移量、类型和大小定义）上存储的值。
2. **识别冗余的加载操作:**  通过分析代码中的 `StructGetOp`（访问结构体字段）、`ArrayLengthOp`（获取数组长度）等类似加载的操作，检查是否已经存在对相同内存位置的先前加载，并且中间没有可能修改该内存位置的操作。
3. **消除冗余加载:** 如果发现冗余的加载操作，`WasmLoadEliminationReducer` 会将后续的加载操作替换为之前加载的结果，从而避免重复的内存访问，提高代码执行效率。
4. **处理别名分析:** 代码中使用了 `non_aliasing_objects_` 来跟踪已知非别名的对象。这有助于更精确地判断哪些操作会修改内存，从而更安全地进行加载消除。
5. **处理控制流和循环:** `AnalyzerIterator` 和循环处理逻辑确保了加载消除分析能够正确处理控制流分支和循环结构，避免在跨越可能修改内存的操作时进行错误的优化。
6. **处理特定的 WebAssembly 操作:** 代码针对不同的 WebAssembly 操作（如 `StructGet`, `StructSet`, `ArrayLength`, `WasmAllocateArray` 等）有专门的处理逻辑，以确保加载消除的正确性。

**关于文件扩展名和 Torque:**

你提供的代码是 C++ 头文件，以 `.h` 结尾。  如果 `v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内部函数的领域特定语言。  当前提供的代码不是 Torque。

**与 Javascript 的关系:**

WebAssembly 旨在成为 JavaScript 的补充，提供接近原生性能的执行环境。  JavaScript 代码可以加载和执行 WebAssembly 模块。 `WasmLoadEliminationReducer` 的优化直接影响 WebAssembly 代码的性能，从而间接提升了运行在 JavaScript 环境中的 WebAssembly 代码的执行效率。

**Javascript 示例:**

```javascript
// 假设有一个 WebAssembly 模块，其中包含一个访问结构体字段的函数

// 模拟 WebAssembly 模块 (简化)
const wasmModule = {
  exports: {
    get_field: (ptr) => {
      // 模拟访问内存 ptr 指向的结构体的某个字段
      const fieldOffset = 8; // 假设字段偏移量为 8
      const fieldValue = getMemoryValue(ptr + fieldOffset);
      return fieldValue;
    },
    set_field: (ptr, value) => {
      const fieldOffset = 8;
      setMemoryValue(ptr + fieldOffset, value);
    }
  }
};

let memoryData = new Uint8Array(1024); // 模拟内存
function getMemoryValue(address) {
  return memoryData[address];
}
function setMemoryValue(address, value) {
  memoryData[address] = value;
}

let structPtr = 100; // 结构体在内存中的地址

// 第一次加载字段值
let value1 = wasmModule.exports.get_field(structPtr);
console.log("First load:", value1);

// 如果中间没有 set_field 操作，第二次加载应该是相同的
let value2 = wasmModule.exports.get_field(structPtr);
console.log("Second load:", value2);

// 进行修改操作
wasmModule.exports.set_field(structPtr, 5);

// 修改后再次加载，值应该不同
let value3 = wasmModule.exports.get_field(structPtr);
console.log("Third load after set:", value3);
```

在这个例子中，`WasmLoadEliminationReducer` 的作用是识别出 `value2` 的加载操作是冗余的，因为它与 `value1` 加载的是相同的内存位置，并且在两次加载之间没有 `set_field` 操作修改该位置。优化器会将 `value2` 直接赋值为 `value1` 的值，避免再次访问内存。

**代码逻辑推理 - 假设输入与输出:**

**假设输入:**  一段包含以下 WebAssembly 操作序列的 Turboshaft 图：

1. `Allocate { type: MyStruct } -> object1`  (分配一个 `MyStruct` 类型的对象)
2. `StructGet { object: object1, field_index: 0, type: MyStruct } -> value1` (获取 `object1` 的第 0 个字段的值)
3. `StructGet { object: object1, field_index: 0, type: MyStruct } -> value2` (再次获取 `object1` 的第 0 个字段的值)

**预期输出:** `WasmLoadEliminationReducer` 会将第二个 `StructGet` 操作（产生 `value2`）替换为对第一个 `StructGet` 操作的结果 (`value1`) 的引用。  在优化后的图中，`value2` 将直接等于 `value1`。

**涉及用户常见的编程错误:**

加载消除优化可以帮助减轻某些编程错误带来的性能影响，但它本身并不能修复错误。 一些相关的常见编程错误包括：

1. **不必要的重复读取:**  程序员可能在短时间内多次读取相同的内存位置，而没有意识到这些读取是冗余的。加载消除可以自动优化这种情况。

   **错误示例 (类似 C++):**

   ```c++
   int* ptr = get_some_pointer();
   int value1 = *ptr;
   // ... 一些不涉及 ptr 指向内存修改的代码 ...
   int value2 = *ptr; // 这是一个可以被消除的冗余读取
   ```

2. **在循环中重复加载不变的值:**  在循环体内，如果某个值的加载结果在循环的多次迭代中都不会改变，那么重复加载是低效的。

   **错误示例 (类似 C++):**

   ```c++
   struct MyData { int field; /* ... */ };
   MyData* data = get_data_pointer();
   for (int i = 0; i < 100; ++i) {
       int fieldValue = data->field; // 如果 data 在循环内不改变，这是可以优化的
       // ... 使用 fieldValue 的代码 ...
   }
   ```

**总结:**

`v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h` 定义了 V8 中用于优化 WebAssembly 代码加载操作的关键组件。它通过跟踪内存内容和识别冗余加载来提升 WebAssembly 代码的执行效率，这对于运行在 JavaScript 环境中的 WebAssembly 应用至关重要。 该组件能够处理复杂的控制流和多种 WebAssembly 操作，并利用别名分析来提高优化的安全性。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/wasm-load-elimination-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_TURBOSHAFT_WASM_LOAD_ELIMINATION_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_WASM_LOAD_ELIMINATION_REDUCER_H_

#include "src/base/doubly-threaded-list.h"
#include "src/compiler/turboshaft/analyzer-iterator.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/loop-finder.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/snapshot-table-opindex.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/zone/zone.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

// WLE is short for Wasm Load Elimination.
// We need the namespace because we reuse class names below that also exist
// in the LateLoadEliminationReducer, and in the same namespace that'd be
// an ODR violation, i.e. Undefined Behavior.
// TODO(jkummerow): Refactor the two Load Elimination implementations to
// reuse commonalities.
namespace wle {

// We model array length and string canonicalization as fields at negative
// indices.
static constexpr int kArrayLengthFieldIndex = -1;
static constexpr int kStringPrepareForGetCodeunitIndex = -2;
static constexpr int kStringAsWtf16Index = -3;
static constexpr int kAnyConvertExternIndex = -4;
static constexpr int kAssertNotNullIndex = -5;

// All "load-like" special cases use the same fake size and type. The specific
// values we use don't matter; for accurate alias analysis, the type should
// be "unrelated" to any struct type.
static constexpr wasm::ModuleTypeIndex kLoadLikeType{wasm::HeapType::kExtern};
static constexpr int kLoadLikeSize = 4;  // Chosen by fair dice roll.

struct WasmMemoryAddress {
  OpIndex base;
  int32_t offset;
  wasm::ModuleTypeIndex type_index;
  uint8_t size;
  bool mutability;

  bool operator==(const WasmMemoryAddress& other) const {
    return base == other.base && offset == other.offset &&
           type_index == other.type_index && size == other.size &&
           mutability == other.mutability;
  }
};

inline size_t hash_value(WasmMemoryAddress const& mem) {
  return fast_hash_combine(mem.base, mem.offset, mem.type_index, mem.size,
                           mem.mutability);
}

struct KeyData {
  using Key = SnapshotTableKey<OpIndex, KeyData>;
  WasmMemoryAddress mem = {};
  // Pointers to the previous and the next Keys at the same base.
  Key* prev_same_base = nullptr;
  Key next_same_base = {};
  // Pointers to either the next/previous Keys at the same offset.
  Key* prev_same_offset = nullptr;
  Key next_same_offset = {};
};

struct OffsetListTraits {
  using T = SnapshotTable<OpIndex, KeyData>::Key;
  static T** prev(T t) { return &(t.data().prev_same_offset); }
  static T* next(T t) { return &(t.data().next_same_offset); }
  static bool non_empty(T t) { return t.valid(); }
};

struct BaseListTraits {
  using T = SnapshotTable<OpIndex, KeyData>::Key;
  static T** prev(T t) { return &(t.data().prev_same_base); }
  static T* next(T t) { return &(t.data().next_same_base); }
  static bool non_empty(T t) { return t.valid(); }
};

struct BaseData {
  using Key = SnapshotTable<OpIndex, KeyData>::Key;
  // List of every value at this base that has an offset rather than an index.
  v8::base::DoublyThreadedList<Key, BaseListTraits> with_offsets;
};

class WasmMemoryContentTable
    : public ChangeTrackingSnapshotTable<WasmMemoryContentTable, OpIndex,
                                         KeyData> {
 public:
  using MemoryAddress = WasmMemoryAddress;

  explicit WasmMemoryContentTable(
      PipelineData* data, Zone* zone,
      SparseOpIndexSnapshotTable<bool>& non_aliasing_objects,
      FixedOpIndexSidetable<OpIndex>& replacements, Graph& graph)
      : ChangeTrackingSnapshotTable(zone),
        non_aliasing_objects_(non_aliasing_objects),
        replacements_(replacements),
        data_(data),
        graph_(graph),
        all_keys_(zone),
        base_keys_(zone),
        offset_keys_(zone) {}

  void OnNewKey(Key key, OpIndex value) {
    if (value.valid()) {
      AddKeyInBaseOffsetMaps(key);
    }
  }

  void OnValueChange(Key key, OpIndex old_value, OpIndex new_value) {
    DCHECK_NE(old_value, new_value);
    if (old_value.valid() && !new_value.valid()) {
      RemoveKeyFromBaseOffsetMaps(key);
    } else if (new_value.valid() && !old_value.valid()) {
      AddKeyInBaseOffsetMaps(key);
    } else {
      DCHECK_EQ(new_value.valid(), old_value.valid());
    }
  }

  bool TypesUnrelated(wasm::ModuleTypeIndex type1,
                      wasm::ModuleTypeIndex type2) {
    return wasm::TypesUnrelated(wasm::ValueType::Ref(type1),
                                wasm::ValueType::Ref(type2), module_, module_);
  }

  void Invalidate(const StructSetOp& set) {
    // This is like LateLoadElimination's {InvalidateAtOffset}, but based
    // on Wasm types instead of tracked JS maps.
    int offset = field_offset(set.type, set.field_index);
    auto offset_keys = offset_keys_.find(offset);
    if (offset_keys == offset_keys_.end()) return;
    for (auto it = offset_keys->second.begin();
         it != offset_keys->second.end();) {
      Key key = *it;
      DCHECK_EQ(offset, key.data().mem.offset);
      OpIndex base = key.data().mem.base;

      // If the base is guaranteed non-aliasing, we don't need to clear any
      // other entries. Any existing entry for this base will be overwritten
      // by {Insert(set)}.
      if (non_aliasing_objects_.Get(base)) {
        ++it;
        continue;
      }

      if (TypesUnrelated(set.type_index, key.data().mem.type_index)) {
        ++it;
        continue;
      }

      it = offset_keys->second.RemoveAt(it);
      Set(key, OpIndex::Invalid());
    }
  }

  // Invalidates all Keys that are not known as non-aliasing.
  enum class EntriesWithOffsets { kInvalidate, kKeep };
  template <EntriesWithOffsets offsets = EntriesWithOffsets::kInvalidate>
  void InvalidateMaybeAliasing() {
    // We find current active keys through {base_keys_} so that we can bail out
    // for whole buckets non-aliasing buckets (if we had gone through
    // {offset_keys_} instead, then for each key we would've had to check
    // whether it was non-aliasing or not).
    for (auto& base_keys : base_keys_) {
      OpIndex base = base_keys.first;
      if (non_aliasing_objects_.Get(base)) continue;
      if constexpr (offsets == EntriesWithOffsets::kInvalidate) {
        for (auto it = base_keys.second.with_offsets.begin();
             it != base_keys.second.with_offsets.end();) {
          Key key = *it;
          if (key.data().mem.mutability == false) {
            ++it;
            continue;
          }
          // It's important to remove with RemoveAt before Setting the key to
          // invalid, otherwise OnKeyChange will remove {key} from {base_keys},
          // which will invalidate {it}.
          it = base_keys.second.with_offsets.RemoveAt(it);
          Set(key, OpIndex::Invalid());
        }
      }
    }
  }

  // TODO(jkummerow): Move this to the WasmStruct class?
  int field_offset(const wasm::StructType* type, int field_index) {
    return WasmStruct::kHeaderSize + type->field_offset(field_index);
  }

  OpIndex Find(const StructGetOp& get) {
    int32_t offset = field_offset(get.type, get.field_index);
    uint8_t size = get.type->field(get.field_index).value_kind_size();
    bool mutability = get.type->mutability(get.field_index);
    return FindImpl(ResolveBase(get.object()), offset, get.type_index, size,
                    mutability);
  }

  bool HasValueWithIncorrectMutability(const StructSetOp& set) {
    int32_t offset = field_offset(set.type, set.field_index);
    uint8_t size = set.type->field(set.field_index).value_kind_size();
    bool mutability = set.type->mutability(set.field_index);
    WasmMemoryAddress mem{ResolveBase(set.object()), offset, set.type_index,
                          size, !mutability};
    return all_keys_.find(mem) != all_keys_.end();
  }

  OpIndex FindLoadLike(OpIndex op_idx, int offset_sentinel) {
    static constexpr bool mutability = false;
    return FindImpl(ResolveBase(op_idx), offset_sentinel, kLoadLikeType,
                    kLoadLikeSize, mutability);
  }

  OpIndex FindImpl(OpIndex object, int offset, wasm::ModuleTypeIndex type_index,
                   uint8_t size, bool mutability,
                   OptionalOpIndex index = OptionalOpIndex::Nullopt()) {
    WasmMemoryAddress mem{object, offset, type_index, size, mutability};
    auto key = all_keys_.find(mem);
    if (key == all_keys_.end()) return OpIndex::Invalid();
    return Get(key->second);
  }

  void Insert(const StructSetOp& set) {
    OpIndex base = ResolveBase(set.object());
    int32_t offset = field_offset(set.type, set.field_index);
    uint8_t size = set.type->field(set.field_index).value_kind_size();
    bool mutability = set.type->mutability(set.field_index);
    Insert(base, offset, set.type_index, size, mutability, set.value());
  }

  void Insert(const StructGetOp& get, OpIndex get_idx) {
    OpIndex base = ResolveBase(get.object());
    int32_t offset = field_offset(get.type, get.field_index);
    uint8_t size = get.type->field(get.field_index).value_kind_size();
    bool mutability = get.type->mutability(get.field_index);
    Insert(base, offset, get.type_index, size, mutability, get_idx);
  }

  void InsertLoadLike(OpIndex base_idx, int offset_sentinel,
                      OpIndex value_idx) {
    OpIndex base = ResolveBase(base_idx);
    static constexpr bool mutability = false;
    Insert(base, offset_sentinel, kLoadLikeType, kLoadLikeSize, mutability,
           value_idx);
  }

#ifdef DEBUG
  void Print() {
    std::cout << "WasmMemoryContentTable:\n";
    for (const auto& base_keys : base_keys_) {
      for (Key key : base_keys.second.with_offsets) {
        std::cout << "  * " << key.data().mem.base << " - "
                  << key.data().mem.offset << " ==> " << Get(key) << "\n";
      }
    }
  }
#endif  // DEBUG

 private:
  void Insert(OpIndex base, int32_t offset, wasm::ModuleTypeIndex type_index,
              uint8_t size, bool mutability, OpIndex value) {
    DCHECK_EQ(base, ResolveBase(base));

    WasmMemoryAddress mem{base, offset, type_index, size, mutability};
    auto existing_key = all_keys_.find(mem);
    if (existing_key != all_keys_.end()) {
      if (mutability) {
        Set(existing_key->second, value);
      } else {
        SetNoNotify(existing_key->second, value);
      }
      return;
    }

    // Creating a new key.
    Key key = NewKey({mem});
    all_keys_.insert({mem, key});
    if (mutability) {
      Set(key, value);
    } else {
      // Call `SetNoNotify` to avoid calls to `OnNewKey` and `OnValueChanged`.
      SetNoNotify(key, value);
    }
  }

 public:
  OpIndex ResolveBase(OpIndex base) {
    while (true) {
      if (replacements_[base] != OpIndex::Invalid()) {
        base = replacements_[base];
        continue;
      }
      Operation& op = graph_.Get(base);
      if (AssertNotNullOp* check = op.TryCast<AssertNotNullOp>()) {
        base = check->object();
        continue;
      }
      if (WasmTypeCastOp* cast = op.TryCast<WasmTypeCastOp>()) {
        base = cast->object();
        continue;
      }
      break;  // Terminate if nothing happened.
    }
    return base;
  }

  void AddKeyInBaseOffsetMaps(Key key) {
    // Inserting in {base_keys_}.
    OpIndex base = key.data().mem.base;
    auto base_keys = base_keys_.find(base);
    if (base_keys != base_keys_.end()) {
      base_keys->second.with_offsets.PushFront(key);
    } else {
      BaseData data;
      data.with_offsets.PushFront(key);
      base_keys_.insert({base, std::move(data)});
    }

    // Inserting in {offset_keys_}.
    int offset = key.data().mem.offset;
    auto offset_keys = offset_keys_.find(offset);
    if (offset_keys != offset_keys_.end()) {
      offset_keys->second.PushFront(key);
    } else {
      v8::base::DoublyThreadedList<Key, OffsetListTraits> list;
      list.PushFront(key);
      offset_keys_.insert({offset, std::move(list)});
    }
  }

  void RemoveKeyFromBaseOffsetMaps(Key key) {
    // Removing from {base_keys_}.
    v8::base::DoublyThreadedList<Key, BaseListTraits>::Remove(key);
    v8::base::DoublyThreadedList<Key, OffsetListTraits>::Remove(key);
  }

  SparseOpIndexSnapshotTable<bool>& non_aliasing_objects_;
  FixedOpIndexSidetable<OpIndex>& replacements_;

  PipelineData* data_;
  Graph& graph_;

  const wasm::WasmModule* module_ = data_->wasm_module();

  // TODO(dmercadier): consider using a faster datastructure than
  // ZoneUnorderedMap for {all_keys_}, {base_keys_} and {offset_keys_}.

  // A map containing all of the keys, for fast lookup of a specific
  // MemoryAddress.
  ZoneUnorderedMap<WasmMemoryAddress, Key> all_keys_;
  // Map from base OpIndex to keys associated with this base.
  ZoneUnorderedMap<OpIndex, BaseData> base_keys_;
  // Map from offsets to keys associated with this offset.
  ZoneUnorderedMap<int, v8::base::DoublyThreadedList<Key, OffsetListTraits>>
      offset_keys_;
};

}  // namespace wle

class WasmLoadEliminationAnalyzer {
 public:
  using AliasTable = SparseOpIndexSnapshotTable<bool>;
  using AliasKey = AliasTable::Key;
  using AliasSnapshot = AliasTable::Snapshot;

  using MemoryKey = wle::WasmMemoryContentTable::Key;
  using MemorySnapshot = wle::WasmMemoryContentTable::Snapshot;

  WasmLoadEliminationAnalyzer(PipelineData* data, Graph& graph,
                              Zone* phase_zone)
      : graph_(graph),
        phase_zone_(phase_zone),
        replacements_(graph.op_id_count(), phase_zone, &graph),
        non_aliasing_objects_(phase_zone),
        memory_(data, phase_zone, non_aliasing_objects_, replacements_, graph_),
        block_to_snapshot_mapping_(graph.block_count(), phase_zone),
        predecessor_alias_snapshots_(phase_zone),
        predecessor_memory_snapshots_(phase_zone) {}

  void Run() {
    LoopFinder loop_finder(phase_zone_, &graph_);
    AnalyzerIterator iterator(phase_zone_, graph_, loop_finder);

    bool compute_start_snapshot = true;
    while (iterator.HasNext()) {
      const Block* block = iterator.Next();

      ProcessBlock(*block, compute_start_snapshot);
      compute_start_snapshot = true;

      // Consider re-processing for loops.
      if (const GotoOp* last = block->LastOperation(graph_).TryCast<GotoOp>()) {
        if (last->destination->IsLoop() &&
            last->destination->LastPredecessor() == block) {
          const Block* loop_header = last->destination;
          // {block} is the backedge of a loop. We recompute the loop header's
          // initial snapshots, and if they differ from its original snapshot,
          // then we revisit the loop.
          if (BeginBlock<true>(loop_header)) {
            // We set the snapshot of the loop's 1st predecessor to the newly
            // computed snapshot. It's not quite correct, but this predecessor
            // is guaranteed to end with a Goto, and we are now visiting the
            // loop, which means that we don't really care about this
            // predecessor anymore.
            // The reason for saving this snapshot is to prevent infinite
            // looping, since the next time we reach this point, the backedge
            // snapshot could still invalidate things from the forward edge
            // snapshot. By restricting the forward edge snapshot, we prevent
            // this.
            const Block* loop_1st_pred =
                loop_header->LastPredecessor()->NeighboringPredecessor();
            FinishBlock(loop_1st_pred);
            // And we start a new fresh snapshot from this predecessor.
            auto pred_snapshots =
                block_to_snapshot_mapping_[loop_1st_pred->index()];
            non_aliasing_objects_.StartNewSnapshot(
                pred_snapshots->alias_snapshot);
            memory_.StartNewSnapshot(pred_snapshots->memory_snapshot);

            iterator.MarkLoopForRevisit();
            compute_start_snapshot = false;
          } else {
            SealAndDiscard();
          }
        }
      }
    }
  }

  OpIndex Replacement(OpIndex index) { return replacements_[index]; }

 private:
  void ProcessBlock(const Block& block, bool compute_start_snapshot);
  void ProcessStructGet(OpIndex op_idx, const StructGetOp& op);
  void ProcessStructSet(OpIndex op_idx, const StructSetOp& op);
  void ProcessArrayLength(OpIndex op_idx, const ArrayLengthOp& op);
  void ProcessWasmAllocateArray(OpIndex op_idx, const WasmAllocateArrayOp& op);
  void ProcessStringAsWtf16(OpIndex op_idx, const StringAsWtf16Op& op);
  void ProcessStringPrepareForGetCodeUnit(
      OpIndex op_idx, const StringPrepareForGetCodeUnitOp& op);
  void ProcessAnyConvertExtern(OpIndex op_idx, const AnyConvertExternOp& op);
  void ProcessAssertNotNull(OpIndex op_idx, const AssertNotNullOp& op);
  void ProcessAllocate(OpIndex op_idx, const AllocateOp& op);
  void ProcessCall(OpIndex op_idx, const CallOp& op);
  void ProcessPhi(OpIndex op_idx, const PhiOp& op);

  void DcheckWordBinop(OpIndex op_idx, const WordBinopOp& binop);

  // BeginBlock initializes the various SnapshotTables for {block}, and returns
  // true if {block} is a loop that should be revisited.
  template <bool for_loop_revisit = false>
  bool BeginBlock(const Block* block);
  void FinishBlock(const Block* block);
  // Seals the current snapshot, but discards it. This is used when considering
  // whether a loop should be revisited or not: we recompute the loop header's
  // snapshots, and then revisit the loop if the snapshots contain
  // modifications. If the snapshots are unchanged, we discard them and don't
  // revisit the loop.
  void SealAndDiscard();
  void StoreLoopSnapshotInForwardPredecessor(const Block& loop_header);

  // Returns true if the loop's backedge already has snapshot data (meaning that
  // it was already visited).
  bool BackedgeHasSnapshot(const Block& loop_header) const;

  void InvalidateAllNonAliasingInputs(const Operation& op);
  void InvalidateIfAlias(OpIndex op_idx);

  Graph& graph_;
  Zone* phase_zone_;

  FixedOpIndexSidetable<OpIndex> replacements_;

  AliasTable non_aliasing_objects_;
  wle::WasmMemoryContentTable memory_;

  struct Snapshot {
    AliasSnapshot alias_snapshot;
    MemorySnapshot memory_snapshot;
  };
  FixedBlockSidetable<std::optional<Snapshot>> block_to_snapshot_mapping_;

  // {predecessor_alias_napshots_}, {predecessor_maps_snapshots_} and
  // {predecessor_memory_snapshots_} are used as temporary vectors when starting
  // to process a block. We store them as members to avoid reallocation.
  ZoneVector<AliasSnapshot> predecessor_alias_snapshots_;
  ZoneVector<MemorySnapshot> predecessor_memory_snapshots_;
};

template <class Next>
class WasmLoadEliminationReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(WasmLoadElimination)

  void Analyze() {
    if (v8_flags.turboshaft_wasm_load_elimination) {
      DCHECK(AllowHandleDereference::IsAllowed());
      analyzer_.Run();
    }
    Next::Analyze();
  }

#define EMIT_OP(Name)                                                          \
  OpIndex REDUCE_INPUT_GRAPH(Name)(OpIndex ig_index, const Name##Op& op) {     \
    if (v8_flags.turboshaft_wasm_load_elimination) {                           \
      OpIndex ig_replacement_index = analyzer_.Replacement(ig_index);          \
      if (ig_replacement_index.valid()) {                                      \
        OpIndex replacement = Asm().MapToNewGraph(ig_replacement_index);       \
        return replacement;                                                    \
      }                                                                        \
    }                                                                          \
    return Next::ReduceInputGraph##Name(ig_index, op);                         \
  }

  EMIT_OP(StructGet)
  EMIT_OP(ArrayLength)
  EMIT_OP(StringAsWtf16)
  EMIT_OP(StringPrepareForGetCodeUnit)
  EMIT_OP(AnyConvertExtern)

  OpIndex REDUCE_INPUT_GRAPH(StructSet)(OpIndex ig_index,
                                        const StructSetOp& op) {
    if (v8_flags.turboshaft_wasm_load_elimination) {
      OpIndex ig_replacement_index = analyzer_.Replacement(ig_index);
      if (ig_replacement_index.valid()) {
        // For struct.set, "replace with itself" is a sentinel for
        // "unreachable", and those are the only replacements we schedule for
        // this operation.
        DCHECK_EQ(ig_replacement_index, ig_index);
        __ Unreachable();
        return OpIndex::Invalid();
      }
    }
    return Next::ReduceInputGraphStructSet(ig_index, op);
  }

 private:
  WasmLoadEliminationAnalyzer analyzer_{
      Asm().data(), Asm().modifiable_input_graph(), Asm().phase_zone()};
};

void WasmLoadEliminationAnalyzer::ProcessBlock(const Block& block,
                                               bool compute_start_snapshot) {
  if (compute_start_snapshot) {
    BeginBlock(&block);
  }
  if (block.IsLoop() && BackedgeHasSnapshot(block)) {
    // Update the associated snapshot for the forward edge with the merged
    // snapshot information from the forward- and backward edge.
    // This will make sure that when evaluating whether a loop needs to be
    // revisited, the inner loop compares the merged state with the backedge
    // preventing us from exponential revisits for loops where the backedge
    // invalidates loads which are eliminatable on the forward edge.
    StoreLoopSnapshotInForwardPredecessor(block);
  }

  for (OpIndex op_idx : graph_.OperationIndices(block)) {
    Operation& op = graph_.Get(op_idx);
    if (ShouldSkipOptimizationStep()) continue;
    if (ShouldSkipOperation(op)) continue;
    switch (op.opcode) {
      case Opcode::kStructGet:
        ProcessStructGet(op_idx, op.Cast<StructGetOp>());
        break;
      case Opcode::kStructSet:
        ProcessStructSet(op_idx, op.Cast<StructSetOp>());
        break;
      case Opcode::kArrayLength:
        ProcessArrayLength(op_idx, op.Cast<ArrayLengthOp>());
        break;
      case Opcode::kWasmAllocateArray:
        ProcessWasmAllocateArray(op_idx, op.Cast<WasmAllocateArrayOp>());
        break;
      case Opcode::kStringAsWtf16:
        ProcessStringAsWtf16(op_idx, op.Cast<StringAsWtf16Op>());
        break;
      case Opcode::kStringPrepareForGetCodeUnit:
        ProcessStringPrepareForGetCodeUnit(
            op_idx, op.Cast<StringPrepareForGetCodeUnitOp>());
        break;
      case Opcode::kAnyConvertExtern:
        ProcessAnyConvertExtern(op_idx, op.Cast<AnyConvertExternOp>());
        break;
      case Opcode::kAssertNotNull:
        // TODO(14108): We'll probably want to handle WasmTypeCast as
        // a "load-like" instruction too, to eliminate repeated casts.
        ProcessAssertNotNull(op_idx, op.Cast<AssertNotNullOp>());
        break;
      case Opcode::kArraySet:
        break;
      case Opcode::kAllocate:
        // Create new non-alias.
        ProcessAllocate(op_idx, op.Cast<AllocateOp>());
        break;
      case Opcode::kCall:
        // Invalidate state (+ maybe invalidate aliases).
        ProcessCall(op_idx, op.Cast<CallOp>());
        break;
      case Opcode::kPhi:
        // Invalidate aliases.
        ProcessPhi(op_idx, op.Cast<PhiOp>());
        break;
      case Opcode::kLoad:
        // Atomic loads have the "can_write" bit set, because they make
        // writes on other threads visible. At any rate, we have to
        // explicitly skip them here.
      case Opcode::kStore:
        // We rely on having no raw "Store" operations operating on Wasm
        // objects at this point in the pipeline.
        // TODO(jkummerow): Is there any way to DCHECK that?
      case Opcode::kAssumeMap:
      case Opcode::kCatchBlockBegin:
      case Opcode::kRetain:
      case Opcode::kDidntThrow:
      case Opcode::kCheckException:
      case Opcode::kAtomicRMW:
      case Opcode::kAtomicWord32Pair:
      case Opcode::kMemoryBarrier:
      case Opcode::kJSStackCheck:
      case Opcode::kWasmStackCheck:
      case Opcode::kSimd128LaneMemory:
      case Opcode::kGlobalSet:
      case Opcode::kParameter:
        // We explicitly break for those operations that have can_write effects
        // but don't actually write, or cannot interfere with load elimination.
        break;

      case Opcode::kWordBinop:
        // A WordBinop should never invalidate aliases (since the only time when
        // it should take a non-aliasing object as input is for Smi checks).
        DcheckWordBinop(op_idx, op.Cast<WordBinopOp>());
        break;

      case Opcode::kFrameState:
      case Opcode::kDeoptimizeIf:
      case Opcode::kComparison:
      case Opcode::kTrapIf:
        // We explicitly break for these opcodes so that we don't call
        // InvalidateAllNonAliasingInputs on their inputs, since they don't
        // really create aliases. (and also, they don't write so it's
        // fine to break)
        DCHECK(!op.Effects().can_write());
        break;

      case Opcode::kDeoptimize:
      case Opcode::kReturn:
        // We explicitly break for these opcodes so that we don't call
        // InvalidateAllNonAliasingInputs on their inputs, since they are block
        // terminators without successors, meaning that it's not useful for the
        // rest of the analysis to invalidate anything here.
        DCHECK(op.IsBlockTerminator() && SuccessorBlocks(op).empty());
        break;

      default:
        // Operations that `can_write` should invalidate the state. All such
        // operations should be already handled above, which means that we don't
        // need a `if (can_write) { Invalidate(); }` here.
        CHECK(!op.Effects().can_write());

        // Even if the operation doesn't write, it could create an alias to its
        // input by returning it. This happens for instance in Phis and in
        // Change (although ChangeOp is already handled earlier by calling
        // ProcessChange). We are conservative here by calling
        // InvalidateAllNonAliasingInputs for all operations even though only
        // few can actually create aliases to fresh allocations, the reason
        // being that missing such a case would be a security issue, and it
        // should be rare for fresh allocations to be used outside of
        // Call/Store/Load/Change anyways.
        InvalidateAllNonAliasingInputs(op);

        break;
    }
  }

  FinishBlock(&block);
}

// Returns true if replacing a load with a RegisterRepresentation
// {expected_reg_rep} and size {in_memory_size} with an
// operation with RegisterRepresentation {actual} is valid. For instance,
// replacing an operation that returns a Float64 by one that returns a Word64 is
// not valid. Similarly, replacing a Tagged with an untagged value is probably
// not valid because of the GC.

bool RepIsCompatible(RegisterRepresentation actual,
                     RegisterRepresentation expected_reg_repr,
                     uint8_t in_memory_size) {
  if (in_memory_size !=
      MemoryRepresentation::FromRegisterRepresentation(actual, true)
          .SizeInBytes()) {
    // The replacement was truncated when being stored or should be truncated
    // (or sign-extended) during the load. Since we don't have enough
    // truncations operators in Turboshaft (eg, we don't have Int32 to Int8
    // truncation), we just prevent load elimination in this case.

    // TODO(jkummerow): support eliminating repeated loads of the same i8/i16
    // field.
    return false;
  }

  return expected_reg_repr == actual;
}

void WasmLoadEliminationAnalyzer::ProcessStructGet(OpIndex op_idx,
                                                   const StructGetOp& get) {
  OpIndex existing = memory_.Find(get);
  if (existing.valid()) {
    const Operation& replacement = graph_.Get(existing);
    DCHECK_EQ(replacement.outputs_rep().size(), 1);
    DCHECK_EQ(get.outputs_rep().size(), 1);
    uint8_t size = get.type->field(get.field_index).value_kind_size();
    if (RepIsCompatible(replacement.outputs_rep()[0], get.outputs_rep()[0],
                        size)) {
      replacements_[op_idx] = existing;
      return;
    }
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.Insert(get, op_idx);
}

void WasmLoadEliminationAnalyzer::ProcessStructSet(OpIndex op_idx,
                                                   const StructSetOp& set) {
  if (memory_.HasValueWithIncorrectMutability(set)) {
    // This struct.set is unreachable. We don't have a good way to annotate
    // it as such, so we use "replace with itself" as a sentinel.
    // TODO(jkummerow): Check how often this case is triggered in practice.
    replacements_[op_idx] = op_idx;
    return;
  }

  memory_.Invalidate(set);
  memory_.Insert(set);

  // Updating aliases if the value stored was known as non-aliasing.
  OpIndex value = set.value();
  if (non_aliasing_objects_.HasKeyFor(value)) {
    non_aliasing_objects_.Set(value, false);
  }
}

void WasmLoadEliminationAnalyzer::ProcessArrayLength(
    OpIndex op_idx, const ArrayLengthOp& length) {
  static constexpr int offset = wle::kArrayLengthFieldIndex;
  OpIndex existing = memory_.FindLoadLike(length.array(), offset);
  if (existing.valid()) {
#if DEBUG
    const Operation& replacement = graph_.Get(existing);
    DCHECK_EQ(replacement.outputs_rep().size(), 1);
    DCHECK_EQ(length.outputs_rep().size(), 1);
    DCHECK_EQ(replacement.outputs_rep()[0], length.outputs_rep()[0]);
#endif
    replacements_[op_idx] = existing;
    return;
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.InsertLoadLike(length.array(), offset, op_idx);
}

void WasmLoadEliminationAnalyzer::ProcessWasmAllocateArray(
    OpIndex op_idx, const WasmAllocateArrayOp& alloc) {
  non_aliasing_objects_.Set(op_idx, true);
  static constexpr int offset = wle::kArrayLengthFieldIndex;
  memory_.InsertLoadLike(op_idx, offset, alloc.length());
}

void WasmLoadEliminationAnalyzer::ProcessStringAsWtf16(
    OpIndex op_idx, const StringAsWtf16Op& op) {
  static constexpr int offset = wle::kStringAsWtf16Index;
  OpIndex existing = memory_.FindLoadLike(op.string(), offset);
  if (existing.valid()) {
    DCHECK_EQ(Opcode::kStringAsWtf16, graph_.Get(existing).opcode);
    replacements_[op_idx] = existing;
    return;
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.InsertLoadLike(op.string(), offset, op_idx);
}

void WasmLoadEliminationAnalyzer::ProcessStringPrepareForGetCodeUnit(
    OpIndex op_idx, const StringPrepareForGetCodeUnitOp& prep) {
  static constexpr int offset = wle::kStringPrepareForGetCodeunitIndex;
  OpIndex existing = memory_.FindLoadLike(prep.string(), offset);
  if (existing.valid()) {
    DCHECK_EQ(Opcode::kStringPrepareForGetCodeUnit,
              graph_.Get(existing).opcode);
    replacements_[op_idx] = existing;
    return;
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.InsertLoadLike(prep.string(), offset, op_idx);
}

void WasmLoadEliminationAnalyzer::ProcessAnyConvertExtern(
    OpIndex op_idx, const AnyConvertExternOp& convert) {
  static constexpr int offset = wle::kAnyConvertExternIndex;
  OpIndex existing = memory_.FindLoadLike(convert.object(), offset);
  if (existing.valid()) {
    DCHECK_EQ(Opcode::kAnyConvertExtern, graph_.Get(existing).opcode);
    replacements_[op_idx] = existing;
    return;
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.InsertLoadLike(convert.object(), offset, op_idx);
}

void WasmLoadEliminationAnalyzer::ProcessAssertNotNull(
    OpIndex op_idx, const AssertNotNullOp& assert) {
  static constexpr int offset = wle::kAssertNotNullIndex;
  OpIndex existing = memory_.FindLoadLike(assert.object(), offset);
  if (existing.valid()) {
    DCHECK_EQ(Opcode::kAssertNotNull, graph_.Get(existing).opcode);
    replacements_[op_idx] = existing;
    return;
  }
  replacements_[op_idx] = OpIndex::Invalid();
  memory_.InsertLoadLike(assert.object(), offset, op_idx);
}

// Since we only loosely keep track of what can or can't alias, we assume that
// anything that was guaranteed to not alias with anything (because it's in
// {non_aliasing_objects_}) can alias with anything when coming back from the
// call if it was an argument of the call.
void WasmLoadEliminationAnalyzer::ProcessCall(OpIndex op_idx,
                                              const CallOp& op) 
"""


```