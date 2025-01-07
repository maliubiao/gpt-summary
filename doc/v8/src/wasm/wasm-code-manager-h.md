Response:
Let's break down the thought process for analyzing the C++ header file `v8/src/wasm/wasm-code-manager.h`.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the file, looking for recurring keywords and patterns. This gives a high-level overview. Keywords like `class`, `enum`, `struct`, `static`, `const`, `private`, `public`, `virtual`, and data structure names (`std::vector`, `std::map`, `absl::flat_hash_map`) are good starting points. The namespace `wasm` is prominent. The file also includes other V8 headers, suggesting interactions with other parts of the engine.

**2. Identifying Core Data Structures:**

The names of the classes and structs are crucial. We see:

* `DisjointAllocationPool`:  Likely for managing non-overlapping memory regions.
* `WasmCode`: Represents a compiled WebAssembly function or code snippet. This is central.
* `WasmCodeAllocator`: Responsible for allocating memory for `WasmCode` objects.
* `NativeModule`:  Represents a loaded WebAssembly module and manages its associated resources, including `WasmCode`.

These are the key building blocks.

**3. Understanding Class Responsibilities (Focusing on `WasmCode`):**

For each class, we try to understand its primary role by examining its members (variables and methods). Let's focus on `WasmCode` as it seems complex:

* **Data Members:**
    * `instructions_`:  Clearly the actual machine code.
    * `meta_data_`: Holds related information like relocation data, source positions, etc. The comments explain the structure of this data.
    * `index_`: The index of the function within the module.
    * `flags_`:  A bitfield storing various properties (kind, tier, debugging status).
    * `ref_count_`:  Indicates that `WasmCode` is reference-counted, essential for memory management in a shared environment.
    *  Offsets (`constant_pool_offset_`, `safepoint_table_offset_`, etc.):  Pointers to data within the `meta_data_`.
    * `native_module_`:  A backpointer to the module it belongs to.
    * `code_pointer_handle_`:  Relates to the Code Pointer Table optimization (if enabled).

* **Methods:**
    * **Accessors:**  Many `instructions()`, `instruction_start()`, `instructions_size()`, `reloc_info()`, etc. These provide ways to access the stored data.
    * **Lifecycle Management:** `IncRef()`, `DecRef()`, `DecRefOnLiveCode()`, `DecRefOnDeadCode()` clearly handle the reference counting.
    * **Metadata Access:** `GetSourcePositionBefore()`, `GetInliningPosition()` provide access to debugging information.
    * **Properties:** `kind()`, `tier()`, `for_debugging()`.
    * **Utility:** `contains()`, `Validate()`, `Print()`, `Disassemble()`, `LogCode()`.
    * **Static Methods:** `GetRecordWriteBuiltin()`, `GetTSANStoreBuiltin()`, `GetTSANRelaxedLoadBuiltin()`  - these seem to provide access to built-in functions based on certain parameters, likely for memory safety or thread safety.

**4. Connecting the Classes:**

Now, we look at how these classes interact:

* `NativeModule` *has-a* `WasmCodeAllocator` to manage its code memory.
* `NativeModule` *owns* a collection of `WasmCode` objects.
* `WasmCode` has a pointer back to its `NativeModule`.

This points to a hierarchical structure.

**5. Inferring Functionality from Method Names and Comments:**

Method names are generally descriptive. For example:

* `AllocateForCode()` in `WasmCodeAllocator` clearly allocates memory.
* `PublishCode()` in `NativeModule` makes code available for execution.
* `RemoveCompiledCode()` in `NativeModule` suggests code eviction or garbage collection.
* `InitializeJumpTableForLazyCompilation()` in `NativeModule` hints at how functions are initially set up before their code is generated.

The comments within the code are *extremely* helpful for understanding the purpose of specific methods and data members.

**6. Considering the Conditional Logic (`#if` directives):**

The `#if V8_ENABLE_WEBASSEMBLY` and `#if V8_ENABLE_WASM_CODE_POINTER_TABLE` sections indicate features that might be enabled or disabled during compilation. This means the code has different behaviors based on these settings. We need to be aware of these variations.

**7. Relating to JavaScript (if applicable):**

The prompt specifically asks about the relationship to JavaScript. WebAssembly is designed to run alongside JavaScript in the browser. We look for clues about this interaction. The presence of `kWasmToJsWrapper` in the `WasmCode::Kind` enum and methods like `GetBuiltinCodePointer` suggest ways WebAssembly calls out to JavaScript or uses JavaScript's built-in functions. The concept of "wrappers" implies bridging the gap between the two environments.

**8. Considering Potential Programming Errors:**

Think about what could go wrong when working with compiled code: memory corruption, incorrect function calls, issues with debugging. The reference counting mechanism in `WasmCode` is a protection against premature deallocation. The existence of protected instructions suggests handling of traps or exceptions.

**9. Structuring the Summary:**

Finally, organize the findings into logical sections. Start with a high-level overview, then detail the responsibilities of the key classes. Discuss the interactions between components, any conditional logic, and potential connections to JavaScript. Address the specific points raised in the prompt (Torque, JavaScript examples – even if the file isn't Torque, the *reason* why needs to be stated).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `DisjointAllocationPool` is just a simple vector."
* **Correction:**  The use of `std::set` and the logic of `Merge` and `Allocate` suggest it's more sophisticated, ensuring non-overlapping regions.

* **Initial thought:** "What's the `WasmCodePointer`?"
* **Refinement:**  The `#if` directive reveals it's either an address or an index into a table, depending on the build configuration.

* **Initial thought:** "The `flags_` field is just some flags."
* **Refinement:** The use of `base::BitField8` makes it clear that it's a compact way to store multiple boolean or small integer values.

By following these steps, iterating, and constantly referring back to the code, we can build a comprehensive understanding of the functionality of the header file.
这是目录为 `v8/src/wasm/wasm-code-manager.h` 的一个 V8 源代码文件。根据文件扩展名 `.h`，它是一个 C++ 头文件，而不是 Torque (`.tq`) 文件。

## `v8/src/wasm/wasm-code-manager.h` 的功能归纳：

这个头文件定义了 V8 中用于管理 WebAssembly 代码的核心数据结构和接口。它主要负责：

1. **表示和管理已编译的 WebAssembly 代码 (`WasmCode` 类):**
   - 存储 WebAssembly 函数的机器码指令、元数据（例如重定位信息、源码位置、调试信息等）。
   - 跟踪代码的类型（例如，WebAssembly 函数、C API 包装器、JS 包装器等）。
   - 管理代码的生命周期，使用引用计数来控制代码的释放。
   - 提供访问代码各种属性和数据的方法（例如，指令起始地址、大小、源码位置等）。
   - 支持代码的反汇编和日志记录。

2. **分配和释放 WebAssembly 代码内存 (`WasmCodeAllocator` 类):**
   - 管理用于存储已编译 WebAssembly 代码的内存区域。
   - 提供分配和释放代码内存的接口。
   - 跟踪已提交、已生成和已释放的代码空间大小。

3. **管理 WebAssembly 模块的本地代码 (`NativeModule` 类):**
   - 代表一个已加载的 WebAssembly 模块，并拥有其所有的已编译代码。
   - 维护一个代码表，用于存储模块中每个函数的 `WasmCode` 对象。
   - 管理函数跳转表，用于高效地调用 WebAssembly 函数。
   - 处理代码的发布（使其可执行）和重新安装（例如，对于调试代码）。
   - 支持延迟编译和代码的移除。
   - 跟踪与代码相关的统计信息（例如，代码大小、liftoff 失败次数、编译时间等）。

4. **支持内存区域的分配和管理 (`DisjointAllocationPool` 类):**
   - 提供一种管理不相交内存区域的机制。
   - 用于 `WasmCodeAllocator` 中管理空闲和已释放的代码空间。

5. **定义 WebAssembly 代码指针 (`WasmCodePointer`):**
   -  根据编译选项，`WasmCodePointer` 可以是代码的起始地址，也可以是指向代码指针表的索引。这是一种优化技术，用于减小代码大小。

**这个文件不是 Torque 源代码。** Torque 文件通常用于定义 V8 的内置函数和运行时库。

## 与 JavaScript 的关系及示例：

`v8/src/wasm/wasm-code-manager.h` 中定义的结构和功能直接支持 WebAssembly 在 JavaScript 环境中的运行。当 JavaScript 代码加载并实例化一个 WebAssembly 模块时，V8 会使用这里的机制来编译和管理 WebAssembly 代码。

例如，当 JavaScript 调用一个 WebAssembly 导出的函数时，V8 内部会执行以下步骤（简化）：

1. **查找 `NativeModule`:**  根据 WebAssembly 模块的实例找到对应的 `NativeModule` 对象。
2. **查找 `WasmCode`:**  使用函数索引在 `NativeModule` 的代码表中查找对应的 `WasmCode` 对象。
3. **执行代码:**  获取 `WasmCode` 中的机器码指令的起始地址，并跳转到该地址执行 WebAssembly 代码。

**JavaScript 示例：**

```javascript
// 假设已经加载并实例化了一个 WebAssembly 模块 'wasmModule'
const instance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));

// 调用 WebAssembly 导出的函数 'add'
const result = instance.exports.add(5, 3);
console.log(result); // 输出 8
```

在这个例子中，当 `instance.exports.add(5, 3)` 被调用时，V8 内部会用到 `wasm-code-manager.h` 中定义的功能来找到并执行 `add` 函数对应的 WebAssembly 代码。

## 代码逻辑推理（假设输入与输出）：

**场景：**  在 `NativeModule` 中添加一个新的已编译的 WebAssembly 函数。

**假设输入：**

- `index`: 新函数的索引，例如 `5`。
- `desc`: 包含代码描述信息的 `CodeDesc` 对象，例如代码大小、是否包含跳跃表等。
- `stack_slots`: 函数需要的栈槽数量，例如 `10`。
- `ool_spill_count`:  需要保存在栈上的寄存器数量，例如 `2`。
- `tagged_parameter_slots`: 标记参数槽信息。
- `protected_instructions`: 受保护指令信息。
- `source_position_table`: 源码位置表。
- `inlining_positions`: 内联位置信息。
- `deopt_data`: 反优化数据。
- `kind`: 代码类型，例如 `WasmCode::kWasmFunction`。
- `tier`: 执行层级，例如 `ExecutionTier::kTurbofan`。
- `for_debugging`: 是否用于调试，例如 `ForDebugging::kNoDebugging`。

**代码逻辑（简化）：**

1. `NativeModule::AddCode` 被调用，使用输入参数创建一个新的 `WasmCode` 对象。
2. `WasmCodeAllocator::AllocateForCode` 被调用，为新函数的机器码分配内存。
3. 机器码和元数据被复制到分配的内存中。
4. 新的 `WasmCode` 对象被添加到 `NativeModule` 的内部数据结构中，例如代码表。
5. `NativeModule::PublishCode` 被调用，将新代码添加到跳转表中，使其可以被调用。

**假设输出：**

- 返回一个指向新创建的 `WasmCode` 对象的指针。
- 新函数的机器码已存储在分配的内存中。
- 代码表和跳转表已更新，指向新添加的代码。

## 用户常见的编程错误（与 WebAssembly 相关）：

虽然 `wasm-code-manager.h` 是 V8 内部的实现细节，用户通常不会直接与之交互，但了解其功能有助于理解与 WebAssembly 相关的错误。一些常见的编程错误可能最终导致与代码管理相关的问题：

1. **内存访问越界：** WebAssembly 代码可能会尝试访问模块线性内存范围之外的内存。这可能导致 V8 抛出错误或程序崩溃。虽然 `WasmCode` 本身不直接防止这种情况，但 V8 的运行时环境会进行检查。
2. **类型错误：** 在 JavaScript 和 WebAssembly 之间传递数据时，类型不匹配会导致错误。例如，尝试将一个 JavaScript 字符串传递给需要一个 WebAssembly 整数的函数。
3. **栈溢出：**  如果 WebAssembly 函数调用栈过深，可能会导致栈溢出。`WasmCode` 中 `stack_slots` 字段与此有关，它定义了函数需要的栈空间。
4. **不正确的导入/导出：**  在定义 WebAssembly 模块时，导入和导出的函数签名必须匹配。不匹配可能导致链接错误或运行时错误。
5. **并发问题：** 如果在多线程环境中不正确地使用共享的 WebAssembly 内存或实例，可能会导致数据竞争和未定义的行为。

**示例（可能间接与代码管理相关）：**

```javascript
// wasm 模块定义了一个需要两个 i32 参数的 add 函数

// 错误地传递了一个字符串参数
instance.exports.add(5, "hello"); // 这可能会导致类型错误，V8 内部在调用 WebAssembly 代码时会检查参数类型。

// 尝试访问超出线性内存范围的内存（假设 wasm 模块中有这样的错误）
// 这可能会导致 V8 抛出异常，虽然不是 `wasm-code-manager.h` 直接负责，但它管理的机器码中可能包含这样的错误。
try {
  instance.exports.accessMemory(1000000); // 假设模块内存大小远小于 1MB
} catch (e) {
  console.error("Memory access error:", e);
}
```

## 总结 `v8/src/wasm/wasm-code-manager.h` 的功能 (第 1 部分)：

`v8/src/wasm/wasm-code-manager.h` 是 V8 引擎中一个至关重要的头文件，它定义了用于管理已编译 WebAssembly 代码的核心结构和功能。它负责表示、分配、释放和组织 WebAssembly 代码，以及处理与代码相关的元数据。`WasmCode` 类代表单个已编译的代码单元，`WasmCodeAllocator` 管理代码内存分配，而 `NativeModule` 则负责管理整个 WebAssembly 模块的本地代码。这个文件是 V8 成功运行 WebAssembly 代码的基础。

Prompt: 
```
这是目录为v8/src/wasm/wasm-code-manager.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-code-manager.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_CODE_MANAGER_H_
#define V8_WASM_WASM_CODE_MANAGER_H_

#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "src/base/address-region.h"
#include "src/base/bit-field.h"
#include "src/base/macros.h"
#include "src/base/vector.h"
#include "src/builtins/builtins.h"
#include "src/codegen/safepoint-table.h"
#include "src/codegen/source-position.h"
#include "src/handles/handles.h"
#include "src/tasks/operations-barrier.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/wasm-code-pointer-table.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module-sourcemap.h"
#include "src/wasm/wasm-tier.h"

namespace v8 {
class CFunctionInfo;
namespace internal {

class InstructionStream;
class CodeDesc;
class Isolate;

namespace wasm {

class AssumptionsJournal;
class DebugInfo;
class NamesProvider;
class NativeModule;
struct WasmCompilationResult;
class WasmEngine;
class WasmImportWrapperCache;
struct WasmModule;
enum class WellKnownImport : uint8_t;

// Sorted, disjoint and non-overlapping memory regions. A region is of the
// form [start, end). So there's no [start, end), [end, other_end),
// because that should have been reduced to [start, other_end).
class V8_EXPORT_PRIVATE DisjointAllocationPool final {
 public:
  MOVE_ONLY_WITH_DEFAULT_CONSTRUCTORS(DisjointAllocationPool);
  explicit DisjointAllocationPool(base::AddressRegion region)
      : regions_({region}) {}

  // Merge the parameter region into this object. The assumption is that the
  // passed parameter is not intersecting this object - for example, it was
  // obtained from a previous Allocate. Returns the merged region.
  base::AddressRegion Merge(base::AddressRegion);

  // Allocate a contiguous region of size {size}. Return an empty region on
  // failure.
  base::AddressRegion Allocate(size_t size);

  // Allocate a contiguous region of size {size} within {region}. Return an
  // empty region on failure.
  base::AddressRegion AllocateInRegion(size_t size, base::AddressRegion);

  bool IsEmpty() const { return regions_.empty(); }

  const auto& regions() const { return regions_; }

 private:
  std::set<base::AddressRegion, base::AddressRegion::StartAddressLess> regions_;
};

#if V8_ENABLE_WASM_CODE_POINTER_TABLE
constexpr WasmCodePointer kInvalidWasmCodePointer =
    WasmCodePointerTable::kInvalidHandle;
#else
constexpr WasmCodePointer kInvalidWasmCodePointer = kNullAddress;
#endif

// Resolve the entry address of a WasmCodePointer
Address WasmCodePointerAddress(WasmCodePointer pointer);

template <Builtin builtin>
WasmCodePointer GetBuiltinCodePointer(Isolate* isolate) {
#if V8_ENABLE_WASM_CODE_POINTER_TABLE
  return Builtins::WasmBuiltinHandleOf<builtin>(isolate);
#else
  return Builtins::EntryOf(builtin, isolate);
#endif
}

class V8_EXPORT_PRIVATE WasmCode final {
 public:
  enum Kind {
    kWasmFunction,
    kWasmToCapiWrapper,
    kWasmToJsWrapper,
#if V8_ENABLE_DRUMBRAKE
    kInterpreterEntry,
#endif  // V8_ENABLE_DRUMBRAKE
    kJumpTable
  };

  static constexpr Builtin GetRecordWriteBuiltin(SaveFPRegsMode fp_mode) {
    switch (fp_mode) {
      case SaveFPRegsMode::kIgnore:
        return Builtin::kRecordWriteIgnoreFP;
      case SaveFPRegsMode::kSave:
        return Builtin::kRecordWriteSaveFP;
    }
  }

#ifdef V8_IS_TSAN
  static Builtin GetTSANStoreBuiltin(SaveFPRegsMode fp_mode, int size,
                                     std::memory_order order) {
    if (order == std::memory_order_relaxed) {
      if (size == kInt8Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANRelaxedStore8IgnoreFP
                   : Builtin::kTSANRelaxedStore8SaveFP;
      } else if (size == kInt16Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANRelaxedStore16IgnoreFP
                   : Builtin::kTSANRelaxedStore16SaveFP;
      } else if (size == kInt32Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANRelaxedStore32IgnoreFP
                   : Builtin::kTSANRelaxedStore32SaveFP;
      } else {
        CHECK_EQ(size, kInt64Size);
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANRelaxedStore64IgnoreFP
                   : Builtin::kTSANRelaxedStore64SaveFP;
      }
    } else {
      DCHECK_EQ(order, std::memory_order_seq_cst);
      if (size == kInt8Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANSeqCstStore8IgnoreFP
                   : Builtin::kTSANSeqCstStore8SaveFP;
      } else if (size == kInt16Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANSeqCstStore16IgnoreFP
                   : Builtin::kTSANSeqCstStore16SaveFP;
      } else if (size == kInt32Size) {
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANSeqCstStore32IgnoreFP
                   : Builtin::kTSANSeqCstStore32SaveFP;
      } else {
        CHECK_EQ(size, kInt64Size);
        return fp_mode == SaveFPRegsMode::kIgnore
                   ? Builtin::kTSANSeqCstStore64IgnoreFP
                   : Builtin::kTSANSeqCstStore64SaveFP;
      }
    }
  }

  static Builtin GetTSANRelaxedLoadBuiltin(SaveFPRegsMode fp_mode, int size) {
    if (size == kInt32Size) {
      return fp_mode == SaveFPRegsMode::kIgnore
                 ? Builtin::kTSANRelaxedLoad32IgnoreFP
                 : Builtin::kTSANRelaxedLoad32SaveFP;
    } else {
      CHECK_EQ(size, kInt64Size);
      return fp_mode == SaveFPRegsMode::kIgnore
                 ? Builtin::kTSANRelaxedLoad64IgnoreFP
                 : Builtin::kTSANRelaxedLoad64SaveFP;
    }
  }
#endif  // V8_IS_TSAN

  base::Vector<uint8_t> instructions() const {
    return base::VectorOf(instructions_,
                          static_cast<size_t>(instructions_size_));
  }
  Address instruction_start() const {
    return reinterpret_cast<Address>(instructions_);
  }
  WasmCodePointer code_pointer() const {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
    return code_pointer_handle_;
#else
    return instruction_start();
#endif
  }
  size_t instructions_size() const {
    return static_cast<size_t>(instructions_size_);
  }
  base::Vector<const uint8_t> reloc_info() const {
    return {protected_instructions_data().end(),
            static_cast<size_t>(reloc_info_size_)};
  }
  base::Vector<const uint8_t> source_positions() const {
    return {reloc_info().end(), static_cast<size_t>(source_positions_size_)};
  }
  base::Vector<const uint8_t> inlining_positions() const {
    return {source_positions().end(),
            static_cast<size_t>(inlining_positions_size_)};
  }
  base::Vector<const uint8_t> deopt_data() const {
    return {inlining_positions().end(), static_cast<size_t>(deopt_data_size_)};
  }

  int index() const { return index_; }
  // Anonymous functions are functions that don't carry an index.
  bool IsAnonymous() const { return index_ == kAnonymousFuncIndex; }
  Kind kind() const { return KindField::decode(flags_); }
  NativeModule* native_module() const { return native_module_; }
  ExecutionTier tier() const { return ExecutionTierField::decode(flags_); }
  Address constant_pool() const;
  Address handler_table() const;
  int handler_table_size() const;
  Address code_comments() const;
  int code_comments_size() const;
  int constant_pool_offset() const { return constant_pool_offset_; }
  int safepoint_table_offset() const { return safepoint_table_offset_; }
  int handler_table_offset() const { return handler_table_offset_; }
  int code_comments_offset() const { return code_comments_offset_; }
  int unpadded_binary_size() const { return unpadded_binary_size_; }
  int stack_slots() const { return stack_slots_; }
  int ool_spills() const { return ool_spills_; }
  uint16_t first_tagged_parameter_slot() const {
    return tagged_parameter_slots_ >> 16;
  }
  uint16_t num_tagged_parameter_slots() const {
    return tagged_parameter_slots_ & 0xFFFF;
  }
  uint32_t raw_tagged_parameter_slots_for_serialization() const {
    return tagged_parameter_slots_;
  }

  bool is_liftoff() const { return tier() == ExecutionTier::kLiftoff; }

  bool is_turbofan() const { return tier() == ExecutionTier::kTurbofan; }

  bool contains(Address pc) const {
    return reinterpret_cast<Address>(instructions_) <= pc &&
           pc < reinterpret_cast<Address>(instructions_ + instructions_size_);
  }

  // Only Liftoff code that was generated for debugging can be inspected
  // (otherwise debug side table positions would not match up).
  bool is_inspectable() const { return is_liftoff() && for_debugging(); }

  base::Vector<const uint8_t> protected_instructions_data() const {
    return {meta_data_.get(),
            static_cast<size_t>(protected_instructions_size_)};
  }

  base::Vector<const trap_handler::ProtectedInstructionData>
  protected_instructions() const {
    return base::Vector<const trap_handler::ProtectedInstructionData>::cast(
        protected_instructions_data());
  }

  bool IsProtectedInstruction(Address pc);

  void Validate() const;
  void Print(const char* name = nullptr) const;
  void MaybePrint() const;
  void Disassemble(const char* name, std::ostream& os,
                   Address current_pc = kNullAddress) const;

  static bool ShouldBeLogged(Isolate* isolate);
  void LogCode(Isolate* isolate, const char* source_url, int script_id) const;

  WasmCode(const WasmCode&) = delete;
  WasmCode& operator=(const WasmCode&) = delete;
  ~WasmCode();

  void IncRef() {
    [[maybe_unused]] int old_val =
        ref_count_.fetch_add(1, std::memory_order_acq_rel);
    DCHECK_LE(1, old_val);
    DCHECK_GT(kMaxInt, old_val);
  }

  // Decrement the ref count. Returns whether this code becomes dead and needs
  // to be freed.
  V8_WARN_UNUSED_RESULT bool DecRef() {
    int old_count = ref_count_.load(std::memory_order_acquire);
    while (true) {
      DCHECK_LE(1, old_count);
      if (V8_UNLIKELY(old_count == 1)) return DecRefOnPotentiallyDeadCode();
      if (ref_count_.compare_exchange_weak(old_count, old_count - 1,
                                           std::memory_order_acq_rel)) {
        return false;
      }
    }
  }

  // Decrement the ref count on code that is known to be in use (i.e. the ref
  // count cannot drop to zero here).
  void DecRefOnLiveCode() {
    [[maybe_unused]] int old_count =
        ref_count_.fetch_sub(1, std::memory_order_acq_rel);
    DCHECK_LE(2, old_count);
  }

  // Decrement the ref count on code that is known to be dead, even though there
  // might still be C++ references. Returns whether this drops the last
  // reference and the code needs to be freed.
  V8_WARN_UNUSED_RESULT bool DecRefOnDeadCode() {
    return ref_count_.fetch_sub(1, std::memory_order_acq_rel) == 1;
  }

  // Decrement the ref count on a set of {WasmCode} objects, potentially
  // belonging to different {NativeModule}s. Dead code will be deleted.
  static void DecrementRefCount(base::Vector<WasmCode* const>);

  // Called by the WasmEngine when it shuts down for code it thinks is
  // probably dead (i.e. is in the "potentially_dead_code_" set). Wrapped
  // in a method only because {ref_count_} is private.
  void DcheckRefCountIsOne() {
    DCHECK_EQ(1, ref_count_.load(std::memory_order_acquire));
  }

  // Returns the last source position before {offset}.
  SourcePosition GetSourcePositionBefore(int code_offset);
  int GetSourceOffsetBefore(int code_offset);

  std::tuple<int, bool, SourcePosition> GetInliningPosition(
      int inlining_id) const;

  // Returns whether this code was generated for debugging. If this returns
  // {kForDebugging}, but {tier()} is not {kLiftoff}, then Liftoff compilation
  // bailed out.
  ForDebugging for_debugging() const {
    return ForDebuggingField::decode(flags_);
  }

  // Returns {true} for Liftoff code that sets up a feedback vector slot in its
  // stack frame.
  // TODO(jkummerow): This can be dropped when we ship Wasm inlining.
  bool frame_has_feedback_slot() const {
    return FrameHasFeedbackSlotField::decode(flags_);
  }

  enum FlushICache : bool { kFlushICache = true, kNoFlushICache = false };

  size_t EstimateCurrentMemoryConsumption() const;

  // Tries to get a reasonable name. Lazily looks up the name section, and falls
  // back to the function index. Return value is guaranteed to not be empty.
  std::string DebugName() const;

 private:
  friend class NativeModule;
  friend class WasmImportWrapperCache;

  static bool ShouldAllocateCodePointerHandle(int index, Kind kind);
  static WasmCodePointerTable::Handle MaybeAllocateCodePointerHandle(
      NativeModule* native_module, int index, Kind kind, Address entry);

  WasmCode(NativeModule* native_module, int index,
           base::Vector<uint8_t> instructions, int stack_slots, int ool_spills,
           uint32_t tagged_parameter_slots, int safepoint_table_offset,
           int handler_table_offset, int constant_pool_offset,
           int code_comments_offset, int unpadded_binary_size,
           base::Vector<const uint8_t> protected_instructions_data,
           base::Vector<const uint8_t> reloc_info,
           base::Vector<const uint8_t> source_position_table,
           base::Vector<const uint8_t> inlining_positions,
           base::Vector<const uint8_t> deopt_data, Kind kind,
           ExecutionTier tier, ForDebugging for_debugging,
           bool frame_has_feedback_slot = false)
      : native_module_(native_module),
        instructions_(instructions.begin()),
        code_pointer_handle_(MaybeAllocateCodePointerHandle(
            native_module, index, kind,
            reinterpret_cast<Address>(instructions.begin()))),
        meta_data_(ConcatenateBytes({protected_instructions_data, reloc_info,
                                     source_position_table, inlining_positions,
                                     deopt_data})),
        instructions_size_(instructions.length()),
        reloc_info_size_(reloc_info.length()),
        source_positions_size_(source_position_table.length()),
        inlining_positions_size_(inlining_positions.length()),
        deopt_data_size_(deopt_data.length()),
        protected_instructions_size_(protected_instructions_data.length()),
        index_(index),
        constant_pool_offset_(constant_pool_offset),
        stack_slots_(stack_slots),
        ool_spills_(ool_spills),
        tagged_parameter_slots_(tagged_parameter_slots),
        safepoint_table_offset_(safepoint_table_offset),
        handler_table_offset_(handler_table_offset),
        code_comments_offset_(code_comments_offset),
        unpadded_binary_size_(unpadded_binary_size),
        flags_(KindField::encode(kind) | ExecutionTierField::encode(tier) |
               ForDebuggingField::encode(for_debugging) |
               FrameHasFeedbackSlotField::encode(frame_has_feedback_slot)) {
    DCHECK_LE(safepoint_table_offset, unpadded_binary_size);
    DCHECK_LE(handler_table_offset, unpadded_binary_size);
    DCHECK_LE(code_comments_offset, unpadded_binary_size);
    DCHECK_LE(constant_pool_offset, unpadded_binary_size);
  }

  std::unique_ptr<const uint8_t[]> ConcatenateBytes(
      std::initializer_list<base::Vector<const uint8_t>>);

  // Code objects that have been registered with the global trap
  // handler within this process, will have a {trap_handler_index} associated
  // with them.
  int trap_handler_index() const {
    CHECK(has_trap_handler_index());
    return trap_handler_index_;
  }
  void set_trap_handler_index(int value) {
    CHECK(!has_trap_handler_index());
    trap_handler_index_ = value;
  }
  bool has_trap_handler_index() const { return trap_handler_index_ >= 0; }

  // Register protected instruction information with the trap handler. Sets
  // trap_handler_index.
  void RegisterTrapHandlerData();

  // Slow path for {DecRef}: The code becomes potentially dead.
  // Returns whether this code becomes dead and needs to be freed.
  V8_NOINLINE bool DecRefOnPotentiallyDeadCode();

  NativeModule* const native_module_ = nullptr;
  uint8_t* const instructions_;
  const WasmCodePointerTable::Handle code_pointer_handle_;
  // {meta_data_} contains several byte vectors concatenated into one:
  //  - protected instructions data of size {protected_instructions_size_}
  //  - relocation info of size {reloc_info_size_}
  //  - source positions of size {source_positions_size_}
  //  - deopt data of size {deopt_data_size_}
  // Note that the protected instructions come first to ensure alignment.
  std::unique_ptr<const uint8_t[]> meta_data_;
  const int instructions_size_;
  const int reloc_info_size_;
  const int source_positions_size_;
  const int inlining_positions_size_;
  const int deopt_data_size_;
  const int protected_instructions_size_;
  const int index_;  // The wasm function-index within the module.
  const int constant_pool_offset_;
  const int stack_slots_;
  const int ool_spills_;
  // Number and position of tagged parameters passed to this function via the
  // stack, packed into a single uint32. These values are used by the stack
  // walker (e.g. GC) to find references.
  const uint32_t tagged_parameter_slots_;
  // We care about safepoint data for wasm-to-js functions, since there may be
  // stack/register tagged values for large number conversions.
  const int safepoint_table_offset_;
  const int handler_table_offset_;
  const int code_comments_offset_;
  const int unpadded_binary_size_;
  int trap_handler_index_ = -1;

  const uint8_t flags_;  // Bit field, see below.
  // Bits encoded in {flags_}:
#if !V8_ENABLE_DRUMBRAKE
  using KindField = base::BitField8<Kind, 0, 2>;
#else   // !V8_ENABLE_DRUMBRAKE
  // We have an additional kind: Wasm interpreter.
  using KindField = base::BitField8<Kind, 0, 3>;
#endif  // !V8_ENABLE_DRUMBRAKE
  using ExecutionTierField = KindField::Next<ExecutionTier, 2>;
  using ForDebuggingField = ExecutionTierField::Next<ForDebugging, 2>;
  using FrameHasFeedbackSlotField = ForDebuggingField::Next<bool, 1>;

  // WasmCode is ref counted. Counters are held by:
  //   1) The jump table / code table.
  //   2) {WasmCodeRefScope}s.
  //   3) The set of potentially dead code in the {WasmEngine}.
  // If a decrement of (1) would drop the ref count to 0, that code becomes a
  // candidate for garbage collection. At that point, we add a ref count for (3)
  // *before* decrementing the counter to ensure the code stays alive as long as
  // it's being used. Once the ref count drops to zero (i.e. after being removed
  // from (3) and all (2)), the code object is deleted and the memory for the
  // machine code is freed.
  std::atomic<int> ref_count_{1};
};

WasmCode::Kind GetCodeKind(const WasmCompilationResult& result);

// Return a textual description of the kind.
const char* GetWasmCodeKindAsString(WasmCode::Kind);

// Manages the code reservations and allocations of a single {NativeModule}.
class WasmCodeAllocator {
 public:
  explicit WasmCodeAllocator(std::shared_ptr<Counters> async_counters);
  ~WasmCodeAllocator();

  // Call before use, after the {NativeModule} is set up completely.
  void Init(VirtualMemory code_space);

  // Call on newly allocated code ranges, to write platform-specific headers.
  void InitializeCodeRange(NativeModule* native_module,
                           base::AddressRegion region);

  size_t committed_code_space() const {
    return committed_code_space_.load(std::memory_order_acquire);
  }
  size_t generated_code_size() const {
    return generated_code_size_.load(std::memory_order_acquire);
  }
  size_t freed_code_size() const {
    return freed_code_size_.load(std::memory_order_acquire);
  }

  // Allocate code space. Returns a valid buffer or fails with OOM (crash).
  // Hold the {NativeModule}'s {allocation_mutex_} when calling this method.
  base::Vector<uint8_t> AllocateForCode(NativeModule*, size_t size);
  // Same, but for wrappers (which are shared across NativeModules).
  base::Vector<uint8_t> AllocateForWrapper(size_t size);

  // Allocate code space within a specific region. Returns a valid buffer or
  // fails with OOM (crash).
  // Hold the {NativeModule}'s {allocation_mutex_} when calling this method.
  base::Vector<uint8_t> AllocateForCodeInRegion(NativeModule*, size_t size,
                                                base::AddressRegion);

  // Free memory pages of all given code objects. Used for wasm code GC.
  // Hold the {NativeModule}'s {allocation_mutex_} when calling this method.
  void FreeCode(base::Vector<WasmCode* const>);

  // Retrieve the number of separately reserved code spaces.
  // Hold the {NativeModule}'s {allocation_mutex_} when calling this method.
  size_t GetNumCodeSpaces() const;

  Counters* counters() const { return async_counters_.get(); }

 private:
  //////////////////////////////////////////////////////////////////////////////
  // These fields are protected by the mutex in {NativeModule}.

  // Code space that was reserved and is available for allocations
  // (subset of {owned_code_space_}).
  DisjointAllocationPool free_code_space_;
  // Code space that was allocated before but is dead now. Full
  // pages within this region are discarded. It's still a subset of
  // {owned_code_space_}.
  DisjointAllocationPool freed_code_space_;
  std::vector<VirtualMemory> owned_code_space_;

  // End of fields protected by {mutex_}.
  //////////////////////////////////////////////////////////////////////////////

  std::atomic<size_t> committed_code_space_{0};
  std::atomic<size_t> generated_code_size_{0};
  std::atomic<size_t> freed_code_size_{0};

  std::shared_ptr<Counters> async_counters_;
};

class V8_EXPORT_PRIVATE NativeModule final {
 public:
  static constexpr ExternalPointerTag kManagedTag = kWasmNativeModuleTag;

#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_S390X || V8_TARGET_ARCH_ARM64 || \
    V8_TARGET_ARCH_PPC64 || V8_TARGET_ARCH_LOONG64 || V8_TARGET_ARCH_RISCV64
  static constexpr bool kNeedsFarJumpsBetweenCodeSpaces = true;
#else
  static constexpr bool kNeedsFarJumpsBetweenCodeSpaces = false;
#endif

  NativeModule(const NativeModule&) = delete;
  NativeModule& operator=(const NativeModule&) = delete;
  ~NativeModule();

  // {AddCode} is thread safe w.r.t. other calls to {AddCode} or methods adding
  // code below, i.e. it can be called concurrently from background threads.
  // The returned code still needs to be published via {PublishCode}.
  std::unique_ptr<WasmCode> AddCode(
      int index, const CodeDesc& desc, int stack_slots, int ool_spill_count,
      uint32_t tagged_parameter_slots,
      base::Vector<const uint8_t> protected_instructions,
      base::Vector<const uint8_t> source_position_table,
      base::Vector<const uint8_t> inlining_positions,
      base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
      ExecutionTier tier, ForDebugging for_debugging);

  // {PublishCode} makes the code available to the system by entering it into
  // the code table and patching the jump table. It returns a raw pointer to the
  // given {WasmCode} object. Ownership is transferred to the {NativeModule}.
  // Returns {nullptr} if the {AssumptionsJournal} is non-nullptr and contains
  // invalid assumptions.
  WasmCode* PublishCode(std::unique_ptr<WasmCode>,
                        AssumptionsJournal* = nullptr);
  std::vector<WasmCode*> PublishCode(base::Vector<std::unique_ptr<WasmCode>>);

  // Clears outdated code as necessary when a new instantiation's imports
  // conflict with previously seen well-known imports.
  void UpdateWellKnownImports(base::Vector<WellKnownImport> entries);

  // ReinstallDebugCode does a subset of PublishCode: It installs the code in
  // the code table and patches the jump table. The given code must be debug
  // code (with breakpoints) and must be owned by this {NativeModule} already.
  // This method is used to re-instantiate code that was removed from the code
  // table and jump table via another {PublishCode}.
  void ReinstallDebugCode(WasmCode*);

  struct JumpTablesRef {
    Address jump_table_start = kNullAddress;
    Address far_jump_table_start = kNullAddress;

    bool is_valid() const { return far_jump_table_start != kNullAddress; }
  };

  std::pair<base::Vector<uint8_t>, JumpTablesRef> AllocateForDeserializedCode(
      size_t total_code_size);

  std::unique_ptr<WasmCode> AddDeserializedCode(
      int index, base::Vector<uint8_t> instructions, int stack_slots,
      int ool_spills, uint32_t tagged_parameter_slots,
      int safepoint_table_offset, int handler_table_offset,
      int constant_pool_offset, int code_comments_offset,
      int unpadded_binary_size,
      base::Vector<const uint8_t> protected_instructions_data,
      base::Vector<const uint8_t> reloc_info,
      base::Vector<const uint8_t> source_position_table,
      base::Vector<const uint8_t> inlining_positions,
      base::Vector<const uint8_t> deopt_data, WasmCode::Kind kind,
      ExecutionTier tier);

  // Adds anonymous code for testing purposes.
  WasmCode* AddCodeForTesting(DirectHandle<Code> code);

  // Allocates and initializes the {lazy_compile_table_} and initializes the
  // first jump table with jumps to the {lazy_compile_table_}.
  void InitializeJumpTableForLazyCompilation(uint32_t num_wasm_functions);

  // Initialize/Free the code pointer table handles for declared functions.
  void InitializeCodePointerTableHandles(uint32_t num_wasm_functions);
  void FreeCodePointerTableHandles();

  // Use {UseLazyStubLocked} to setup lazy compilation per function. It will use
  // the existing {WasmCode::kWasmCompileLazy} runtime stub and populate the
  // jump table with trampolines accordingly.
  void UseLazyStubLocked(uint32_t func_index);

  // Creates a snapshot of the current state of the code table, along with the
  // current import statuses that these code objects depend on. This is useful
  // to get a consistent view of the table (e.g. used by the serializer).
  std::pair<std::vector<WasmCode*>, std::vector<WellKnownImport>>
  SnapshotCodeTable() const;
  // Creates a snapshot of all {owned_code_}, will transfer new code (if any) to
  // {owned_code_}.
  std::vector<WasmCode*> SnapshotAllOwnedCode() const;

  WasmCode* GetCode(uint32_t index) const;
  bool HasCode(uint32_t index) const;
  bool HasCodeWithTier(uint32_t index, ExecutionTier tier) const;

  void SetWasmSourceMap(std::unique_ptr<WasmModuleSourceMap> source_map);
  WasmModuleSourceMap* GetWasmSourceMap() const;

  Address jump_table_start() const {
    return main_jump_table_ ? main_jump_table_->instruction_start()
                            : kNullAddress;
  }

  // Get the call target in the jump table previously looked up via
  // {FindJumpTablesForRegionLocked}.
  Address GetNearCallTargetForFunction(uint32_t func_index,
                                       const JumpTablesRef&) const;

  // Get the slot offset in the far jump table that jumps to the given builtin.
  Address GetJumpTableEntryForBuiltin(Builtin builtin,
                                      const JumpTablesRef&) const;

  // Reverse lookup from a given call target (which must be a jump table slot)
  // to a function index.
  uint32_t GetFunctionIndexFromJumpTableSlot(Address slot_address) const;

  using CallIndirectTargetMap = absl::flat_hash_map<WasmCodePointer, uint32_t>;
  CallIndirectTargetMap CreateIndirectCallTargetToFunctionIndexMap() const;

  // For cctests, where we build both WasmModule and the runtime objects
  // on the fly, and bypass the instance builder pipeline.
  void ReserveCodeTableForTesting(uint32_t max_functions);

  // Log all owned code in the given isolate, using the given script as the
  // containing script. Use this after transferring the module to a new isolate
  // or when enabling a component that needs all code to be logged (profiler).
  void LogWasmCodes(Isolate*, Tagged<Script>);

  CompilationState* compilation_state() const {
    return compilation_state_.get();
  }

  uint32_t num_functions() const {
    return module_->num_declared_functions + module_->num_imported_functions;
  }
  uint32_t num_imported_functions() const {
    return module_->num_imported_functions;
  }
  void set_lazy_compile_frozen(bool frozen) { lazy_compile_frozen_ = frozen; }
  bool lazy_compile_frozen() const { return lazy_compile_frozen_; }
  base::Vector<const uint8_t> wire_bytes() const {
    return std::atomic_load(&wire_bytes_)->as_vector();
  }
  const WasmModule* module() const { return module_.get(); }
  std::shared_ptr<const WasmModule> shared_module() const { return module_; }
  size_t committed_code_space() const {
    return code_allocator_.committed_code_space();
  }
  size_t generated_code_size() const {
    return code_allocator_.generated_code_size();
  }
  size_t liftoff_bailout_count() const {
    return liftoff_bailout_count_.load(std::memory_order_relaxed);
  }
  size_t liftoff_code_size() const {
    return liftoff_code_size_.load(std::memory_order_relaxed);
  }
  size_t turbofan_code_size() const {
    return turbofan_code_size_.load(std::memory_order_relaxed);
  }

  void AddLazyCompilationTimeSample(int64_t sample);

  int num_lazy_compilations() const {
    return num_lazy_compilations_.load(std::memory_order_relaxed);
  }

  int64_t sum_lazy_compilation_time_in_ms() const {
    return sum_lazy_compilation_time_in_micro_sec_.load(
               std::memory_order_relaxed) /
           1000;
  }

  int64_t max_lazy_compilation_time_in_ms() const {
    return max_lazy_compilation_time_in_micro_sec_.load(
               std::memory_order_relaxed) /
           1000;
  }

  // To avoid double-reporting, only the first instantiation should report lazy
  // compilation performance metrics.
  bool ShouldLazyCompilationMetricsBeReported() {
    return should_metrics_be_reported_.exchange(false,
                                                std::memory_order_relaxed);
  }

  // Similar to above, scheduling a repeated task to write out PGO data is only
  // needed once per module, not per instantiation.
  bool ShouldPgoDataBeWritten() {
    return should_pgo_data_be_written_.exchange(false,
                                                std::memory_order_relaxed);
  }

  bool HasWireBytes() const {
    auto wire_bytes = std::atomic_load(&wire_bytes_);
    return wire_bytes && !wire_bytes->empty();
  }
  void SetWireBytes(base::OwnedVector<const uint8_t> wire_bytes);

  void AddLiftoffBailout() {
    liftoff_bailout_count_.fetch_add(1, std::memory_order_relaxed);
  }

  WasmCode* Lookup(Address) const;

  WasmEnabledFeatures enabled_features() const { return enabled_features_; }
  const CompileTimeImports& compile_imports() const { return compile_imports_; }

  // Returns the builtin that corresponds to the given address (which
  // must be a far jump table slot). Returns {kNoBuiltinId} on failure.
  Builtin GetBuiltinInJumptableSlot(Address target) const;

  // Sample the current code size of this modules to the given counters.
  void SampleCodeSize(Counters*) const;

  V8_WARN_UNUSED_RESULT std::unique_ptr<WasmCode> AddCompiledCode(
      const WasmCompilationResult&);
  V8_WARN_UNUSED_RESULT std::vector<std::unique_ptr<WasmCode>> AddCompiledCode(
      base::Vector<const WasmCompilationResult>);

  // Set a new debugging state, but don't trigger any recompilation;
  // recompilation happens lazily.
  void SetDebugState(DebugState);

  // Check whether this modules is in debug state.
  DebugState IsInDebugState() const {
    base::RecursiveMutexGuard lock(&allocation_mutex_);
    return debug_state_;
  }

  enum class RemoveFilter {
    kRemoveDebugCode,
    kRemoveNonDebugCode,
    kRemoveLiftoffCode,
    kRemoveTurbofanCode,
    kRemoveAllCode,
  };
  // Remove all compiled code based on the `filter` from the {NativeModule},
  // replace it with {CompileLazy} builtins and return the sizes of the removed
  // (executable) code and the removed metadata.
  std::pair<size_t, size_t> RemoveCompiledCode(RemoveFilter filter);

  // Returns the code size of all Liftoff compiled functions.
  size_t SumLiftoffCodeSizeForTesting() const;

  // Free a set of functions of this module. Uncommits whole pages if possible.
  // The given vector must be ordered by the instruction start address, and all
  // {WasmCode} objects must not be used any more.
"""


```