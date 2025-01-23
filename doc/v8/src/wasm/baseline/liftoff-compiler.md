Response: The user wants to understand the functionality of the C++ file `liftoff-compiler.cc`.
The file path suggests it's part of the V8 JavaScript engine, specifically related to WebAssembly compilation.
It seems to be the first part of a larger file.

**Plan:**

1. Read through the provided C++ code.
2. Identify the main components and their roles.
3. Summarize the file's overall function in relation to WebAssembly compilation.
4. If there are connections to JavaScript, provide a simple JavaScript example to illustrate the relationship.

**High-level observations from the code:**

* Includes numerous V8 headers related to code generation, compilation, and WebAssembly.
* Defines a `LiftoffCompiler` class, which is likely the core of the file's functionality.
* Contains a lot of macros and helper functions for code generation.
* Deals with concepts like stack management, registers, control flow, and exception handling in the context of WebAssembly.
* Mentions "Liftoff", suggesting it's a specific compilation strategy.
这个C++源代码文件 `liftoff-compiler.cc` 是 V8 JavaScript 引擎中用于 WebAssembly 的 **Liftoff 编译器** 的一部分。

**主要功能归纳:**

1. **Liftoff 编译策略的实现:**  Liftoff 是一种用于 WebAssembly 的**基线编译器**，它的目标是快速生成代码，以便 WebAssembly 模块能够快速启动执行。相较于更优化的编译器（如 TurboFan），Liftoff 生成的代码性能较低，但编译速度更快。这个文件实现了 Liftoff 编译器的核心逻辑。

2. **WebAssembly 代码的低级代码生成:** 该文件负责将 WebAssembly 的字节码指令转换为目标架构（如 x64, ARM 等）的机器码指令。它处理诸如算术运算、内存访问、函数调用、控制流 (if/else, loop, block)、异常处理 (try/catch) 等 WebAssembly 概念的低级实现。

3. **寄存器和栈管理:**  Liftoff 编译器需要管理 WebAssembly 执行时使用的寄存器和栈。这个文件中的代码负责分配和释放寄存器，将 WebAssembly 的值存储到栈上，并根据需要从栈上加载值。

4. **与 V8 引擎的集成:**  该文件使用了大量的 V8 内部 API 和数据结构，例如 `Assembler`, `CodeDesc`, `Builtin`, `WasmInstance`,  `DebugSideTable` 等，这表明 Liftoff 编译器是 V8 引擎 WebAssembly 执行流程的一个组成部分。

5. **调试支持:**  代码中包含了对调试功能的支持，例如断点、单步执行等。通过 `DebugSideTableBuilder` 等组件，它能够生成用于调试器将机器码映射回 WebAssembly 源代码的信息。

6. **性能监控和优化 (Tier-Up):**  Liftoff 编译器生成的代码虽然启动快，但性能可能不是最优的。该文件包含了一些机制，用于监控代码的执行情况，并在满足特定条件时触发 "Tier-Up" 到更优化的编译器 (TurboFan)，从而在运行时提高性能。

7. **异常处理:**  该文件实现了 WebAssembly 的异常处理机制 (try, catch, throw)。它负责生成在发生异常时跳转到相应 catch 代码块的机器码。

**与 JavaScript 的关系及示例:**

Liftoff 编译器是 V8 引擎执行 JavaScript 中加载的 WebAssembly 模块的关键部分。当你在 JavaScript 中加载和实例化一个 WebAssembly 模块时，V8 引擎会使用 Liftoff (或其他编译器) 将 WebAssembly 代码编译成机器码，然后才能被 JavaScript 调用执行。

**JavaScript 示例:**

```javascript
// 假设你有一个名为 'module.wasm' 的 WebAssembly 文件

async function loadAndRunWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer); // V8 可能会使用 Liftoff 编译
  const instance = await WebAssembly.instantiate(module);

  // 假设你的 WebAssembly 模块导出一个名为 'add' 的函数
  const result = instance.exports.add(5, 3);
  console.log(result); // 输出 8
}

loadAndRunWasm();
```

**在这个 JavaScript 例子中：**

1. `fetch('module.wasm')` 获取 WebAssembly 字节码。
2. `WebAssembly.compile(buffer)` 这一步，V8 引擎的 Liftoff 编译器（如果被选中作为初始编译器）会解析 `buffer` 中的 WebAssembly 字节码，并将其转换为目标平台的机器码。这个 `liftoff-compiler.cc` 文件中的代码就在这个阶段发挥作用。
3. `WebAssembly.instantiate(module)` 创建 WebAssembly 模块的实例，并将编译后的机器码与 JavaScript 环境连接起来。
4. `instance.exports.add(5, 3)` 调用 WebAssembly 模块中导出的函数 `add`，执行的是由 Liftoff 编译器生成的机器码。

**总结:**

`liftoff-compiler.cc` 是 V8 引擎中负责快速编译 WebAssembly 代码的关键组件。它将 WebAssembly 的高级指令转换为可以在 JavaScript 环境中执行的低级机器码，使得 JavaScript 可以无缝地调用和执行 WebAssembly 模块的功能。

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/baseline/liftoff-compiler.h"

#include <optional>

#include "src/base/enum-set.h"
#include "src/codegen/assembler-inl.h"
// TODO(clemensb): Remove dependences on compiler stuff.
#include "src/codegen/external-reference.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/wasm-compiler.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/objects/contexts.h"
#include "src/objects/smi.h"
#include "src/roots/roots.h"
#include "src/tracing/trace-event.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"
#include "src/wasm/baseline/liftoff-assembler-inl.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/memory-tracing.h"
#include "src/wasm/object-access.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/simd-shuffle.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8::internal::wasm {

using VarState = LiftoffAssembler::VarState;
constexpr auto kRegister = VarState::kRegister;
constexpr auto kIntConst = VarState::kIntConst;
constexpr auto kStack = VarState::kStack;

namespace {

#define __ asm_.

// It's important that we don't modify the LiftoffAssembler's cache state
// in conditionally-executed code paths. Creating these witnesses helps
// enforce that (using DCHECKs in the cache state).
// Conditional jump instructions require a witness to have been created (to
// make sure we don't forget); the witness should stay alive until the label
// is bound where regular control flow resumes. This implies that when we're
// jumping to a trap, the live range of the witness isn't important.
#define FREEZE_STATE(witness_name) FreezeCacheState witness_name(asm_)

#define TRACE(...)                                                \
  do {                                                            \
    if (v8_flags.trace_liftoff) PrintF("[liftoff] " __VA_ARGS__); \
  } while (false)

#define WASM_TRUSTED_INSTANCE_DATA_FIELD_OFFSET(name) \
  ObjectAccess::ToTagged(WasmTrustedInstanceData::k##name##Offset)

template <int expected_size, int actual_size>
struct assert_field_size {
  static_assert(expected_size == actual_size,
                "field in WasmInstance does not have the expected size");
  static constexpr int size = actual_size;
};

#define WASM_TRUSTED_INSTANCE_DATA_FIELD_SIZE(name) \
  FIELD_SIZE(WasmTrustedInstanceData::k##name##Offset)

#define LOAD_INSTANCE_FIELD(dst, name, load_size, pinned)            \
  __ LoadFromInstance(                                               \
      dst, LoadInstanceIntoRegister(pinned, dst),                    \
      WASM_TRUSTED_INSTANCE_DATA_FIELD_OFFSET(name),                 \
      assert_field_size<WASM_TRUSTED_INSTANCE_DATA_FIELD_SIZE(name), \
                        load_size>::size);

#define LOAD_TAGGED_PTR_INSTANCE_FIELD(dst, name, pinned)                  \
  static_assert(                                                           \
      WASM_TRUSTED_INSTANCE_DATA_FIELD_SIZE(name) == kTaggedSize,          \
      "field in WasmTrustedInstanceData does not have the expected size"); \
  __ LoadTaggedPointerFromInstance(                                        \
      dst, LoadInstanceIntoRegister(pinned, dst),                          \
      WASM_TRUSTED_INSTANCE_DATA_FIELD_OFFSET(name));

#define LOAD_PROTECTED_PTR_INSTANCE_FIELD(dst, name, pinned)                 \
  static_assert(                                                             \
      WASM_TRUSTED_INSTANCE_DATA_FIELD_SIZE(Protected##name) == kTaggedSize, \
      "field in WasmTrustedInstanceData does not have the expected size");   \
  __ LoadProtectedPointer(                                                   \
      dst, LoadInstanceIntoRegister(pinned, dst),                            \
      WASM_TRUSTED_INSTANCE_DATA_FIELD_OFFSET(Protected##name));

// Liftoff's code comments are intentionally without source location to keep
// readability up.
#ifdef V8_CODE_COMMENTS
#define CODE_COMMENT(str) __ RecordComment(str, SourceLocation{})
#define SCOPED_CODE_COMMENT(str)                                   \
  AssemblerBase::CodeComment scoped_comment_##__LINE__(&asm_, str, \
                                                       SourceLocation{})
#else
#define CODE_COMMENT(str) ((void)0)
#define SCOPED_CODE_COMMENT(str) ((void)0)
#endif

// For fuzzing purposes, we count each instruction as one "step". Certain
// "bulk" type instructions (dealing with memories, tables, strings, arrays)
// can take much more time. For simplicity, we count them all as a fixed
// large number of steps.
constexpr int kHeavyInstructionSteps = 1000;

constexpr ValueKind kIntPtrKind = LiftoffAssembler::kIntPtrKind;
constexpr ValueKind kSmiKind = LiftoffAssembler::kSmiKind;

// Used to construct fixed-size signatures: MakeSig::Returns(...).Params(...);
using MakeSig = FixedSizeSignature<ValueKind>;

#if V8_TARGET_ARCH_ARM64
// On ARM64, the Assembler keeps track of pointers to Labels to resolve
// branches to distant targets. Moving labels would confuse the Assembler,
// thus store the label in the Zone.
class MovableLabel {
 public:
  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(MovableLabel);
  explicit MovableLabel(Zone* zone) : label_(zone->New<Label>()) {}

  Label* get() { return label_; }

 private:
  Label* label_;
};
#else
// On all other platforms, just store the Label directly.
class MovableLabel {
 public:
  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(MovableLabel);
  explicit MovableLabel(Zone*) {}

  Label* get() { return &label_; }

 private:
  Label label_;
};
#endif

compiler::CallDescriptor* GetLoweredCallDescriptor(
    Zone* zone, compiler::CallDescriptor* call_desc) {
  return kSystemPointerSize == 4
             ? compiler::GetI32WasmCallDescriptor(zone, call_desc)
             : call_desc;
}

constexpr Condition GetCompareCondition(WasmOpcode opcode) {
  switch (opcode) {
    case kExprI32Eq:
      return kEqual;
    case kExprI32Ne:
      return kNotEqual;
    case kExprI32LtS:
      return kLessThan;
    case kExprI32LtU:
      return kUnsignedLessThan;
    case kExprI32GtS:
      return kGreaterThan;
    case kExprI32GtU:
      return kUnsignedGreaterThan;
    case kExprI32LeS:
      return kLessThanEqual;
    case kExprI32LeU:
      return kUnsignedLessThanEqual;
    case kExprI32GeS:
      return kGreaterThanEqual;
    case kExprI32GeU:
      return kUnsignedGreaterThanEqual;
    default:
      UNREACHABLE();
  }
}

// Builds a {DebugSideTable}.
class DebugSideTableBuilder {
  using Entry = DebugSideTable::Entry;
  using Value = Entry::Value;

 public:
  enum AssumeSpilling {
    // All register values will be spilled before the pc covered by the debug
    // side table entry. Register slots will be marked as stack slots in the
    // generated debug side table entry.
    kAssumeSpilling,
    // Register slots will be written out as they are.
    kAllowRegisters,
    // Register slots cannot appear since we already spilled.
    kDidSpill
  };

  class EntryBuilder {
   public:
    explicit EntryBuilder(int pc_offset, int stack_height,
                          std::vector<Value> changed_values)
        : pc_offset_(pc_offset),
          stack_height_(stack_height),
          changed_values_(std::move(changed_values)) {}

    Entry ToTableEntry() {
      return Entry{pc_offset_, stack_height_, std::move(changed_values_)};
    }

    void MinimizeBasedOnPreviousStack(const std::vector<Value>& last_values) {
      auto dst = changed_values_.begin();
      auto end = changed_values_.end();
      for (auto src = dst; src != end; ++src) {
        if (src->index < static_cast<int>(last_values.size()) &&
            *src == last_values[src->index]) {
          continue;
        }
        if (dst != src) *dst = *src;
        ++dst;
      }
      changed_values_.erase(dst, end);
    }

    int pc_offset() const { return pc_offset_; }
    void set_pc_offset(int new_pc_offset) { pc_offset_ = new_pc_offset; }

   private:
    int pc_offset_;
    int stack_height_;
    std::vector<Value> changed_values_;
  };

  // Adds a new entry in regular code.
  void NewEntry(int pc_offset,
                base::Vector<DebugSideTable::Entry::Value> values) {
    entries_.emplace_back(pc_offset, static_cast<int>(values.size()),
                          GetChangedStackValues(last_values_, values));
  }

  // Adds a new entry for OOL code, and returns a pointer to a builder for
  // modifying that entry.
  EntryBuilder* NewOOLEntry(base::Vector<DebugSideTable::Entry::Value> values) {
    constexpr int kNoPcOffsetYet = -1;
    ool_entries_.emplace_back(kNoPcOffsetYet, static_cast<int>(values.size()),
                              GetChangedStackValues(last_ool_values_, values));
    return &ool_entries_.back();
  }

  void SetNumLocals(int num_locals) {
    DCHECK_EQ(-1, num_locals_);
    DCHECK_LE(0, num_locals);
    num_locals_ = num_locals;
  }

  std::unique_ptr<DebugSideTable> GenerateDebugSideTable() {
    DCHECK_LE(0, num_locals_);

    // Connect {entries_} and {ool_entries_} by removing redundant stack
    // information from the first {ool_entries_} entry (based on
    // {last_values_}).
    if (!entries_.empty() && !ool_entries_.empty()) {
      ool_entries_.front().MinimizeBasedOnPreviousStack(last_values_);
    }

    std::vector<Entry> entries;
    entries.reserve(entries_.size() + ool_entries_.size());
    for (auto& entry : entries_) entries.push_back(entry.ToTableEntry());
    for (auto& entry : ool_entries_) entries.push_back(entry.ToTableEntry());
    DCHECK(std::is_sorted(
        entries.begin(), entries.end(),
        [](Entry& a, Entry& b) { return a.pc_offset() < b.pc_offset(); }));
    return std::make_unique<DebugSideTable>(num_locals_, std::move(entries));
  }

 private:
  static std::vector<Value> GetChangedStackValues(
      std::vector<Value>& last_values, base::Vector<Value> values) {
    std::vector<Value> changed_values;
    int old_stack_size = static_cast<int>(last_values.size());
    last_values.resize(values.size());

    int index = 0;
    for (const auto& value : values) {
      if (index >= old_stack_size || last_values[index] != value) {
        changed_values.push_back(value);
        last_values[index] = value;
      }
      ++index;
    }
    return changed_values;
  }

  int num_locals_ = -1;
  // Keep a snapshot of the stack of the last entry, to generate a delta to the
  // next entry.
  std::vector<Value> last_values_;
  std::vector<EntryBuilder> entries_;
  // Keep OOL code entries separate so we can do proper delta-encoding (more
  // entries might be added between the existing {entries_} and the
  // {ool_entries_}). Store the entries in a list so the pointer is not
  // invalidated by adding more entries.
  std::vector<Value> last_ool_values_;
  std::list<EntryBuilder> ool_entries_;
};

void CheckBailoutAllowed(LiftoffBailoutReason reason, const char* detail,
                         const CompilationEnv* env) {
  // Decode errors are ok.
  if (reason == kDecodeError) return;

  // --liftoff-only ensures that tests actually exercise the Liftoff path
  // without bailing out. We also fail for missing CPU support, to avoid
  // running any TurboFan code under --liftoff-only.
  if (v8_flags.liftoff_only) {
    FATAL("--liftoff-only: treating bailout as fatal error. Cause: %s", detail);
  }

  // Missing CPU features are generally OK, except with --liftoff-only.
  if (reason == kMissingCPUFeature) return;

  // If --enable-testing-opcode-in-wasm is set, we are expected to bailout with
  // "testing opcode".
  if (v8_flags.enable_testing_opcode_in_wasm &&
      strcmp(detail, "testing opcode") == 0) {
    return;
  }

  // Some externally maintained architectures don't fully implement Liftoff yet.
#if V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_S390X || V8_TARGET_ARCH_PPC64 || \
    V8_TARGET_ARCH_LOONG64
  return;
#endif

#if V8_TARGET_ARCH_ARM
  // Allow bailout for missing ARMv7 support.
  if (!CpuFeatures::IsSupported(ARMv7) && reason == kUnsupportedArchitecture) {
    return;
  }
#endif

#define LIST_FEATURE(name, ...) WasmEnabledFeature::name,
  constexpr WasmEnabledFeatures kExperimentalFeatures{
      FOREACH_WASM_EXPERIMENTAL_FEATURE_FLAG(LIST_FEATURE)};
#undef LIST_FEATURE

  // Bailout is allowed if any experimental feature is enabled.
  if (env->enabled_features.contains_any(kExperimentalFeatures)) return;

  // Otherwise, bailout is not allowed.
  FATAL("Liftoff bailout should not happen. Cause: %s\n", detail);
}

class TempRegisterScope {
 public:
  LiftoffRegister Acquire(RegClass rc) {
    LiftoffRegList candidates = free_temps_ & GetCacheRegList(rc);
    DCHECK(!candidates.is_empty());
    return free_temps_.clear(candidates.GetFirstRegSet());
  }

  void Return(LiftoffRegister&& temp) {
    DCHECK(!free_temps_.has(temp));
    free_temps_.set(temp);
  }

  void Return(Register&& temp) {
    Return(LiftoffRegister{temp});
    temp = no_reg;
  }

  LiftoffRegList AddTempRegisters(int count, RegClass rc,
                                  LiftoffAssembler* lasm,
                                  LiftoffRegList pinned) {
    LiftoffRegList temps;
    pinned |= free_temps_;
    for (int i = 0; i < count; ++i) {
      temps.set(lasm->GetUnusedRegister(rc, pinned | temps));
    }
    free_temps_ |= temps;
    return temps;
  }

 private:
  LiftoffRegList free_temps_;
};

class ScopedTempRegister {
 public:
  ScopedTempRegister(TempRegisterScope& temp_scope, RegClass rc)
      : reg_(temp_scope.Acquire(rc)), temp_scope_(&temp_scope) {}

  ScopedTempRegister(const ScopedTempRegister&) = delete;

  ScopedTempRegister(ScopedTempRegister&& other) V8_NOEXCEPT
      : reg_(other.reg_),
        temp_scope_(other.temp_scope_) {
    other.temp_scope_ = nullptr;
  }

  ScopedTempRegister& operator=(const ScopedTempRegister&) = delete;

  ~ScopedTempRegister() {
    if (temp_scope_) Reset();
  }

  LiftoffRegister reg() const {
    DCHECK_NOT_NULL(temp_scope_);
    return reg_;
  }

  Register gp_reg() const { return reg().gp(); }

  void Reset() {
    DCHECK_NOT_NULL(temp_scope_);
    temp_scope_->Return(std::move(reg_));
    temp_scope_ = nullptr;
  }

 private:
  LiftoffRegister reg_;
  TempRegisterScope* temp_scope_;
};

class LiftoffCompiler {
 public:
  using ValidationTag = Decoder::NoValidationTag;
  using Value = ValueBase<ValidationTag>;
  static constexpr bool kUsesPoppedArgs = false;

  // Some constants for tier-up checks.
  // In general we use the number of executed machine code bytes as an estimate
  // of how much time was spent in this function.
  // - {kTierUpCostForCheck} is the cost for checking for the tier-up itself,
  //   which is added to the PC distance on every tier-up check. This cost is
  //   for loading the tiering budget, subtracting from one entry in the array,
  //   and the conditional branch if the value is negative.
  // - {kTierUpCostForFunctionEntry} reflects the cost for calling the frame
  //   setup stub in the function prologue (the time is spent in another code
  //   object and hence not reflected in the PC distance).
  static constexpr int kTierUpCostForCheck = 20;
  static constexpr int kTierUpCostForFunctionEntry = 40;

  struct ElseState {
    explicit ElseState(Zone* zone) : label(zone), state(zone) {}
    MovableLabel label;
    LiftoffAssembler::CacheState state;
  };

  struct TryInfo {
    explicit TryInfo(Zone* zone) : catch_state(zone) {}
    LiftoffAssembler::CacheState catch_state;
    Label catch_label;
    bool catch_reached = false;
    bool in_handler = false;
  };

  struct Control : public ControlBase<Value, ValidationTag> {
    ElseState* else_state = nullptr;
    LiftoffAssembler::CacheState label_state;
    MovableLabel label;
    TryInfo* try_info = nullptr;
    // Number of exceptions on the stack below this control.
    int num_exceptions = 0;

    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(Control);

    template <typename... Args>
    explicit Control(Zone* zone, Args&&... args) V8_NOEXCEPT
        : ControlBase(zone, std::forward<Args>(args)...),
          label_state(zone),
          label(zone) {}
  };

  using FullDecoder = WasmFullDecoder<ValidationTag, LiftoffCompiler>;
  using ValueKindSig = LiftoffAssembler::ValueKindSig;

  class MostlySmallValueKindSig : public Signature<ValueKind> {
   public:
    MostlySmallValueKindSig(Zone* zone, const FunctionSig* sig)
        : Signature<ValueKind>(sig->return_count(), sig->parameter_count(),
                               MakeKinds(inline_storage_, zone, sig)) {}

   private:
    static constexpr size_t kInlineStorage = 8;

    static ValueKind* MakeKinds(ValueKind* storage, Zone* zone,
                                const FunctionSig* sig) {
      const size_t size = sig->parameter_count() + sig->return_count();
      if (V8_UNLIKELY(size > kInlineStorage)) {
        storage = zone->AllocateArray<ValueKind>(size);
      }
      std::transform(sig->all().begin(), sig->all().end(), storage,
                     [](ValueType type) { return type.kind(); });
      return storage;
    }

    ValueKind inline_storage_[kInlineStorage];
  };

  // For debugging, we need to spill registers before a trap or a stack check to
  // be able to inspect them.
  struct SpilledRegistersForInspection : public ZoneObject {
    struct Entry {
      int offset;
      LiftoffRegister reg;
      ValueKind kind;
    };
    ZoneVector<Entry> entries;

    explicit SpilledRegistersForInspection(Zone* zone) : entries(zone) {}
  };

  struct OutOfLineSafepointInfo {
    ZoneVector<int> slots;
    LiftoffRegList spills;

    explicit OutOfLineSafepointInfo(Zone* zone) : slots(zone) {}
  };

  struct OutOfLineCode {
    MovableLabel label;
    MovableLabel continuation;
    Builtin builtin;
    WasmCodePosition position;
    LiftoffRegList regs_to_save;
    Register cached_instance_data;
    OutOfLineSafepointInfo* safepoint_info;
    // These two pointers will only be used for debug code:
    SpilledRegistersForInspection* spilled_registers;
    DebugSideTableBuilder::EntryBuilder* debug_sidetable_entry_builder;

    // Named constructors:
    static OutOfLineCode Trap(
        Zone* zone, Builtin builtin, WasmCodePosition pos,
        SpilledRegistersForInspection* spilled_registers,
        OutOfLineSafepointInfo* safepoint_info,
        DebugSideTableBuilder::EntryBuilder* debug_sidetable_entry_builder) {
      DCHECK_LT(0, pos);
      return {
          MovableLabel{zone},            // label
          MovableLabel{zone},            // continuation
          builtin,                       // builtin
          pos,                           // position
          {},                            // regs_to_save
          no_reg,                        // cached_instance_data
          safepoint_info,                // safepoint_info
          spilled_registers,             // spilled_registers
          debug_sidetable_entry_builder  // debug_side_table_entry_builder
      };
    }
    static OutOfLineCode StackCheck(
        Zone* zone, WasmCodePosition pos, LiftoffRegList regs_to_save,
        Register cached_instance_data,
        SpilledRegistersForInspection* spilled_regs,
        OutOfLineSafepointInfo* safepoint_info,
        DebugSideTableBuilder::EntryBuilder* debug_sidetable_entry_builder) {
      Builtin stack_guard = Builtin::kWasmStackGuard;
      if (v8_flags.experimental_wasm_growable_stacks) {
        stack_guard = Builtin::kWasmGrowableStackGuard;
      }
      return {
          MovableLabel{zone},            // label
          MovableLabel{zone},            // continuation
          stack_guard,                   // builtin
          pos,                           // position
          regs_to_save,                  // regs_to_save
          cached_instance_data,          // cached_instance_data
          safepoint_info,                // safepoint_info
          spilled_regs,                  // spilled_registers
          debug_sidetable_entry_builder  // debug_side_table_entry_builder
      };
    }
    static OutOfLineCode TierupCheck(
        Zone* zone, WasmCodePosition pos, LiftoffRegList regs_to_save,
        Register cached_instance_data,
        SpilledRegistersForInspection* spilled_regs,
        OutOfLineSafepointInfo* safepoint_info,
        DebugSideTableBuilder::EntryBuilder* debug_sidetable_entry_builder) {
      return {
          MovableLabel{zone},            // label
          MovableLabel{zone},            // continuation,
          Builtin::kWasmTriggerTierUp,   // builtin
          pos,                           // position
          regs_to_save,                  // regs_to_save
          cached_instance_data,          // cached_instance_data
          safepoint_info,                // safepoint_info
          spilled_regs,                  // spilled_registers
          debug_sidetable_entry_builder  // debug_side_table_entry_builder
      };
    }
  };

  LiftoffCompiler(compiler::CallDescriptor* call_descriptor,
                  CompilationEnv* env, Zone* zone,
                  std::unique_ptr<AssemblerBuffer> buffer,
                  DebugSideTableBuilder* debug_sidetable_builder,
                  const LiftoffOptions& options)
      : asm_(zone, std::move(buffer)),
        descriptor_(GetLoweredCallDescriptor(zone, call_descriptor)),
        env_(env),
        debug_sidetable_builder_(debug_sidetable_builder),
        for_debugging_(options.for_debugging),
        func_index_(options.func_index),
        out_of_line_code_(zone),
        source_position_table_builder_(zone),
        protected_instructions_(zone),
        zone_(zone),
        safepoint_table_builder_(zone_),
        next_breakpoint_ptr_(options.breakpoints.begin()),
        next_breakpoint_end_(options.breakpoints.end()),
        dead_breakpoint_(options.dead_breakpoint),
        handlers_(zone),
        max_steps_(options.max_steps),
        nondeterminism_(options.nondeterminism) {
    // We often see huge numbers of traps per function, so pre-reserve some
    // space in that vector. 128 entries is enough for ~94% of functions on
    // modern modules, as of 2022-06-03.
    out_of_line_code_.reserve(128);

    DCHECK(options.is_initialized());
    // If there are no breakpoints, both pointers should be nullptr.
    DCHECK_IMPLIES(
        next_breakpoint_ptr_ == next_breakpoint_end_,
        next_breakpoint_ptr_ == nullptr && next_breakpoint_end_ == nullptr);
    DCHECK_IMPLIES(!for_debugging_, debug_sidetable_builder_ == nullptr);
  }

  bool did_bailout() const { return bailout_reason_ != kSuccess; }
  LiftoffBailoutReason bailout_reason() const { return bailout_reason_; }

  void GetCode(CodeDesc* desc) {
    asm_.GetCode(nullptr, desc, &safepoint_table_builder_,
                 handler_table_offset_);
  }

  std::unique_ptr<AssemblerBuffer> ReleaseBuffer() {
    return asm_.ReleaseBuffer();
  }

  std::unique_ptr<LiftoffFrameDescriptionForDeopt> ReleaseFrameDescriptions() {
    return std::move(frame_description_);
  }

  base::OwnedVector<uint8_t> GetSourcePositionTable() {
    return source_position_table_builder_.ToSourcePositionTableVector();
  }

  base::OwnedVector<uint8_t> GetProtectedInstructionsData() const {
    return base::OwnedVector<uint8_t>::Of(base::Vector<const uint8_t>::cast(
        base::VectorOf(protected_instructions_)));
  }

  uint32_t GetTotalFrameSlotCountForGC() const {
    return __ GetTotalFrameSlotCountForGC();
  }

  uint32_t OolSpillCount() const { return __ OolSpillCount(); }

  void unsupported(FullDecoder* decoder, LiftoffBailoutReason reason,
                   const char* detail) {
    DCHECK_NE(kSuccess, reason);
    if (did_bailout()) return;
    bailout_reason_ = reason;
    TRACE("unsupported: %s\n", detail);
    decoder->errorf(decoder->pc_offset(), "unsupported liftoff operation: %s",
                    detail);
    UnuseLabels(decoder);
    CheckBailoutAllowed(reason, detail, env_);
  }

  bool DidAssemblerBailout(FullDecoder* decoder) {
    if (decoder->failed() || !__ did_bailout()) return false;
    unsupported(decoder, __ bailout_reason(), __ bailout_detail());
    return true;
  }

  V8_INLINE bool CheckSupportedType(FullDecoder* decoder, ValueKind kind,
                                    const char* context) {
    if (V8_LIKELY(supported_types_.contains(kind))) return true;
    return MaybeBailoutForUnsupportedType(decoder, kind, context);
  }

  V8_NOINLINE bool MaybeBailoutForUnsupportedType(FullDecoder* decoder,
                                                  ValueKind kind,
                                                  const char* context) {
    DCHECK(!supported_types_.contains(kind));

    // Lazily update {supported_types_}; then check again.
    if (CpuFeatures::SupportsWasmSimd128()) supported_types_.Add(kS128);
    if (supported_types_.contains(kind)) return true;

    LiftoffBailoutReason bailout_reason;
    switch (kind) {
      case kS128:
        bailout_reason = kSimd;
        break;
      default:
        UNREACHABLE();
    }
    base::EmbeddedVector<char, 128> buffer;
    SNPrintF(buffer, "%s %s", name(kind), context);
    unsupported(decoder, bailout_reason, buffer.begin());
    return false;
  }

  void UnuseLabels(FullDecoder* decoder) {
#ifdef DEBUG
    auto Unuse = [](Label* label) {
      label->Unuse();
      label->UnuseNear();
    };
    // Unuse all labels now, otherwise their destructor will fire a DCHECK error
    // if they where referenced before.
    uint32_t control_depth = decoder ? decoder->control_depth() : 0;
    for (uint32_t i = 0; i < control_depth; ++i) {
      Control* c = decoder->control_at(i);
      Unuse(c->label.get());
      if (c->else_state) Unuse(c->else_state->label.get());
      if (c->try_info != nullptr) Unuse(&c->try_info->catch_label);
    }
    for (auto& ool : out_of_line_code_) Unuse(ool.label.get());
#endif
  }

  void StartFunction(FullDecoder* decoder) {
    if (v8_flags.trace_liftoff && !v8_flags.trace_wasm_decoder) {
      StdoutStream{} << "hint: add --trace-wasm-decoder to also see the wasm "
                        "instructions being decoded\n";
    }
    int num_locals = decoder->num_locals();
    __ set_num_locals(num_locals);
    for (int i = 0; i < num_locals; ++i) {
      ValueKind kind = decoder->local_type(i).kind();
      __ set_local_kind(i, kind);
    }
  }

  class ParameterProcessor {
   public:
    ParameterProcessor(LiftoffCompiler* compiler, uint32_t num_params)
        : compiler_(compiler), num_params_(num_params) {}

    void Process() {
      // First pass: collect parameter registers.
      while (NextParam()) {
        MaybeCollectRegister();
        if (needs_gp_pair_) {
          NextLocation();
          MaybeCollectRegister();
        }
      }
      // Second pass: allocate parameters.
      param_idx_ = 0;
      input_idx_ = kFirstInputIdx;
      while (NextParam()) {
        LiftoffRegister reg = LoadToReg(param_regs_);
        // In-sandbox corruption can replace one function's code with another's.
        // That's mostly safe, but certain signature mismatches can violate
        // security-relevant invariants later. To maintain such invariants,
        // explicitly clear the high word of any i32 parameters in 64-bit
        // registers.
        // 'clear_i32_upper_half' is empty on LoongArch64, MIPS64 and riscv64,
        // because they will explicitly zero-extend their lower halves before
        // using them for memory accesses anyway.
        // In addition, the generic js-to-wasm wrapper does a sign-extension
        // of i32 parameters, so clearing the upper half is required for
        // correctness in this case.
#if V8_TARGET_ARCH_64_BIT
        if (kind_ == kI32 && location_.IsRegister()) {
          compiler_->asm_.clear_i32_upper_half(reg.gp());
        }
#endif
        if (needs_gp_pair_) {
          NextLocation();
          LiftoffRegister reg2 = LoadToReg(param_regs_ | LiftoffRegList{reg});
          reg = LiftoffRegister::ForPair(reg.gp(), reg2.gp());
        }
        compiler_->asm_.PushRegister(kind_, reg);
      }
    }

   private:
    bool NextParam() {
      if (param_idx_ >= num_params_) {
        DCHECK_EQ(input_idx_, compiler_->descriptor_->InputCount());
        return false;
      }
      kind_ = compiler_->asm_.local_kind(param_idx_++);
      needs_gp_pair_ = needs_gp_reg_pair(kind_);
      reg_kind_ = needs_gp_pair_ ? kI32 : kind_;
      rc_ = reg_class_for(reg_kind_);
      NextLocation();
      return true;
    }

    void NextLocation() {
      location_ = compiler_->descriptor_->GetInputLocation(input_idx_++);
    }

    LiftoffRegister CurrentRegister() {
      DCHECK(!location_.IsAnyRegister());
      return LiftoffRegister::from_external_code(rc_, reg_kind_,
                                                 location_.AsRegister());
    }

    void MaybeCollectRegister() {
      if (!location_.IsRegister()) return;
      DCHECK(!param_regs_.has(CurrentRegister()));
      param_regs_.set(CurrentRegister());
    }

    LiftoffRegister LoadToReg(LiftoffRegList pinned) {
      if (location_.IsRegister()) {
        LiftoffRegister reg = CurrentRegister();
        DCHECK(compiler_->asm_.cache_state()->is_free(reg));
        // Unpin the register, to avoid depending on the set of allocatable
        // registers being larger than the set of parameter registers.
        param_regs_.clear(reg);
        return reg;
      }
      DCHECK(location_.IsCallerFrameSlot());
      LiftoffRegister reg = compiler_->asm_.GetUnusedRegister(rc_, pinned);
      compiler_->asm_.LoadCallerFrameSlot(reg, -location_.AsCallerFrameSlot(),
                                          reg_kind_);
      return reg;
    }

    // Input 0 is the code target, 1 is the instance data.
    static constexpr uint32_t kFirstInputIdx = 2;

    LiftoffCompiler* compiler_;
    const uint32_t num_params_;
    uint32_t param_idx_{0};
    uint32_t input_idx_{kFirstInputIdx};
    ValueKind kind_;
    bool needs_gp_pair_;
    ValueKind reg_kind_;
    RegClass rc_;
    LinkageLocation location_{LinkageLocation::ForAnyRegister()};
    LiftoffRegList param_regs_;
  };

  void StackCheck(FullDecoder* decoder, WasmCodePosition position) {
    CODE_COMMENT("stack check");
    if (!v8_flags.wasm_stack_checks) return;

    LiftoffRegList regs_to_save = __ cache_state()->used_registers;
    // The cached instance data will be reloaded separately.
    if (__ cache_state()->cached_instance_data != no_reg) {
      DCHECK(regs_to_save.has(__ cache_state()->cached_instance_data));
      regs_to_save.clear(__ cache_state()->cached_instance_data);
    }
    SpilledRegistersForInspection* spilled_regs = nullptr;

    OutOfLineSafepointInfo* safepoint_info =
        zone_->New<OutOfLineSafepointInfo>(zone_);
    __ cache_state()->GetTaggedSlotsForOOLCode(
        &safepoint_info->slots, &safepoint_info->spills,
        for_debugging_
            ? LiftoffAssembler::CacheState::SpillLocation::kStackSlots
            : LiftoffAssembler::CacheState::SpillLocation::kTopOfStack);
    if (V8_UNLIKELY(for_debugging_)) {
      // When debugging, we do not just push all registers to the stack, but we
      // spill them to their proper stack locations such that we can inspect
      // them.
      // The only exception is the cached memory start, which we just push
      // before the stack check and pop afterwards.
      regs_to_save = {};
      if (__ cache_state()->cached_mem_start != no_reg) {
        regs_to_save.set(__ cache_state()->cached_mem_start);
      }
      spilled_regs = GetSpilledRegistersForInspection();
    }
    out_of_line_code_.push_back(OutOfLineCode::StackCheck(
        zone_, position, regs_to_save, __ cache_state()->cached_instance_data,
        spilled_regs, safepoint_info, RegisterOOLDebugSideTableEntry(decoder)));
    OutOfLineCode& ool = out_of_line_code_.back();
    __ StackCheck(ool.label.get());
    __ bind(ool.continuation.get());
  }

  void TierupCheck(FullDecoder* decoder, WasmCodePosition position,
                   int budget_used) {
    if (for_debugging_ != kNotForDebugging) return;
    SCOPED_CODE_COMMENT("tierup check");
    budget_used += kTierUpCostForCheck;
    // We never want to blow the entire budget at once.
    const int max_budget_use = std::max(1, v8_flags.wasm_tiering_budget / 4);
    if (budget_used > max_budget_use) budget_used = max_budget_use;

    // We should always decrement the budget, and we don't expect integer
    // overflows in the budget calculation.
    DCHECK_LE(1, budget_used);

    SpilledRegistersForInspection* spilled_regs = nullptr;

    OutOfLineSafepointInfo* safepoint_info =
        zone_->New<OutOfLineSafepointInfo>(zone_);
    __ cache_state()->GetTaggedSlotsForOOLCode(
        &safepoint_info->slots, &safepoint_info->spills,
        LiftoffAssembler::CacheState::SpillLocation::kTopOfStack);

    LiftoffRegList regs_to_save = __ cache_state()->used_registers;
    // The cached instance will be reloaded separately.
    if (__ cache_state()->cached_instance_data != no_reg) {
      DCHECK(regs_to_save.has(__ cache_state()->cached_instance_data));
      regs_to_save.clear(__ cache_state()->cached_instance_data);
    }

    out_of_line_code_.push_back(OutOfLineCode::TierupCheck(
        zone_, position, regs_to_save, __ cache_state()->cached_instance_data,
        spilled_regs, safepoint_info, RegisterOOLDebugSideTableEntry(decoder)));
    OutOfLineCode& ool = out_of_line_code_.back();

    FREEZE_STATE(tierup_check);
    __ CheckTierUp(declared_function_index(env_->module, func_index_),
                   budget_used, ool.label.get(), tierup_check);

    __ bind(ool.continuation.get());
  }

  bool SpillLocalsInitially(FullDecoder* decoder, uint32_t num_params) {
    int actual_locals = __ num_locals() - num_params;
    DCHECK_LE(0, actual_locals);
    constexpr int kNumCacheRegisters = kLiftoffAssemblerGpCacheRegs.Count();
    // If we have many locals, we put them on the stack initially. This avoids
    // having to spill them on merge points. Use of these initial values should
    // be rare anyway.
    if (actual_locals > kNumCacheRegisters / 2) return true;
    // If there are locals which are not i32 or i64, we also spill all locals,
    // because other types cannot be initialized to constants.
    for (uint32_t param_idx = num_params; param_idx < __ num_locals();
         ++param_idx) {
      ValueKind kind = __ local_kind(param_idx);
      if (kind != kI32 && kind != kI64) return true;
    }
    return false;
  }

  V8_NOINLINE V8_PRESERVE_MOST void TraceFunctionEntry(FullDecoder* decoder) {
    CODE_COMMENT("trace function entry");
    __ SpillAllRegisters();
    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(decoder->position()), false);
    __ CallBuiltin(Builtin::kWasmTraceEnter);
    DefineSafepoint();
  }

  bool dynamic_tiering() {
    return env_->dynamic_tiering && for_debugging_ == kNotForDebugging &&
           (v8_flags.wasm_tier_up_filter == -1 ||
            v8_flags.wasm_tier_up_filter == func_index_);
  }

  void StartFunctionBody(FullDecoder* decoder, Control* block) {
    for (uint32_t i = 0; i < __ num_locals(); ++i) {
      if (!CheckSupportedType(decoder, __ local_kind(i), "param")) return;
    }

    // Parameter 0 is the instance data.
    uint32_t num_params =
        static_cast<uint32_t>(decoder->sig_->parameter_count());

    __ CodeEntry();

    if (v8_flags.wasm_inlining) {
      CODE_COMMENT("frame setup");
      int declared_func_index =
          func_index_ - env_->module->num_imported_functions;
      DCHECK_GE(declared_func_index, 0);
      __ CallFrameSetupStub(declared_func_index);
    } else {
      __ EnterFrame(StackFrame::WASM);
    }
    __ set_has_frame(true);
    pc_offset_stack_frame_construction_ = __ PrepareStackFrame();
    // {PrepareStackFrame} is the first platform-specific assembler method.
    // If this failed, we can bail out immediately, avoiding runtime overhead
    // and potential failures because of other unimplemented methods.
    // A platform implementing {PrepareStackFrame} must ensure that we can
    // finish compilation without errors even if we hit unimplemented
    // LiftoffAssembler methods.
    if (DidAssemblerBailout(decoder)) return;

    // Input 0 is the call target, the trusted instance data is at 1.
    [[maybe_unused]] constexpr int kInstanceDataParameterIndex = 1;
    // Check that {kWasmImplicitArgRegister} matches our call descriptor.
    DCHECK_EQ(kWasmImplicitArgRegister,
              Register::from_code(
                  descriptor_->GetInputLocation(kInstanceDataParameterIndex)
                      .AsRegister()));
    __ cache_state() -> SetInstanceCacheRegister(kWasmImplicitArgRegister);

    if (num_params) {
      CODE_COMMENT("process parameters");
      ParameterProcessor processor(this, num_params);
      processor.Process();
    }
    int params_size = __ TopSpillOffset();

    // Initialize locals beyond parameters.
    if (num_params < __ num_locals()) CODE_COMMENT("init locals");
    if (SpillLocalsInitially(decoder, num_params)) {
      bool has_refs = false;
      for (uint32_t param_idx = num_params; param_idx < __ num_locals();
           ++param_idx) {
        ValueKind kind = __ local_kind(param_idx);
        has_refs |= is_reference(kind);
        __ PushStack(kind);
      }
      int spill_size = __ TopSpillOffset() - params_size;
      __ FillStackSlotsWithZero(params_size, spill_size);

      // Initialize all reference type locals with ref.null.
      if (has_refs) {
        LiftoffRegList pinned;
        Register null_ref_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned).gp());
        Register wasm_null_ref_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned).gp());
        LoadNullValue(null_ref_reg, kWasmExternRef);
        LoadNullValue(wasm_null_ref_reg, kWasmAnyRef);
        for (uint32_t local_index = num_params; local_index < __ num_locals();
             ++local_index) {
          ValueType type = decoder->local_types_[local_index];
          if (type.is_reference()) {
            __ Spill(__ cache_state()->stack_state[local_index].offset(),
                     type.use_wasm_null() ? LiftoffRegister(wasm_null_ref_reg)
                                          : LiftoffRegister(null_ref_reg),
                     type.kind());
          }
        }
      }
    } else {
      for (uint32_t param_idx = num_params; param_idx < __ num_locals();
           ++param_idx) {
        ValueKind kind = __ local_kind(param_idx);
        // Anything which is not i32 or i64 requires spilling.
        DCHECK(kind == kI32 || kind == kI64);
        __ PushConstant(kind, int32_t{0});
      }
    }

    DCHECK_EQ(__ num_locals(), __ cache_state()->stack_height());

    if (V8_UNLIKELY(debug_sidetable_builder_)) {
      debug_sidetable_builder_->SetNumLocals(__ num_locals());
    }

    if (V8_UNLIKELY(for_debugging_)) {
      __ ResetOSRTarget();
      if (V8_UNLIKELY(max_steps_)) {
        // Generate the single OOL code to jump to if {max_steps_} have been
        // executed.
        DCHECK_EQ(0, out_of_line_code_.size());
        // This trap is never intercepted (e.g. by a debugger), so we do not
        // need safepoint information (which would be difficult to compute if
        // the OOL code is shared).
        out_of_line_code_.push_back(OutOfLineCode::Trap(
            zone_, Builtin::kThrowWasmTrapUnreachable, decoder->position(),
            nullptr, nullptr, nullptr));

        // Subtract 16 steps for the function call itself (including the
        // function prologue), plus 1 for each local (including parameters). Do
        // this only *after* setting up the frame completely, even though we
        // already executed the work then.
        CheckMaxSteps(decoder, 16 + __ num_locals());
      }
    } else {
      DCHECK(!max_steps_);
    }

    // If debug code is enabled, assert that the first parameter is a
    // WasmTrustedInstanceData.
    if (v8_flags.debug_code) {
      SCOPED_CODE_COMMENT("Check instance data parameter type");
      LiftoffRegList pinned;
      Register scratch = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      Register instance = pinned.set(LoadInstanceIntoRegister(pinned, scratch));
      // Load the map.
      __ LoadMap(scratch, instance);
      // Load the instance type.
      __ Load(LiftoffRegister{scratch}, scratch, no_reg,
              wasm::ObjectAccess::ToTagged(Map::kInstanceTypeOffset),
              LoadType::kI32Load16U);
      // If not WASM_TRUSTED_INSTANCE_DATA_TYPE -> error.
      Label ok;
      FreezeCacheState frozen{asm_};
      __ emit_i32_cond_jumpi(kEqual, &ok, scratch,
                             WASM_TRUSTED_INSTANCE_DATA_TYPE, frozen);
      __ AssertUnreachable(AbortReason::kUnexpectedInstanceType);
      __ bind(&ok);
    }

    // The function-prologue stack check is associated with position 0, which
    // is never a position of any instruction in the function.
    StackCheck(decoder, 0);

    if (V8_UNLIKELY(v8_flags.trace_wasm)) TraceFunctionEntry(decoder);
  }

  void GenerateOutOfLineCode(OutOfLineCode* ool) {
    CODE_COMMENT((std::string("OOL: ") + Builtins::name(ool->builtin)).c_str());
    __ bind(ool->label.get());
    const bool is_stack_check =
        ool->builtin == Builtin::kWasmStackGuard ||
        ool->builtin == Builtin::kWasmGrowableStackGuard;
    const bool is_tierup = ool->builtin == Builtin::kWasmTriggerTierUp;

    if (!ool->regs_to_save.is_empty()) {
      __ PushRegisters(ool->regs_to_save);
    }
    if (V8_UNLIKELY(ool->spilled_registers != nullptr)) {
      for (auto& entry : ool->spilled_registers->entries) {
        // We should not push and spill the same register.
        DCHECK(!ool->regs_to_save.has(entry.reg));
        __ Spill(entry.offset, entry.reg, entry.kind);
      }
    }

    if (ool->builtin == Builtin::kWasmGrowableStackGuard) {
      WasmGrowableStackGuardDescriptor descriptor;
      DCHECK_EQ(0, descriptor.GetStackParameterCount());
      DCHECK_EQ(1, descriptor.GetRegisterParameterCount());
      Register param_reg = descriptor.GetRegisterParameter(0);
      __ LoadConstant(LiftoffRegister(param_reg),
                      WasmValue::ForUintPtr(descriptor_->ParameterSlotCount() *
                                            LiftoffAssembler::kStackSlotSize));
    }

    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(ool->position), true);
    __ CallBuiltin(ool->builtin);
    // It is safe to not check for existing safepoint at this address since we
    // just emitted a call.
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_);

    if (ool->safepoint_info) {
      for (auto index : ool->safepoint_info->slots) {
        safepoint.DefineTaggedStackSlot(index);
      }

      int total_frame_size = __ GetTotalFrameSize();
      // {total_frame_size} is the highest offset from the FP that is used to
      // store a value. The offset of the first spill slot should therefore be
      // {(total_frame_size / kSystemPointerSize) + 1}. However, spill slots
      // don't start at offset '0' but at offset '-1' (or
      // {-kSystemPointerSize}). Therefore we have to add another '+ 1' to the
      // index of the first spill slot.
      int index = (total_frame_size / kSystemPointerSize) + 2;

      __ RecordSpillsInSafepoint(safepoint, ool->regs_to_save,
                                 ool->safepoint_info->spills, index);
    }

    DCHECK_EQ(!debug_sidetable_builder_, !ool->debug_sidetable_entry_builder);
    if (V8_UNLIKELY(ool->debug_sidetable_entry_builder)) {
      ool->debug_sidetable_entry_builder->set_pc_offset(__ pc_offset());
    }
    DCHECK_EQ(ool->continuation.get()->is_bound(), is_stack_check || is_tierup);
    if (is_stack_check) {
      MaybeOSR();
    }
    if (!ool->regs_to_save.is_empty()) __ PopRegisters(ool->regs_to_save);
    if (is_stack_check || is_tierup) {
      if (V8_UNLIKELY(ool->spilled_registers != nullptr)) {
        DCHECK(for_debugging_);
        for (auto& entry : ool->spilled_registers->entries) {
          __ Fill(entry.reg, entry.offset, entry.kind);
        }
      }
      if (ool->cached_instance_data != no_reg) {
        __ LoadInstanceDataFromFrame(ool->cached_instance_data);
      }
      __ emit_jump(ool->continuation.get());
    } else {
      __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
    }
  }

  void FinishFunction(FullDecoder* decoder) {
    if (DidAssemblerBailout(decoder)) return;
    __ AlignFrameSize();
#if DEBUG
    int frame_size = __ GetTotalFrameSize();
#endif
    for (OutOfLineCode& ool : out_of_line_code_) {
      GenerateOutOfLineCode(&ool);
    }
    DCHECK_EQ(frame_size, __ GetTotalFrameSize());
    __ PatchPrepareStackFrame(pc_offset_stack_frame_construction_,
                              &safepoint_table_builder_, v8_flags.wasm_inlining,
                              descriptor_->ParameterSlotCount());
    __ FinishCode();
    safepoint_table_builder_.Emit(&asm_, __ GetTotalFrameSlotCountForGC());
    // Emit the handler table.
    if (!handlers_.empty()) {
      handler_table_offset_ = HandlerTable::EmitReturnTableStart(&asm_);
      for (auto& handler : handlers_) {
        HandlerTable::EmitReturnEntry(&asm_, handler.pc_offset,
                                      handler.handler.get()->pos());
      }
    }
    __ MaybeEmitOutOfLineConstantPool();
    // The previous calls may have also generated a bailout.
    DidAssemblerBailout(decoder);
    DCHECK_EQ(num_exceptions_, 0);

    if (v8_flags.wasm_inlining && !encountered_call_instructions_.empty()) {
      // Update the call targets stored in the WasmModule.
      TypeFeedbackStorage& type_feedback = env_->module->type_feedback;
      base::SharedMutexGuard<base::kExclusive> mutex_guard(
          &type_feedback.mutex);
      FunctionTypeFeedback& function_feedback =
          type_feedback.feedback_for_function[func_index_];
      function_feedback.liftoff_frame_size = __ GetTotalFrameSize();
      base::OwnedVector<uint32_t>& call_targets =
          function_feedback.call_targets;
      if (call_targets.empty()) {
        call_targets =
            base::OwnedVector<uint32_t>::Of(encountered_call_instructions_);
      } else {
        DCHECK_EQ(call_targets.as_vector(),
                  base::VectorOf(encountered_call_instructions_));
      }
    }

    if (frame_description_) {
      frame_description_->total_frame_size = __ GetTotalFrameSize();
    }
  }

  void OnFirstError(FullDecoder* decoder) {
    if (!did_bailout()) bailout_reason_ = kDecodeError;
    UnuseLabels(decoder);
    asm_.AbortCompilation();
  }

  // Rule of thumb: an instruction is "heavy" when its runtime is linear in
  // some random variable that the fuzzer generates.
#define FUZZER_HEAVY_INSTRUCTION                      \
  do {                                                \
    if (V8_UNLIKELY(max_steps_ != nullptr)) {         \
      CheckMaxSteps(decoder, kHeavyInstructionSteps); \
    }                                                 \
  } while (false)

  V8_NOINLINE void CheckMaxSteps(FullDecoder* decoder, int steps_done = 1) {
    DCHECK_LE(1, steps_done);
    SCOPED_CODE_COMMENT("check max steps");
    LiftoffRegList pinned;
    LiftoffRegister max_steps = pinned.set(__ GetUnusedRegister(kGpReg, {}));
    LiftoffRegister max_steps_addr =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    {
      FREEZE_STATE(frozen);
      __ LoadConstant(
          max_steps_addr,
          WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(max_steps_)));
      __ Load(max_steps, max_steps_addr.gp(), no_reg, 0, LoadType::kI32Load);
      // Subtract first (and store the result), so the caller sees that
      // max_steps ran negative. Since we never subtract too much at once, we
      // cannot underflow.
      DCHECK_GE(kMaxInt / 16, steps_done);  // An arbitrary limit.
      __ emit_i32_subi(max_steps.gp(), max_steps.gp(), steps_done);
      __ Store(max_steps_addr.gp(), no_reg, 0, max_steps, StoreType::kI32Store,
               pinned);
      // Abort if max steps have been executed.
      DCHECK_EQ(Builtin::kThrowWasmTrapUnreachable,
                out_of_line_code_.front().builtin);
      Label* trap_label = out_of_line_code_.front().label.get();
      __ emit_i32_cond_jumpi(kLessThan, trap_label, max_steps.gp(), 0, frozen);
    }
  }

  V8_NOINLINE void EmitDebuggingInfo(FullDecoder* decoder, WasmOpcode opcode) {
    DCHECK(for_debugging_);

    // Snapshot the value types (from the decoder) here, for potentially
    // building a debug side table entry later. Arguments will have been popped
    // from the stack later (when we need them), and Liftoff does not keep
    // precise type information.
    stack_value_types_for_debugging_ = GetStackValueTypesForDebugging(decoder);

    if (!WasmOpcodes::IsBreakable(opcode)) return;

    bool has_breakpoint = false;
    if (next_breakpoint_ptr_) {
      if (*next_breakpoint_ptr_ == 0) {
        // A single breakpoint at offset 0 indicates stepping.
        DCHECK_EQ(next_breakpoint_ptr_ + 1, next_breakpoint_end_);
        has_breakpoint = true;
      } else {
        while (next_breakpoint_ptr_ != next_breakpoint_end_ &&
               *next_breakpoint_ptr_ < decoder->position()) {
          // Skip unreachable breakpoints.
          ++next_breakpoint_ptr_;
        }
        if (next_breakpoint_ptr_ == next_breakpoint_end_) {
          next_breakpoint_ptr_ = next_breakpoint_end_ = nullptr;
        } else if (*next_breakpoint_ptr_ == decoder->position()) {
          has_breakpoint = true;
        }
      }
    }
    if (has_breakpoint) {
      CODE_COMMENT("breakpoint");
      EmitBreakpoint(decoder);
      // Once we emitted an unconditional breakpoint, we don't need to check
      // function entry breaks any more.
      did_function_entry_break_checks_ = true;
    } else if (!did_function_entry_break_checks_) {
      did_function_entry_break_checks_ = true;
      CODE_COMMENT("check function entry break");
      Label do_break;
      Label no_break;
      Register flag = __ GetUnusedRegister(kGpReg, {}).gp();

      // Check the "hook on function call" flag. If set, trigger a break.
      LOAD_INSTANCE_FIELD(flag, HookOnFunctionCallAddress, kSystemPointerSize,
                          {});
      FREEZE_STATE(frozen);
      __ Load(LiftoffRegister{flag}, flag, no_reg, 0, LoadType::kI32Load8U, {});
      __ emit_cond_jump(kNotZero, &do_break, kI32, flag, no_reg, frozen);

      // Check if we should stop on "script entry".
      LOAD_INSTANCE_FIELD(flag, BreakOnEntry, kUInt8Size, {});
      __ emit_cond_jump(kZero, &no_break, kI32, flag, no_reg, frozen);

      __ bind(&do_break);
      EmitBreakpoint(decoder);
      __ bind(&no_break);
    } else if (dead_breakpoint_ == decoder->position()) {
      DCHECK(!next_breakpoint_ptr_ ||
             *next_breakpoint_ptr_ != dead_breakpoint_);
      // The top frame is paused at this position, but the breakpoint was
      // removed. Adding a dead breakpoint here ensures that the source
      // position exists, and that the offset to the return address is the
      // same as in the old code.
      CODE_COMMENT("dead breakpoint");
      Label cont;
      __ emit_jump(&cont);
      EmitBreakpoint(decoder);
      __ bind(&cont);
    }
    if (V8_UNLIKELY(max_steps_ != nullptr)) {
      CheckMaxSteps(decoder);
    }
  }

  void NextInstruction(FullDecoder* decoder, WasmOpcode opcode) {
    TraceCacheState(decoder);
    SLOW_DCHECK(__ ValidateCacheState());
    CODE_COMMENT(WasmOpcodes::OpcodeName(
        WasmOpcodes::IsPrefixOpcode(opcode)
            ? decoder->read_prefixed_opcode<ValidationTag>(decoder->pc()).first
            : opcode));

    if (!has_outstanding_op() && decoder->control_at(0)->reachable()) {
      // Decoder stack and liftoff stack have to be in sync if current code
      // path is reachable.
      DCHECK_EQ(decoder->stack_size() + __ num_locals() + num_exceptions_,
                __ cache_state()->stack_state.size());
    }

    // Add a single check, so that the fast path can be inlined while
    // {EmitDebuggingInfo} stays outlined.
    if (V8_UNLIKELY(for_debugging_)) EmitDebuggingInfo(decoder, opcode);
  }

  void EmitBreakpoint(FullDecoder* decoder) {
    DCHECK(for_debugging_);
    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(decoder->position()), true);
    __ CallBuiltin(Builtin::kWasmDebugBreak);
    DefineSafepointWithCalleeSavedRegisters();
    RegisterDebugSideTableEntry(decoder,
                                DebugSideTableBuilder::kAllowRegisters);
    MaybeOSR();
  }

  void PushControl(Control* block) {
    // The Liftoff stack includes implicit exception refs stored for catch
    // blocks, so that they can be rethrown.
    block->num_exceptions = num_exceptions_;
  }

  void Block(FullDecoder* decoder, Control* block) { PushControl(block); }

  void Loop(FullDecoder* decoder, Control* loop) {
    // Before entering a loop, spill all locals to the stack, in order to free
    // the cache registers, and to avoid unnecessarily reloading stack values
    // into registers at branches.
    // TODO(clemensb): Come up with a better strategy here, involving
    // pre-analysis of the function.
    __ SpillLocals();

    __ SpillLoopArgs(loop->start_merge.arity);

    // Loop labels bind at the beginning of the block.
    __ bind(loop->label.get());

    // Save the current cache state for the merge when jumping to this loop.
    loop->label_state.Split(*__ cache_state());

    PushControl(loop);

    if (!dynamic_tiering()) {
      // When the budget-based tiering mechanism is enabled, use that to
      // check for interrupt requests; otherwise execute a stack check in the
      // loop header.
      StackCheck(decoder, decoder->position());
    }
  }

  void Try(FullDecoder* decoder, Control* block) {
    block->try_info = zone_->New<TryInfo>(zone_);
    PushControl(block);
  }

  // Load the property in {kReturnRegister0}.
  LiftoffRegister GetExceptionProperty(const VarState& exception,
                                       RootIndex root_index) {
    DCHECK(root_index == RootIndex::kwasm_exception_tag_symbol ||
           root_index == RootIndex::kwasm_exception_values_symbol);

    LiftoffRegList pinned;
    LiftoffRegister tag_symbol_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadExceptionSymbol(tag_symbol_reg.gp(), pinned, root_index);
    LiftoffRegister context_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LOAD_TAGGED_PTR_INSTANCE_FIELD(context_reg.gp(), NativeContext, pinned);

    VarState tag_symbol{kRef, tag_symbol_reg, 0};
    VarState context{kRef, context_reg, 0};

    CallBuiltin(Builtin::kWasmGetOwnProperty,
                MakeSig::Returns(kRef).Params(kRef, kRef, kRef),
                {exception, tag_symbol, context}, kNoSourcePosition);

    return LiftoffRegister(kReturnRegister0);
  }

  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    DCHECK(block->is_try_catch());
    __ emit_jump(block->label.get());

    // This is the last use of this label. Re-use the field for the label of the
    // next catch block, and jump there if the tag does not match.
    __ bind(&block->try_info->catch_label);
    block->try_info->catch_label.Unuse();
    block->try_info->catch_label.UnuseNear();

    __ cache_state()->Split(block->try_info->catch_state);

    CODE_COMMENT("load caught exception tag");
    DCHECK_EQ(__ cache_state()->stack_state.back().kind(), kRef);
    LiftoffRegister caught_tag =
        GetExceptionProperty(__ cache_state()->stack_state.back(),
                             RootIndex::kwasm_exception_tag_symbol);
    LiftoffRegList pinned;
    pinned.set(caught_tag);

    CODE_COMMENT("load expected exception tag");
    Register imm_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(imm_tag, TagsTable, pinned);
    __ LoadTaggedPointer(
        imm_tag, imm_tag, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    CODE_COMMENT("compare tags");

    if (imm.tag->sig->parameter_count() == 1 &&
        imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise we know
      // statically that it cannot be the JSTag.
      LiftoffRegister undefined =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      __ LoadFullPointer(
          undefined.gp(), kRootRegister,
          IsolateData::root_slot_offset(RootIndex::kUndefinedValue));
      LiftoffRegister js_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      LOAD_TAGGED_PTR_INSTANCE_FIELD(js_tag.gp(), NativeContext, pinned);
      __ LoadTaggedPointer(
          js_tag.gp(), js_tag.gp(), no_reg,
          NativeContext::SlotOffset(Context::WASM_JS_TAG_INDEX));
      __ LoadTaggedPointer(
          js_tag.gp(), js_tag.gp(), no_reg,
          wasm::ObjectAccess::ToTagged(WasmTagObject::kTagOffset));
      {
        LiftoffAssembler::CacheState initial_state(zone_);
        LiftoffAssembler::CacheState end_state(zone_);
        Label js_exception;
        Label done;
        Label uncaught;
        initial_state.Split(*__ cache_state());
        {
          FREEZE_STATE(state_merged_explicitly);
          // If the tag is undefined, this is not a wasm exception. Go to a
          // different block to process the JS exception. Otherwise compare it
          // with the expected tag.
          __ emit_cond_jump(kEqual, &js_exception, kRefNull, caught_tag.gp(),
                            undefined.gp(), state_merged_explicitly);
          __ emit_cond_jump(kNotEqual, &uncaught, kRefNull, imm_tag,
                            caught_tag.gp(), state_merged_explicitly);
        }
        // Case 1: A wasm exception with a matching tag.
        GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                           imm.tag);
        // GetExceptionValues modified the cache state. Remember the new state
        // to merge the end state of case 2 into it.
        end_state.Steal(*__ cache_state());
        __ emit_jump(&done);

        __ bind(&js_exception);
        __ cache_state()->Split(initial_state);
        {
          FREEZE_STATE(state_merged_explicitly);
          __ emit_cond_jump(kNotEqual, &uncaught, kRefNull, imm_tag,
                            js_tag.gp(), state_merged_explicitly);
        }
        // Case 2: A JS exception, and the expected tag is JSTag.
        // TODO(thibaudm): Can we avoid some state splitting/stealing by
        // reserving this register earlier and not modifying the state in this
        // block?
        LiftoffRegister exception = __ PeekToRegister(0, pinned);
        __ PushRegister(kRef, exception);
        // The exception is now on the stack twice: once as an implicit operand
        // for rethrow, and once as the "unpacked" value.
        __ MergeFullStackWith(end_state);
        __ emit_jump(&done);

        // Case 3: Either a wasm exception with a mismatching tag, or a JS
        // exception but the expected tag is not JSTag.
        __ bind(&uncaught);
        __ cache_state()->Steal(initial_state);
        __ MergeFullStackWith(block->try_info->catch_state);
        __ emit_jump(&block->try_info->catch_label);

        __ bind(&done);
        __ cache_state()->Steal(end_state);
      }
    } else {
      {
        FREEZE_STATE(frozen);
        Label caught;
        __ emit_cond_jump(kEqual, &caught, kRefNull, imm_tag, caught_tag.gp(),
                          frozen);
        // The tags don't match, merge the current state into the catch state
        // and jump to the next handler.
        __ MergeFullStackWith(block->try_info->catch_state);
        __ emit_jump(&block->try_info->catch_label);
        __ bind(&caught);
      }
      GetExceptionValues(decoder, __ cache_state()->stack_state.back(),
                         imm.tag);
    }
    if (!block->try_info->in_handler) {
      block->try_info->in_handler = true;
      num_exceptions_++;
    }
  }

  void Rethrow(FullDecoder* decoder, const VarState& exception) {
    CallBuiltin(Builtin::kWasmRethrow, MakeSig::Params(kRef), {exception},
                decoder->position());
  }

  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    DCHECK_EQ(block, decoder->control_at(0));
    Control* target = decoder->control_at(depth);
    DCHECK(block->is_incomplete_try());
    __ bind(&block->try_info->catch_label);
    if (block->try_info->catch_reached) {
      __ cache_state()->Steal(block->try_info->catch_state);
      if (depth == decoder->control_depth() - 1) {
        // Delegate to the caller, do not emit a landing pad.
        Rethrow(decoder, __ cache_state()->stack_state.back());
        MaybeOSR();
      } else {
        DCHECK(target->is_incomplete_try());
        if (target->try_info->catch_reached) {
          __ MergeStackWith(target->try_info->catch_state, 1,
                            LiftoffAssembler::kForwardJump);
        } else {
          target->try_info->catch_state = __ MergeIntoNewState(
              __ num_locals(), 1, target->stack_depth + target->num_exceptions);
          target->try_info->catch_reached = true;
        }
        __ emit_jump(&target->try_info->catch_label);
      }
    }
  }

  void Rethrow(FullDecoder* decoder, Control* try_block) {
    int index = try_block->try_info->catch_state.stack_height() - 1;
    auto& exception = __ cache_state()->stack_state[index];
    Rethrow(decoder, exception);
    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
  }

  void CatchAll(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    DCHECK_EQ(decoder->control_at(0), block);
    __ bind(&block->try_info->catch_label);
    __ cache_state()->Split(block->try_info->catch_state);
    if (!block->try_info->in_handler) {
      block->try_info->in_handler = true;
      num_exceptions_++;
    }
  }

  void TryTable(FullDecoder* decoder, Control* block) {
    block->try_info = zone_->New<TryInfo>(zone_);
    PushControl(block);
  }

  void CatchCase(FullDecoder* decoder, Control* block,
                 const CatchCase& catch_case, base::Vector<Value> values) {
    DCHECK(block->is_try_table());

    // This is the last use of this label. Re-use the field for the label of the
    // next catch block, and jump there if the tag does not match.
    __ bind(&block->try_info->catch_label);
    block->try_info->catch_label.Unuse();
    block->try_info->catch_label.UnuseNear();
    __ cache_state()->Split(block->try_info->catch_state);

    if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
      // The landing pad pushed the exception on the stack, so keep
      // it there for {kCatchAllRef}, and drop it for {kCatchAll}.
      if (catch_case.kind == kCatchAll) {
        __ DropValues(1);
      }
      BrOrRet(decoder, catch_case.br_imm.depth);
      return;
    }

    CODE_COMMENT("load caught exception tag");
    DCHECK_EQ(__ cache_state()->stack_state.back().kind(), kRef);
    LiftoffRegister caught_tag =
        GetExceptionProperty(__ cache_state()->stack_state.back(),
                             RootIndex::kwasm_exception_tag_symbol);
    LiftoffRegList pinned;
    pinned.set(caught_tag);

    CODE_COMMENT("load expected exception tag");
    Register imm_tag = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(imm_tag, TagsTable, pinned);
    __ LoadTaggedPointer(imm_tag, imm_tag, no_reg,
                         wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                             catch_case.maybe_tag.tag_imm.index));

    VarState exn = __ cache_state() -> stack_state.back();

    CODE_COMMENT("compare tags");
    if (catch_case.maybe_tag.tag_imm.tag->sig->parameter_count() == 1 &&
        catch_case.maybe_tag.tag_imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise we know
      // statically that it cannot be the
```