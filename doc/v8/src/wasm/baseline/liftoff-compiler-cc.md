Response:
The user wants a summary of the functionality of the C++ code in `v8/src/wasm/baseline/liftoff-compiler.cc`. I need to extract the main responsibilities of this file based on the included headers and the code itself.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The file name `liftoff-compiler.cc` strongly suggests this file is responsible for implementing the Liftoff compiler, a baseline compiler for WebAssembly in V8.

2. **Analyze included headers:** The included headers provide clues about the functionalities involved:
    * `src/wasm/baseline/liftoff-compiler.h`:  The header file for this source file, likely defining the public interface.
    * `src/codegen/assembler-inl.h`, `src/codegen/macro-assembler-inl.h`:  Indicate code generation and assembly manipulation.
    * `src/compiler/wasm-compiler.h`:  Suggests integration with the overall WebAssembly compilation pipeline.
    * `src/wasm/baseline/liftoff-assembler-inl.h`:  Points to the Liftoff-specific assembler.
    * `src/wasm/function-body-decoder-impl.h`:  Implies decoding and processing of the WebAssembly function body.
    * `src/wasm/wasm-objects.h`, `src/wasm/wasm-opcodes-inl.h`:  Deal with WebAssembly structures and opcodes.

3. **Examine the code structure and key classes:**
    * `LiftoffCompiler` class: The central class, likely orchestrating the compilation process.
    * `LiftoffAssembler`: Handles the low-level assembly generation.
    * `DebugSideTableBuilder`:  Manages the creation of debug information.
    * `OutOfLineCode`:  Deals with code that is generated outside the main instruction stream, like trap handlers or stack checks.

4. **Infer functionalities from the code snippets:**
    * **Memory Management:** `#define LOAD_INSTANCE_FIELD` suggests loading data from memory related to the WebAssembly instance.
    * **Control Flow:**  `ElseState`, `TryInfo`, and `Control` structures indicate handling of control flow constructs like `if-else` and `try-catch`.
    * **Register Allocation:** `TempRegisterScope` and `ScopedTempRegister` suggest temporary register management.
    * **Function Compilation:** `StartFunction` indicates the beginning of the compilation process for a function. `ParameterProcessor` handles function parameters.
    * **Stack Management:** `StackCheck` function hints at stack overflow protection.
    * **Tier-Up:** `TierupCheck` suggests integration with V8's tiered compilation system.
    * **Debugging:** `DebugSideTableBuilder`, `SpilledRegistersForInspection`, and mentions of breakpoints indicate support for debugging WebAssembly code.
    * **Error Handling:**  `bailout_reason_`, `unsupported` function suggest mechanisms for handling unsupported features or errors.

5. **Address specific questions in the prompt:**
    * **`.tq` extension:** The code does not end with `.tq`, so it's not a Torque file.
    * **Relationship to JavaScript:**  WebAssembly interacts with JavaScript. While this specific file might not directly execute JavaScript code, it's a crucial part of the process that allows JavaScript to run WebAssembly.
    * **Code logic inference:** The `GetCompareCondition` function provides a simple example of mapping Wasm opcodes to comparison conditions.
    * **Common programming errors:** The code includes stack checks to prevent stack overflow, a common programming error.

6. **Synthesize a summary:** Combine the observations from the above steps to create a concise description of the file's functionality.

7. **Structure the answer:**  Organize the information logically, addressing each point raised in the prompt. Use clear and concise language.

By following these steps, I can arrive at the comprehensive summary provided in the initial good answer. The process involves code analysis, understanding the purpose of different components, and inferring functionalities from the code structure and names.
```cpp
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
    SNPrintF(buffer, "%s %s", name(kind
### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    budget_used += kTierUpCostFor
```