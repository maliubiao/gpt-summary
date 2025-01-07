Response:
The user wants a summary of the functionality of the provided C++ header file `v8/src/codegen/interface-descriptors.h`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name itself, "interface-descriptors.h", strongly suggests it deals with describing interfaces. Scanning the content confirms this. It defines structures and enums related to describing how functions (built-ins, stubs, etc.) are called.

2. **Key Structures and Enums:**  Focus on the major building blocks:
    * `CallInterfaceDescriptorData`: This class seems to hold the actual description of a call interface (registers used, parameter counts, flags, etc.).
    * `CallDescriptors`: This appears to be a registry or manager for `CallInterfaceDescriptorData` instances, using an enum `Key` to identify them.
    * `CallInterfaceDescriptor`: This is a base class providing access to the data stored in `CallInterfaceDescriptorData`.
    * `StaticCallInterfaceDescriptor`:  A template class for statically defining call interfaces.
    * The various `DEFINE_*` macros are clearly for simplifying the definition of these static descriptors.
    * The `enum class StackArgumentOrder` defines how arguments are arranged on the stack.

3. **Functionality Breakdown:**  Based on the structures and enums, deduce the core functionalities:
    * **Describing Calling Conventions:** The file is about defining how different functions within V8 are called. This includes which registers hold arguments and return values, how arguments are passed on the stack, and other relevant details.
    * **Centralized Definition:** The `CallDescriptors` class acts as a central place to manage these descriptions.
    * **Abstraction:** `CallInterfaceDescriptor` provides an abstract way to access call interface information.
    * **Static Configuration:**  The `StaticCallInterfaceDescriptor` template allows for compile-time definition of call interfaces.

4. **Relate to JavaScript (if applicable):** While this is a low-level C++ file, these descriptors are ultimately used to implement JavaScript features. Think about how built-in JavaScript functions work. The descriptors define how these built-ins are called from within the V8 engine. For example, calling `Array.prototype.push()` will involve using a descriptor.

5. **Torque Connection:** The `#define TORQUE_BUILTIN_LIST_TFC(V)` hints at a connection to Torque. The prompt specifically asks about `.tq` files. Explain that if this were a `.tq` file, it would be a Torque source file, a domain-specific language used in V8 for defining built-ins.

6. **Hypothetical Inputs and Outputs (Code Logic Inference):**  Consider how these descriptors are used. Imagine a scenario where the compiler needs to generate code to call a specific built-in. The input would be the `Key` of the descriptor, and the output would be the information needed to generate the calling sequence (registers, stack offsets, etc.).

7. **Common Programming Errors:** Think about what could go wrong when dealing with calling conventions. Incorrect number of arguments, wrong argument types, or mismatch between the caller's expectations and the callee's definition are common issues.

8. **Structure the Answer:** Organize the information logically. Start with a high-level summary, then delve into the details of the classes and enums, and finally address the specific points raised in the prompt (Torque, JavaScript relation, etc.).

9. **Refine and Elaborate:** Review the generated answer and add more detail where necessary. For instance, explain the purpose of the different flags in `CallInterfaceDescriptorData`. Clarify the role of the macros.

10. **Address the "Part 1 of 4" Constraint:**  Since this is part 1, focus on a general overview of the file's purpose. Avoid going into extreme detail that might be better suited for later parts. The request asks for a "归纳一下它的功能" (summarize its functionality).

By following these steps, the provided detailed and accurate summary of `v8/src/codegen/interface-descriptors.h` can be generated.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_INTERFACE_DESCRIPTORS_H_
#define V8_CODEGEN_INTERFACE_DESCRIPTORS_H_

#include <memory>

#include "src/base/logging.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/register.h"
#include "src/codegen/tnode.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"

namespace v8 {
namespace internal {

#define TORQUE_BUILTIN_LIST_TFC(V)                                            \
  BUILTIN_LIST_FROM_TORQUE(IGNORE_BUILTIN, IGNORE_BUILTIN, V, IGNORE_BUILTIN, \
                           IGNORE_BUILTIN, IGNORE_BUILTIN)

#define INTERFACE_DESCRIPTOR_LIST(V)                 \
  V(Abort)                                           \
  V(Allocate)                                        \
  V(CallApiCallbackGeneric)                          \
  V(CallApiCallbackOptimized)                        \
  V(ApiGetter)                                       \
  V(ArrayConstructor)                                \
  V(ArrayNArgumentsConstructor)                      \
  V(ArrayNoArgumentConstructor)                      \
  V(ArraySingleArgumentConstructor)                  \
  V(AsyncFunctionStackParameter)                     \
  V(BaselineLeaveFrame)                              \
  V(BaselineOutOfLinePrologue)                       \
  V(BigIntToI32Pair)                                 \
  V(BigIntToI64)                                     \
  V(BinaryOp)                                        \
  V(BinaryOp_Baseline)                               \
  V(BinaryOp_WithFeedback)                           \
  V(BinarySmiOp_Baseline)                            \
  V(CallForwardVarargs)                              \
  V(CallFunctionTemplate)                            \
  V(CallFunctionTemplateGeneric)                     \
  V(CallTrampoline)                                  \
  V(CallTrampoline_Baseline)                         \
  V(CallTrampoline_Baseline_Compact)                 \
  V(CallTrampoline_WithFeedback)                     \
  V(CallVarargs)                                     \
  V(CallWithArrayLike)                               \
  V(CallWithArrayLike_WithFeedback)                  \
  V(CallWithSpread)                                  \
  V(CallWithSpread_Baseline)                         \
  V(CallWithSpread_WithFeedback)                     \
  V(CCall)                                           \
  V(CEntryDummy)                                     \
  V(CEntry1ArgvOnStack)                              \
  V(CloneObjectBaseline)                             \
  V(CloneObjectWithVector)                           \
  V(Compare)                                         \
  V(CompareNoContext)                                \
  V(StringEqual)                                     \
  V(Compare_Baseline)                                \
  V(Compare_WithFeedback)                            \
  V(Construct_Baseline)                              \
  V(ConstructForwardVarargs)                         \
  V(ConstructForwardAllArgs)                         \
  V(ConstructForwardAllArgs_Baseline)                \
  V(ConstructForwardAllArgs_WithFeedback)            \
  V(ConstructStub)                                   \
  V(ConstructVarargs)                                \
  V(ConstructWithArrayLike)                          \
  V(Construct_WithFeedback)                          \
  V(ConstructWithSpread)                             \
  V(ConstructWithSpread_Baseline)                    \
  V(ConstructWithSpread_WithFeedback)                \
  V(ContextOnly)                                     \
  V(CopyDataPropertiesWithExcludedProperties)        \
  V(CopyDataPropertiesWithExcludedPropertiesOnStack) \
  V(CppBuiltinAdaptor)                               \
  V(CreateFromSlowBoilerplateHelper)                 \
  V(DefineKeyedOwn)                                  \
  V(DefineKeyedOwnBaseline)                          \
  V(DefineKeyedOwnWithVector)                        \
  V(FastNewObject)                                   \
  V(FindNonDefaultConstructorOrConstruct)            \
  V(ForInPrepare)                                    \
  V(GetIteratorStackParameter)                       \
  V(GetProperty)                                     \
  V(GrowArrayElements)                               \
  V(I32PairToBigInt)                                 \
  V(I64ToBigInt)                                     \
  V(InterpreterCEntry1)                              \
  V(InterpreterCEntry2)                             \
  V(InterpreterDispatch)                             \
  V(InterpreterPushArgsThenCall)                     \
  V(InterpreterPushArgsThenConstruct)                \
  V(JSTrampoline)                                    \
  V(KeyedHasICBaseline)                              \
  V(KeyedHasICWithVector)                            \
  V(KeyedLoad)                                       \
  V(KeyedLoadBaseline)                               \
  V(EnumeratedKeyedLoadBaseline)                     \
  V(KeyedLoadWithVector)                             \
  V(EnumeratedKeyedLoad)                             \
  V(Load)                                            \
  V(LoadBaseline)                                    \
  V(LoadGlobal)                                      \
  V(LoadGlobalBaseline)                              \
  V(LoadGlobalNoFeedback)                            \
  V(LoadGlobalWithVector)                            \
  V(LoadNoFeedback)                                  \
  V(LoadWithReceiverAndVector)                       \
  V(LoadWithReceiverBaseline)                        \
  V(LoadWithVector)                                  \
  V(LookupWithVector)                                \
  V(LookupTrampoline)                                \
  V(LookupBaseline)                                  \
  V(MaglevOptimizeCodeOrTailCallOptimizedCodeSlot)   \
  V(NewHeapNumber)                                   \
  V(NoContext)                                       \
  V(OnStackReplacement)                              \
  V(RegExpTrampoline)                                \
  V(RestartFrameTrampoline)                          \
  V(ResumeGenerator)                                 \
  V(ResumeGeneratorBaseline)                         \
  V(RunMicrotasks)                                   \
  V(RunMicrotasksEntry)                              \
  V(SingleParameterOnStack)                          \
  V(Store)                                           \
  V(StoreNoFeedback)                                 \
  V(StoreBaseline)                                   \
  V(StoreGlobal)                                     \
  V(StoreGlobalBaseline)                             \
  V(StoreGlobalWithVector)                           \
  V(StoreTransition)                                 \
  V(StoreWithVector)                                 \
  V(StringAtAsString)                                \
  V(StringSubstring)                                 \
  V(SuspendGeneratorBaseline)                        \
  V(TypeConversion)                                  \
  V(TypeConversion_Baseline)                         \
  V(TypeConversionNoContext)                         \
  V(Typeof)                                          \
  V(UnaryOp_Baseline)                                \
  V(UnaryOp_WithFeedback)                            \
  V(Void)                                            \
  V(WasmDummy)                                       \
  V(WasmDummyWithJSLinkage)                          \
  V(WasmFloat32ToNumber)                             \
  V(WasmFloat64ToTagged)                             \
  V(WasmJSToWasmWrapper)                             \
  V(WasmToJSWrapper)                                 \
  V(WasmSuspend)                                     \
  V(WasmHandleStackOverflow)                         \
  V(WriteBarrier)                                    \
  V(IndirectPointerWriteBarrier)                     \
  IF_TSAN(V, TSANLoad)                               \
  IF_TSAN(V, TSANStore)                              \
  BUILTIN_LIST_TFS(V)                                \
  TORQUE_BUILTIN_LIST_TFC(V)

enum class StackArgumentOrder {
  kDefault,  // Arguments in the stack are pushed in the default/stub order (the
             // first argument is pushed first).
  kJS,  // Arguments in the stack are pushed in the same order as the one used
        // by JS-to-JS function calls. This should be used if calling a
        // JSFunction or if the builtin is expected to be called directly from a
        // JSFunction. This order is reversed compared to kDefault.
};

class V8_EXPORT_PRIVATE CallInterfaceDescriptorData {
 public:
  enum Flag {
    kNoFlags = 0u,
    kNoContext = 1u << 0,
    // This indicates that the code uses a special frame that does not scan the
    // stack arguments, e.g. EntryFrame. And this allows the code to use
    // untagged stack arguments.
    kNoStackScan = 1u << 1,
    // In addition to the specified parameters, additional arguments can be
    // passed on the stack.
    // This does not indicate if arguments adaption is used or not.
    kAllowVarArgs = 1u << 2,
    // Callee save allocatable_registers.
    kCalleeSaveRegisters = 1u << 3,
  };
  using Flags = base::Flags<Flag>;

  static constexpr int kUninitializedCount = -1;

  CallInterfaceDescriptorData() = default;

  CallInterfaceDescriptorData(const CallInterfaceDescriptorData&) = delete;
  CallInterfaceDescriptorData& operator=(const CallInterfaceDescriptorData&) =
      delete;

  // The passed registers are owned by the caller, and their lifetime is
  // expected to exceed that of this data. In practice, they are expected to
  // be in a static local.
  void InitializeRegisters(Flags flags, CodeEntrypointTag tag, int return_count,
                           int parameter_count, StackArgumentOrder stack_order,
                           int register_parameter_count,
                           const Register* registers,
                           const DoubleRegister* double_registers,
                           const Register* return_registers,
                           const DoubleRegister* return_double_registers);

  // if machine_types is null, then an array of size
  // (return_count + parameter_count) will be created with
  // MachineType::AnyTagged() for each member.
  //
  // if machine_types is not null, then it should be of the size
  // (return_count + parameter_count). Those members of the parameter array will
  // be initialized from {machine_types}, and the rest initialized to
  // MachineType::AnyTagged().
  void InitializeTypes(const MachineType* machine_types,
                       int machine_types_length);

  void Reset();

  bool IsInitialized() const {
    return IsInitializedRegisters() && IsInitializedTypes();
  }

  Flags flags() const { return flags_; }
  CodeEntrypointTag tag() const { return tag_; }
  int return_count() const { return return_count_; }
  int param_count() const { return param_count_; }
  int register_param_count() const { return register_param_count_; }
  Register register_param(int index) const { return register_params_[index]; }
  DoubleRegister double_register_param(int index) const {
    return double_register_params_[index];
  }
  Register register_return(int index) const { return register_returns_[index]; }
  DoubleRegister double_register_return(int index) const {
    return double_register_returns_[index];
  }
  MachineType return_type(int index) const {
    DCHECK_LT(index, return_count_);
    return machine_types_[index];
  }
  MachineType param_type(int index) const {
    DCHECK_LT(index, param_count_);
    return machine_types_[return_count_ + index];
  }
  StackArgumentOrder stack_order() const { return stack_order_; }

  void RestrictAllocatableRegisters(const Register* registers, size_t num) {
    DCHECK(allocatable_registers_.is_empty());
    for (size_t i = 0; i < num; ++i) {
      allocatable_registers_.set(registers[i]);
    }
    DCHECK(!allocatable_registers_.is_empty());
  }

  RegList allocatable_registers() const { return allocatable_registers_; }

 private:
  bool IsInitializedRegisters() const {
    const bool initialized =
        return_count_ != kUninitializedCount &&
        param_count_ != kUninitializedCount &&
        (register_param_count_ == 0 || register_params_ != nullptr);
    // Register initialization happens before type initialization.
    return initialized;
  }
  bool IsInitializedTypes() const {
    const bool initialized = machine_types_ != nullptr;
    // Register initialization happens before type initialization.
    return initialized;
  }

#ifdef DEBUG
  bool AllStackParametersAreTagged() const;
#endif  // DEBUG

  int register_param_count_ = kUninitializedCount;
  int return_count_ = kUninitializedCount;
  int param_count_ = kUninitializedCount;
  Flags flags_ = kNoFlags;
  CodeEntrypointTag tag_ = kDefaultCodeEntrypointTag;
  StackArgumentOrder stack_order_ = StackArgumentOrder::kDefault;

  // Specifying the set of registers that could be used by the register
  // allocator. Currently, it's only used by RecordWrite code stub.
  RegList allocatable_registers_;

  // |registers_params_| defines registers that are used for parameter passing.
  // |machine_types_| defines machine types for resulting values and incomping
  // parameters.
  // The register params array is owned by the caller, and it's expected that it
  // is a static local stored in the caller function. The machine types are
  // allocated dynamically by the InterfaceDescriptor and freed on destruction.
  const Register* register_params_ = nullptr;
  const DoubleRegister* double_register_params_ = nullptr;
  const Register* register_returns_ = nullptr;
  const DoubleRegister* double_register_returns_ = nullptr;
  MachineType* machine_types_ = nullptr;
};

class V8_EXPORT_PRIVATE CallDescriptors : public AllStatic {
 public:
  enum Key {
#define DEF_ENUM(name, ...) name,
    INTERFACE_DESCRIPTOR_LIST(DEF_ENUM)
#undef DEF_ENUM
        NUMBER_OF_DESCRIPTORS
  };

  static void InitializeOncePerProcess();
  static void TearDown();

  static CallInterfaceDescriptorData* call_descriptor_data(
      CallDescriptors::Key key) {
    return &call_descriptor_data_[key];
  }

  static Key GetKey(const CallInterfaceDescriptorData* data) {
    ptrdiff_t index = data - call_descriptor_data_;
    DCHECK_LE(0, index);
    DCHECK_LT(index, CallDescriptors::NUMBER_OF_DESCRIPTORS);
    return static_cast<CallDescriptors::Key>(index);
  }

 private:
  static CallInterfaceDescriptorData
      call_descriptor_data_[NUMBER_OF_DESCRIPTORS];
};

#if defined(V8_TARGET_ARCH_IA32)
// To support all possible cases, we must limit the number of register args for
// TFS builtins on ia32 to 3. Out of the 6 allocatable registers, esi is taken
// as the context register and ebx is the root register. One register must
// remain available to store the jump/call target. Thus 3 registers remain for
// arguments. The reason this applies to TFS builtins specifically is because
// this becomes relevant for builtins used as targets of Torque function
// pointers (which must have a register available to store the target).
// TODO(jgruber): Ideally we should just decrement kMaxBuiltinRegisterParams but
// that comes with its own set of complications. It's possible, but requires
// refactoring the calling convention of other existing stubs.
constexpr int kMaxBuiltinRegisterParams = 4;
constexpr int kMaxTFSBuiltinRegisterParams = 3;
#else
constexpr int kMaxBuiltinRegisterParams = 5;
constexpr int kMaxTFSBuiltinRegisterParams = kMaxBuiltinRegisterParams;
#endif
static_assert(kMaxTFSBuiltinRegisterParams <= kMaxBuiltinRegisterParams);
constexpr int kJSBuiltinRegisterParams = 4;

// Polymorphic base class for call interface descriptors, which defines getters
// for the various descriptor properties via a runtime-loaded
// CallInterfaceDescriptorData field.
class V8_EXPORT_PRIVATE CallInterfaceDescriptor {
 public:
  using Flags = CallInterfaceDescriptorData::Flags;

  CallInterfaceDescriptor() : data_(nullptr) {}
  ~CallInterfaceDescriptor() = default;

  explicit CallInterfaceDescriptor(CallDescriptors::Key key)
      : data_(CallDescriptors::call_descriptor_data(key)) {}

  Flags flags() const { return data()->flags(); }

  CodeEntrypointTag tag() const { return data()->tag(); }

  bool HasContextParameter() const {
    return (flags() & CallInterfaceDescriptorData::kNoContext) == 0;
  }

  bool AllowVarArgs() const {
    return flags() & CallInterfaceDescriptorData::kAllowVarArgs;
  }

  bool CalleeSaveRegisters() const {
    return flags() & CallInterfaceDescriptorData::kCalleeSaveRegisters;
  }

  int GetReturnCount() const { return data()->return_count(); }

  MachineType GetReturnType(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->return_type(index);
  }

  int GetParameterCount() const { return data()->param_count(); }

  int GetRegisterParameterCount() const {
    return data()->register_param_count();
  }

  int GetStackParameterCount() const {
    return data()->param_count() - data()->register_param_count();
  }

  Register GetRegisterParameter(int index) const {
    DCHECK_LT(index, data()->register_param_count());
    return data()->register_param(index);
  }

  DoubleRegister GetDoubleRegisterParameter(int index) const {
    DCHECK_LT(index, data()->register_param_count());
    return data()->double_register_param(index);
  }

  Register GetRegisterReturn(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->register_return(index);
  }

  DoubleRegister GetDoubleRegisterReturn(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->double_register_return(index);
  }

  MachineType GetParameterType(int index) const {
    DCHECK_LT(index, data()->param_count());
    return data()->param_type(index);
  }

  RegList allocatable_registers() const {
    return data()->allocatable_registers();
  }

  StackArgumentOrder GetStackArgumentOrder() const {
    return data()->stack_order();
  }

  static constexpr inline Register ContextRegister() {
    return kContextRegister;
  }

  const char* DebugName() const;

  bool operator==(const CallInterfaceDescriptor& other) const {
    return data() == other.data();
  }

 protected:
  const CallInterfaceDescriptorData* data() const { return data_; }

  // Helper for defining the default register set.
  //
  // Use auto for the return type to allow different architectures to have
  // differently sized default register arrays.
  static constexpr inline auto DefaultRegisterArray();
  static constexpr inline auto DefaultDoubleRegisterArray();
  static constexpr inline auto DefaultReturnRegisterArray();
  static constexpr inline auto DefaultReturnDoubleRegisterArray();
  static constexpr inline std::array<Register, kJSBuiltinRegisterParams>
  DefaultJSRegisterArray();

  // Checks if float parameters are not assigned invalid registers.
  bool CheckFloatingPointParameters(CallInterfaceDescriptorData* data) {
    for (int i = 0; i < data->register_param_count(); i++) {
      if (IsFloatingPoint(data->param_type(i).representation())) {
        if (!IsValidFloatParameterRegister(data->register_param(i))) {
          return false;
        }
      }
    }
    return true;
  }

  bool IsValidFloatParameterRegister(Register reg);

 private:
  const CallInterfaceDescriptorData* data_;
};

// CRTP base class for call interface descriptors, which defines static getters
// for the various descriptor properties based on static values defined in the
// subclass.
template <typename DerivedDescriptor>
class StaticCallInterfaceDescriptor : public CallInterfaceDescriptor {
 public:
  // ===========================================================================
  // The following are the descriptor's CRTP configuration points, overwritable
  // by DerivedDescriptor.
  static constexpr int kReturnCount =
      CallInterfaceDescriptorData::kUninitializedCount;
  static constexpr int kParameterCount =
      CallInterfaceDescriptorData::kUninitializedCount;
  static constexpr bool kNoContext = false;
  static constexpr bool kAllowVarArgs = false;
  static constexpr bool kNoStackScan = false;
  static constexpr auto kStackArgumentOrder = StackArgumentOrder::kDefault;

  // The set of registers available to the parameters, as a
  // std::array<Register,N>. Can be larger or smaller than kParameterCount; if
  // larger then any remaining registers are ignored; if smaller, any parameters
  // after registers().size() will be stack registers.
  //
  // Defaults to CallInterfaceDescriptor::DefaultRegisterArray().
  static constexpr inline auto registers();
  static constexpr inline auto double_registers();
  static constexpr inline auto return_registers();
  static constexpr inline auto return_double_registers();

  // An additional limit on the number of register parameters allowed. This is
  // here so that it can be overwritten to kMaxTFSBuiltinRegisterParams for TFS
  // builtins, see comment on kMaxTFSBuiltinRegisterParams above.
  static constexpr int kMaxRegisterParams = kMaxBuiltinRegisterParams;

  // If set to true, the descriptor will restrict the set of allocatable
  // registers to the set returned by registers(). Then, it is expected that
  // the first kParameterCount registers() are the parameters of the builtin.
  static constexpr bool kRestrictAllocatableRegisters = false;

  // If set to true, builtins will callee save the set returned by registers().
  static constexpr bool kCalleeSaveRegisters = false;

  // If set to true, the descriptor will define a kMachineTypes array with the
  // types of each result value and parameter.
  static constexpr bool kCustomMachineTypes = false;

  // End of customization points.
  // ===========================================================================

  static constexpr inline Flags flags() {
    return Flags((DerivedDescriptor::kNoContext
                      ? CallInterfaceDescriptorData::kNoContext
                      : 0) |
                 (DerivedDescriptor::kAllowVarArgs
                      ? CallInterfaceDescriptorData::kAllowVarArgs
                      : 0) |
                 (DerivedDescriptor::kNoStackScan
                      ? CallInterfaceDescriptorData::kNoStackScan
                      : 0) |
                 (DerivedDescriptor::kCalleeSaveRegisters
                      ? CallInterfaceDescriptorData::kCalleeSaveRegisters
                      : 0));
  }
  static constexpr inline bool AllowVarArgs() {
    return DerivedDescriptor::kAllowVarArgs;
  }
  static constexpr inline bool HasContextParameter() {
    return !DerivedDescriptor::kNoContext;
  }

  static constexpr inline int GetReturnCount();
  static constexpr inline int GetParameterCount();
  static constexpr inline int GetRegisterParameterCount();
  static constexpr inline int GetStackParameterCount();
  static constexpr inline Register* GetRegisterData();
  static constexpr inline Register GetRegisterParameter(int i);
  static constexpr inline int GetStackParameterIndex(int i);
  static constexpr inline MachineType GetParameterType(int i);

  // Interface descriptors don't really support double registers.
  // This reinterprets the i-th register as a double with the same code.
  static constexpr inline DoubleRegister GetDoubleRegisterParameter(int i);

  explicit StaticCallInterfaceDescriptor(CallDescriptors::Key key)
      : CallInterfaceDescriptor(key) {}

#if DEBUG
  // Overwritten in DerivedDescriptor.
  static void Verify(CallInterfaceDescriptorData* data);
  // Verify that the CallInterfaceDescriptorData contains the default
  // argument registers for {argc} arguments.
  static inline void VerifyArgumentRegisterCount(
      CallInterfaceDescriptorData* data, int nof_expected_args);
#endif

 private:
  // {CallDescriptors} is allowed to call the private {Initialize} method.
  friend class CallDescriptors;

  inline void Initialize(CallInterfaceDescriptorData* data);

  // Set up the types of the descriptor. This is a static function, so that it
  // is overwritable by subclasses. By default, all parameters have
  // MachineType::AnyTagged() type.
  static void InitializeTypes(CallInterfaceDescriptorData* data) {
    DCHECK(!kCustomMachineTypes);
    data->InitializeTypes(nullptr, 0);
  }
};

template <typename Descriptor>
class StaticJSCallInterfaceDescriptor
    : public StaticCallInterfaceDescriptor<Descriptor> {
 public:
  static constexpr auto kStackArgumentOrder = StackArgumentOrder::kJS;
  static constexpr inline auto registers();

  using StaticCallInterfaceDescriptor<
      Descriptor>::StaticCallInterfaceDescriptor;
};

template <Builtin kBuiltin>
struct CallInterfaceDescriptorFor;

// Stub class replacing std::array<Register, 0>, as a workaround for MSVC's
// https://github.com/microsoft/STL/issues/942
struct EmptyRegisterArray {
  const Register* data() const { return nullptr; }
  size_t size() const { return 0; }
  Register operator[](size_t i) const { UNREACHABLE(); }
};

// Helper method for defining an array of unique registers for the various
// Descriptor::registers() methods.
template <typename... Registers>
constexpr std::array<Register, 1 + sizeof...(Registers)> RegisterArray(
    Register first_reg, Registers... regs) {
  DCHECK(!AreAliased(first_reg, regs...));
  return {first_reg, regs...};
}
constexpr EmptyRegisterArray RegisterArray() { return {}; }

// Stub class replacing std::array<Register, 0>, as a workaround for MSVC's
// https://github.com/microsoft/STL/issues/942
struct EmptyDoubleRegisterArray {
  const DoubleRegister* data() const { return nullptr; }
  size_t size() const { return 0; }
  DoubleRegister operator[](size_t i) const { UNREACHABLE(); }
};

// Helper method for defining an array of unique registers for the various
// Descriptor::double_registers() methods.
template <typename... Registers>
constexpr std::array<DoubleRegister, 1 + sizeof...(Registers)>
DoubleRegisterArray(DoubleRegister first_reg, Registers... regs) {
  DCHECK(!AreAliased(first_reg, regs...));
  return {first_reg, regs...};
}

constexpr EmptyDoubleRegisterArray DoubleRegisterArray() { return {}; }

#define DECLARE_DESCRIPTOR_WITH_BASE(name, base)                  \
 public:                                                          \
  /* StaticCallInterfaceDescriptor can call Initialize methods */ \
  friend class StaticCallInterfaceDescriptor<name>;               \
  explicit name() : base(key()) {}                                \
  static inline CallDescriptors::Key key();

#define DECLARE_DEFAULT_DESCRIPTOR(name)                                  \
  DECLARE_DESCRIPTOR_WITH_BASE(name, StaticCallInterfaceDescriptor)       \
  static constexpr int kMaxRegisterParams = kMaxTFSBuiltinRegisterParams; \
                                                                          \
 protected:                                                               \
  explicit name(CallDescriptors::Key key)                                 \
      : StaticCallInterfaceDescriptor(key) {}                             \
                                                                          \
 public:

#define DECLARE_JS_COMPATIBLE_DESCRIPTOR(name)                        \
  DECLARE_DESCRIPTOR_WITH_BASE(name, StaticJSCallInterfaceDescriptor) \
 protected:                                                           \
  explicit name(CallDescriptors::Key key)                             \
      : StaticJSCallInterfaceDescriptor(key) {}                       \
                                                                      \
 public:

#define DEFINE_RESULT_AND_PARAMETERS(return_count, ...)   \
  static constexpr int kReturnCount = return_count;       \
  enum ParameterIndices {                                 \
    __dummy = -1, /* to be able to pass zero arguments */ \
    ##__VA_ARGS__,                                        \
                                                          \
    kParameterCount,                                      \
    kContext = kParameterCount /* implicit parameter */   \
  };

// This is valid only for builtins that use EntryFrame, which does not scan
// stack arguments on GC.
#define DEFINE_PARAMETERS_ENTRY(...)                        \
  static constexpr bool kNoContext = true;                  \
  static constexpr bool kNoStackScan = true;                \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kDefault;                         \
  static constexpr int kReturnCount = 1;                    \
  enum ParameterIndices {                                   \
    __dummy = -1, /* to be able to pass zero arguments */   \
    ##__VA_ARGS__,                                          \
                                                            \
    kParameterCount                                         \
  };

#define DEFINE_PARAMETERS(...) DEFINE_RESULT_AND_PARAMETERS(1, ##__VA_ARGS__)

#define DEFINE_PARAMETERS_NO_CONTEXT(...) \
  DEFINE_PARAMETERS(__VA_ARGS__)          \
  static constexpr bool kNoContext = true;

#define DEFINE_PARAMETERS_VARARGS(...)                      \
  DEFINE_PARAMETERS(__VA_ARGS__)                            \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;

#define DEFINE_PARAMETERS_NO_CONTEXT_VARARGS(...)           \
  DEFINE_PARAMETERS_NO_CONTEXT(__VA_ARGS__)                 \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;

#define DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT(return_count, ...) \
  DEFINE_RESULT_AND_PARAMETERS(return_count, ##__VA_ARGS__)        \
  static constexpr bool kNoContext = true;

#define DEFINE_RESULT_AND_PARAMETER_TYPES(...)                                \
  static constexpr bool kCustomMachineTypes = true;                           \
  static constexpr MachineType kMachineTypes[] = {__VA_ARGS__};               \
  static void InitializeTypes(CallInterfaceDescriptorData* data) {            \
    static_assert(                                                            \
        kReturnCount + kParameterCount == arraysize(kMachineTypes),           \
        "Parameter names definition is not consistent with parameter types"); \
    data->InitializeTypes(kMachineTypes, arraysize(kMachineTypes));           \
  }

#define DEFINE_PARAMETER_TYPES(...)                                        \
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged() /* result */, \
                                    ##__VA_ARGS__)

// When the extra arguments described here are located in the stack, they are
// just above the return address in the frame (first arguments).
#define DEFINE_JS_PARAMETERS(...)                           \
  static constexpr bool kAllowVarArgs
Prompt: 
```
这是目录为v8/src/codegen/interface-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/interface-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_INTERFACE_DESCRIPTORS_H_
#define V8_CODEGEN_INTERFACE_DESCRIPTORS_H_

#include <memory>

#include "src/base/logging.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/register.h"
#include "src/codegen/tnode.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"

namespace v8 {
namespace internal {

#define TORQUE_BUILTIN_LIST_TFC(V)                                            \
  BUILTIN_LIST_FROM_TORQUE(IGNORE_BUILTIN, IGNORE_BUILTIN, V, IGNORE_BUILTIN, \
                           IGNORE_BUILTIN, IGNORE_BUILTIN)

#define INTERFACE_DESCRIPTOR_LIST(V)                 \
  V(Abort)                                           \
  V(Allocate)                                        \
  V(CallApiCallbackGeneric)                          \
  V(CallApiCallbackOptimized)                        \
  V(ApiGetter)                                       \
  V(ArrayConstructor)                                \
  V(ArrayNArgumentsConstructor)                      \
  V(ArrayNoArgumentConstructor)                      \
  V(ArraySingleArgumentConstructor)                  \
  V(AsyncFunctionStackParameter)                     \
  V(BaselineLeaveFrame)                              \
  V(BaselineOutOfLinePrologue)                       \
  V(BigIntToI32Pair)                                 \
  V(BigIntToI64)                                     \
  V(BinaryOp)                                        \
  V(BinaryOp_Baseline)                               \
  V(BinaryOp_WithFeedback)                           \
  V(BinarySmiOp_Baseline)                            \
  V(CallForwardVarargs)                              \
  V(CallFunctionTemplate)                            \
  V(CallFunctionTemplateGeneric)                     \
  V(CallTrampoline)                                  \
  V(CallTrampoline_Baseline)                         \
  V(CallTrampoline_Baseline_Compact)                 \
  V(CallTrampoline_WithFeedback)                     \
  V(CallVarargs)                                     \
  V(CallWithArrayLike)                               \
  V(CallWithArrayLike_WithFeedback)                  \
  V(CallWithSpread)                                  \
  V(CallWithSpread_Baseline)                         \
  V(CallWithSpread_WithFeedback)                     \
  V(CCall)                                           \
  V(CEntryDummy)                                     \
  V(CEntry1ArgvOnStack)                              \
  V(CloneObjectBaseline)                             \
  V(CloneObjectWithVector)                           \
  V(Compare)                                         \
  V(CompareNoContext)                                \
  V(StringEqual)                                     \
  V(Compare_Baseline)                                \
  V(Compare_WithFeedback)                            \
  V(Construct_Baseline)                              \
  V(ConstructForwardVarargs)                         \
  V(ConstructForwardAllArgs)                         \
  V(ConstructForwardAllArgs_Baseline)                \
  V(ConstructForwardAllArgs_WithFeedback)            \
  V(ConstructStub)                                   \
  V(ConstructVarargs)                                \
  V(ConstructWithArrayLike)                          \
  V(Construct_WithFeedback)                          \
  V(ConstructWithSpread)                             \
  V(ConstructWithSpread_Baseline)                    \
  V(ConstructWithSpread_WithFeedback)                \
  V(ContextOnly)                                     \
  V(CopyDataPropertiesWithExcludedProperties)        \
  V(CopyDataPropertiesWithExcludedPropertiesOnStack) \
  V(CppBuiltinAdaptor)                               \
  V(CreateFromSlowBoilerplateHelper)                 \
  V(DefineKeyedOwn)                                  \
  V(DefineKeyedOwnBaseline)                          \
  V(DefineKeyedOwnWithVector)                        \
  V(FastNewObject)                                   \
  V(FindNonDefaultConstructorOrConstruct)            \
  V(ForInPrepare)                                    \
  V(GetIteratorStackParameter)                       \
  V(GetProperty)                                     \
  V(GrowArrayElements)                               \
  V(I32PairToBigInt)                                 \
  V(I64ToBigInt)                                     \
  V(InterpreterCEntry1)                              \
  V(InterpreterCEntry2)                              \
  V(InterpreterDispatch)                             \
  V(InterpreterPushArgsThenCall)                     \
  V(InterpreterPushArgsThenConstruct)                \
  V(JSTrampoline)                                    \
  V(KeyedHasICBaseline)                              \
  V(KeyedHasICWithVector)                            \
  V(KeyedLoad)                                       \
  V(KeyedLoadBaseline)                               \
  V(EnumeratedKeyedLoadBaseline)                     \
  V(KeyedLoadWithVector)                             \
  V(EnumeratedKeyedLoad)                             \
  V(Load)                                            \
  V(LoadBaseline)                                    \
  V(LoadGlobal)                                      \
  V(LoadGlobalBaseline)                              \
  V(LoadGlobalNoFeedback)                            \
  V(LoadGlobalWithVector)                            \
  V(LoadNoFeedback)                                  \
  V(LoadWithReceiverAndVector)                       \
  V(LoadWithReceiverBaseline)                        \
  V(LoadWithVector)                                  \
  V(LookupWithVector)                                \
  V(LookupTrampoline)                                \
  V(LookupBaseline)                                  \
  V(MaglevOptimizeCodeOrTailCallOptimizedCodeSlot)   \
  V(NewHeapNumber)                                   \
  V(NoContext)                                       \
  V(OnStackReplacement)                              \
  V(RegExpTrampoline)                                \
  V(RestartFrameTrampoline)                          \
  V(ResumeGenerator)                                 \
  V(ResumeGeneratorBaseline)                         \
  V(RunMicrotasks)                                   \
  V(RunMicrotasksEntry)                              \
  V(SingleParameterOnStack)                          \
  V(Store)                                           \
  V(StoreNoFeedback)                                 \
  V(StoreBaseline)                                   \
  V(StoreGlobal)                                     \
  V(StoreGlobalBaseline)                             \
  V(StoreGlobalWithVector)                           \
  V(StoreTransition)                                 \
  V(StoreWithVector)                                 \
  V(StringAtAsString)                                \
  V(StringSubstring)                                 \
  V(SuspendGeneratorBaseline)                        \
  V(TypeConversion)                                  \
  V(TypeConversion_Baseline)                         \
  V(TypeConversionNoContext)                         \
  V(Typeof)                                          \
  V(UnaryOp_Baseline)                                \
  V(UnaryOp_WithFeedback)                            \
  V(Void)                                            \
  V(WasmDummy)                                       \
  V(WasmDummyWithJSLinkage)                          \
  V(WasmFloat32ToNumber)                             \
  V(WasmFloat64ToTagged)                             \
  V(WasmJSToWasmWrapper)                             \
  V(WasmToJSWrapper)                                 \
  V(WasmSuspend)                                     \
  V(WasmHandleStackOverflow)                         \
  V(WriteBarrier)                                    \
  V(IndirectPointerWriteBarrier)                     \
  IF_TSAN(V, TSANLoad)                               \
  IF_TSAN(V, TSANStore)                              \
  BUILTIN_LIST_TFS(V)                                \
  TORQUE_BUILTIN_LIST_TFC(V)

enum class StackArgumentOrder {
  kDefault,  // Arguments in the stack are pushed in the default/stub order (the
             // first argument is pushed first).
  kJS,  // Arguments in the stack are pushed in the same order as the one used
        // by JS-to-JS function calls. This should be used if calling a
        // JSFunction or if the builtin is expected to be called directly from a
        // JSFunction. This order is reversed compared to kDefault.
};

class V8_EXPORT_PRIVATE CallInterfaceDescriptorData {
 public:
  enum Flag {
    kNoFlags = 0u,
    kNoContext = 1u << 0,
    // This indicates that the code uses a special frame that does not scan the
    // stack arguments, e.g. EntryFrame. And this allows the code to use
    // untagged stack arguments.
    kNoStackScan = 1u << 1,
    // In addition to the specified parameters, additional arguments can be
    // passed on the stack.
    // This does not indicate if arguments adaption is used or not.
    kAllowVarArgs = 1u << 2,
    // Callee save allocatable_registers.
    kCalleeSaveRegisters = 1u << 3,
  };
  using Flags = base::Flags<Flag>;

  static constexpr int kUninitializedCount = -1;

  CallInterfaceDescriptorData() = default;

  CallInterfaceDescriptorData(const CallInterfaceDescriptorData&) = delete;
  CallInterfaceDescriptorData& operator=(const CallInterfaceDescriptorData&) =
      delete;

  // The passed registers are owned by the caller, and their lifetime is
  // expected to exceed that of this data. In practice, they are expected to
  // be in a static local.
  void InitializeRegisters(Flags flags, CodeEntrypointTag tag, int return_count,
                           int parameter_count, StackArgumentOrder stack_order,
                           int register_parameter_count,
                           const Register* registers,
                           const DoubleRegister* double_registers,
                           const Register* return_registers,
                           const DoubleRegister* return_double_registers);

  // if machine_types is null, then an array of size
  // (return_count + parameter_count) will be created with
  // MachineType::AnyTagged() for each member.
  //
  // if machine_types is not null, then it should be of the size
  // (return_count + parameter_count). Those members of the parameter array will
  // be initialized from {machine_types}, and the rest initialized to
  // MachineType::AnyTagged().
  void InitializeTypes(const MachineType* machine_types,
                       int machine_types_length);

  void Reset();

  bool IsInitialized() const {
    return IsInitializedRegisters() && IsInitializedTypes();
  }

  Flags flags() const { return flags_; }
  CodeEntrypointTag tag() const { return tag_; }
  int return_count() const { return return_count_; }
  int param_count() const { return param_count_; }
  int register_param_count() const { return register_param_count_; }
  Register register_param(int index) const { return register_params_[index]; }
  DoubleRegister double_register_param(int index) const {
    return double_register_params_[index];
  }
  Register register_return(int index) const { return register_returns_[index]; }
  DoubleRegister double_register_return(int index) const {
    return double_register_returns_[index];
  }
  MachineType return_type(int index) const {
    DCHECK_LT(index, return_count_);
    return machine_types_[index];
  }
  MachineType param_type(int index) const {
    DCHECK_LT(index, param_count_);
    return machine_types_[return_count_ + index];
  }
  StackArgumentOrder stack_order() const { return stack_order_; }

  void RestrictAllocatableRegisters(const Register* registers, size_t num) {
    DCHECK(allocatable_registers_.is_empty());
    for (size_t i = 0; i < num; ++i) {
      allocatable_registers_.set(registers[i]);
    }
    DCHECK(!allocatable_registers_.is_empty());
  }

  RegList allocatable_registers() const { return allocatable_registers_; }

 private:
  bool IsInitializedRegisters() const {
    const bool initialized =
        return_count_ != kUninitializedCount &&
        param_count_ != kUninitializedCount &&
        (register_param_count_ == 0 || register_params_ != nullptr);
    // Register initialization happens before type initialization.
    return initialized;
  }
  bool IsInitializedTypes() const {
    const bool initialized = machine_types_ != nullptr;
    // Register initialization happens before type initialization.
    return initialized;
  }

#ifdef DEBUG
  bool AllStackParametersAreTagged() const;
#endif  // DEBUG

  int register_param_count_ = kUninitializedCount;
  int return_count_ = kUninitializedCount;
  int param_count_ = kUninitializedCount;
  Flags flags_ = kNoFlags;
  CodeEntrypointTag tag_ = kDefaultCodeEntrypointTag;
  StackArgumentOrder stack_order_ = StackArgumentOrder::kDefault;

  // Specifying the set of registers that could be used by the register
  // allocator. Currently, it's only used by RecordWrite code stub.
  RegList allocatable_registers_;

  // |registers_params_| defines registers that are used for parameter passing.
  // |machine_types_| defines machine types for resulting values and incomping
  // parameters.
  // The register params array is owned by the caller, and it's expected that it
  // is a static local stored in the caller function. The machine types are
  // allocated dynamically by the InterfaceDescriptor and freed on destruction.
  const Register* register_params_ = nullptr;
  const DoubleRegister* double_register_params_ = nullptr;
  const Register* register_returns_ = nullptr;
  const DoubleRegister* double_register_returns_ = nullptr;
  MachineType* machine_types_ = nullptr;
};

class V8_EXPORT_PRIVATE CallDescriptors : public AllStatic {
 public:
  enum Key {
#define DEF_ENUM(name, ...) name,
    INTERFACE_DESCRIPTOR_LIST(DEF_ENUM)
#undef DEF_ENUM
        NUMBER_OF_DESCRIPTORS
  };

  static void InitializeOncePerProcess();
  static void TearDown();

  static CallInterfaceDescriptorData* call_descriptor_data(
      CallDescriptors::Key key) {
    return &call_descriptor_data_[key];
  }

  static Key GetKey(const CallInterfaceDescriptorData* data) {
    ptrdiff_t index = data - call_descriptor_data_;
    DCHECK_LE(0, index);
    DCHECK_LT(index, CallDescriptors::NUMBER_OF_DESCRIPTORS);
    return static_cast<CallDescriptors::Key>(index);
  }

 private:
  static CallInterfaceDescriptorData
      call_descriptor_data_[NUMBER_OF_DESCRIPTORS];
};

#if defined(V8_TARGET_ARCH_IA32)
// To support all possible cases, we must limit the number of register args for
// TFS builtins on ia32 to 3. Out of the 6 allocatable registers, esi is taken
// as the context register and ebx is the root register. One register must
// remain available to store the jump/call target. Thus 3 registers remain for
// arguments. The reason this applies to TFS builtins specifically is because
// this becomes relevant for builtins used as targets of Torque function
// pointers (which must have a register available to store the target).
// TODO(jgruber): Ideally we should just decrement kMaxBuiltinRegisterParams but
// that comes with its own set of complications. It's possible, but requires
// refactoring the calling convention of other existing stubs.
constexpr int kMaxBuiltinRegisterParams = 4;
constexpr int kMaxTFSBuiltinRegisterParams = 3;
#else
constexpr int kMaxBuiltinRegisterParams = 5;
constexpr int kMaxTFSBuiltinRegisterParams = kMaxBuiltinRegisterParams;
#endif
static_assert(kMaxTFSBuiltinRegisterParams <= kMaxBuiltinRegisterParams);
constexpr int kJSBuiltinRegisterParams = 4;

// Polymorphic base class for call interface descriptors, which defines getters
// for the various descriptor properties via a runtime-loaded
// CallInterfaceDescriptorData field.
class V8_EXPORT_PRIVATE CallInterfaceDescriptor {
 public:
  using Flags = CallInterfaceDescriptorData::Flags;

  CallInterfaceDescriptor() : data_(nullptr) {}
  ~CallInterfaceDescriptor() = default;

  explicit CallInterfaceDescriptor(CallDescriptors::Key key)
      : data_(CallDescriptors::call_descriptor_data(key)) {}

  Flags flags() const { return data()->flags(); }

  CodeEntrypointTag tag() const { return data()->tag(); }

  bool HasContextParameter() const {
    return (flags() & CallInterfaceDescriptorData::kNoContext) == 0;
  }

  bool AllowVarArgs() const {
    return flags() & CallInterfaceDescriptorData::kAllowVarArgs;
  }

  bool CalleeSaveRegisters() const {
    return flags() & CallInterfaceDescriptorData::kCalleeSaveRegisters;
  }

  int GetReturnCount() const { return data()->return_count(); }

  MachineType GetReturnType(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->return_type(index);
  }

  int GetParameterCount() const { return data()->param_count(); }

  int GetRegisterParameterCount() const {
    return data()->register_param_count();
  }

  int GetStackParameterCount() const {
    return data()->param_count() - data()->register_param_count();
  }

  Register GetRegisterParameter(int index) const {
    DCHECK_LT(index, data()->register_param_count());
    return data()->register_param(index);
  }

  DoubleRegister GetDoubleRegisterParameter(int index) const {
    DCHECK_LT(index, data()->register_param_count());
    return data()->double_register_param(index);
  }

  Register GetRegisterReturn(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->register_return(index);
  }

  DoubleRegister GetDoubleRegisterReturn(int index) const {
    DCHECK_LT(index, data()->return_count());
    return data()->double_register_return(index);
  }

  MachineType GetParameterType(int index) const {
    DCHECK_LT(index, data()->param_count());
    return data()->param_type(index);
  }

  RegList allocatable_registers() const {
    return data()->allocatable_registers();
  }

  StackArgumentOrder GetStackArgumentOrder() const {
    return data()->stack_order();
  }

  static constexpr inline Register ContextRegister() {
    return kContextRegister;
  }

  const char* DebugName() const;

  bool operator==(const CallInterfaceDescriptor& other) const {
    return data() == other.data();
  }

 protected:
  const CallInterfaceDescriptorData* data() const { return data_; }

  // Helper for defining the default register set.
  //
  // Use auto for the return type to allow different architectures to have
  // differently sized default register arrays.
  static constexpr inline auto DefaultRegisterArray();
  static constexpr inline auto DefaultDoubleRegisterArray();
  static constexpr inline auto DefaultReturnRegisterArray();
  static constexpr inline auto DefaultReturnDoubleRegisterArray();
  static constexpr inline std::array<Register, kJSBuiltinRegisterParams>
  DefaultJSRegisterArray();

  // Checks if float parameters are not assigned invalid registers.
  bool CheckFloatingPointParameters(CallInterfaceDescriptorData* data) {
    for (int i = 0; i < data->register_param_count(); i++) {
      if (IsFloatingPoint(data->param_type(i).representation())) {
        if (!IsValidFloatParameterRegister(data->register_param(i))) {
          return false;
        }
      }
    }
    return true;
  }

  bool IsValidFloatParameterRegister(Register reg);

 private:
  const CallInterfaceDescriptorData* data_;
};

// CRTP base class for call interface descriptors, which defines static getters
// for the various descriptor properties based on static values defined in the
// subclass.
template <typename DerivedDescriptor>
class StaticCallInterfaceDescriptor : public CallInterfaceDescriptor {
 public:
  // ===========================================================================
  // The following are the descriptor's CRTP configuration points, overwritable
  // by DerivedDescriptor.
  static constexpr int kReturnCount =
      CallInterfaceDescriptorData::kUninitializedCount;
  static constexpr int kParameterCount =
      CallInterfaceDescriptorData::kUninitializedCount;
  static constexpr bool kNoContext = false;
  static constexpr bool kAllowVarArgs = false;
  static constexpr bool kNoStackScan = false;
  static constexpr auto kStackArgumentOrder = StackArgumentOrder::kDefault;

  // The set of registers available to the parameters, as a
  // std::array<Register,N>. Can be larger or smaller than kParameterCount; if
  // larger then any remaining registers are ignored; if smaller, any parameters
  // after registers().size() will be stack registers.
  //
  // Defaults to CallInterfaceDescriptor::DefaultRegisterArray().
  static constexpr inline auto registers();
  static constexpr inline auto double_registers();
  static constexpr inline auto return_registers();
  static constexpr inline auto return_double_registers();

  // An additional limit on the number of register parameters allowed. This is
  // here so that it can be overwritten to kMaxTFSBuiltinRegisterParams for TFS
  // builtins, see comment on kMaxTFSBuiltinRegisterParams above.
  static constexpr int kMaxRegisterParams = kMaxBuiltinRegisterParams;

  // If set to true, the descriptor will restrict the set of allocatable
  // registers to the set returned by registers(). Then, it is expected that
  // the first kParameterCount registers() are the parameters of the builtin.
  static constexpr bool kRestrictAllocatableRegisters = false;

  // If set to true, builtins will callee save the set returned by registers().
  static constexpr bool kCalleeSaveRegisters = false;

  // If set to true, the descriptor will define a kMachineTypes array with the
  // types of each result value and parameter.
  static constexpr bool kCustomMachineTypes = false;

  // End of customization points.
  // ===========================================================================

  static constexpr inline Flags flags() {
    return Flags((DerivedDescriptor::kNoContext
                      ? CallInterfaceDescriptorData::kNoContext
                      : 0) |
                 (DerivedDescriptor::kAllowVarArgs
                      ? CallInterfaceDescriptorData::kAllowVarArgs
                      : 0) |
                 (DerivedDescriptor::kNoStackScan
                      ? CallInterfaceDescriptorData::kNoStackScan
                      : 0) |
                 (DerivedDescriptor::kCalleeSaveRegisters
                      ? CallInterfaceDescriptorData::kCalleeSaveRegisters
                      : 0));
  }
  static constexpr inline bool AllowVarArgs() {
    return DerivedDescriptor::kAllowVarArgs;
  }
  static constexpr inline bool HasContextParameter() {
    return !DerivedDescriptor::kNoContext;
  }

  static constexpr inline int GetReturnCount();
  static constexpr inline int GetParameterCount();
  static constexpr inline int GetRegisterParameterCount();
  static constexpr inline int GetStackParameterCount();
  static constexpr inline Register* GetRegisterData();
  static constexpr inline Register GetRegisterParameter(int i);
  static constexpr inline int GetStackParameterIndex(int i);
  static constexpr inline MachineType GetParameterType(int i);

  // Interface descriptors don't really support double registers.
  // This reinterprets the i-th register as a double with the same code.
  static constexpr inline DoubleRegister GetDoubleRegisterParameter(int i);

  explicit StaticCallInterfaceDescriptor(CallDescriptors::Key key)
      : CallInterfaceDescriptor(key) {}

#if DEBUG
  // Overwritten in DerivedDescriptor.
  static void Verify(CallInterfaceDescriptorData* data);
  // Verify that the CallInterfaceDescriptorData contains the default
  // argument registers for {argc} arguments.
  static inline void VerifyArgumentRegisterCount(
      CallInterfaceDescriptorData* data, int nof_expected_args);
#endif

 private:
  // {CallDescriptors} is allowed to call the private {Initialize} method.
  friend class CallDescriptors;

  inline void Initialize(CallInterfaceDescriptorData* data);

  // Set up the types of the descriptor. This is a static function, so that it
  // is overwritable by subclasses. By default, all parameters have
  // MachineType::AnyTagged() type.
  static void InitializeTypes(CallInterfaceDescriptorData* data) {
    DCHECK(!kCustomMachineTypes);
    data->InitializeTypes(nullptr, 0);
  }
};

template <typename Descriptor>
class StaticJSCallInterfaceDescriptor
    : public StaticCallInterfaceDescriptor<Descriptor> {
 public:
  static constexpr auto kStackArgumentOrder = StackArgumentOrder::kJS;
  static constexpr inline auto registers();

  using StaticCallInterfaceDescriptor<
      Descriptor>::StaticCallInterfaceDescriptor;
};

template <Builtin kBuiltin>
struct CallInterfaceDescriptorFor;

// Stub class replacing std::array<Register, 0>, as a workaround for MSVC's
// https://github.com/microsoft/STL/issues/942
struct EmptyRegisterArray {
  const Register* data() const { return nullptr; }
  size_t size() const { return 0; }
  Register operator[](size_t i) const { UNREACHABLE(); }
};

// Helper method for defining an array of unique registers for the various
// Descriptor::registers() methods.
template <typename... Registers>
constexpr std::array<Register, 1 + sizeof...(Registers)> RegisterArray(
    Register first_reg, Registers... regs) {
  DCHECK(!AreAliased(first_reg, regs...));
  return {first_reg, regs...};
}
constexpr EmptyRegisterArray RegisterArray() { return {}; }

// Stub class replacing std::array<Register, 0>, as a workaround for MSVC's
// https://github.com/microsoft/STL/issues/942
struct EmptyDoubleRegisterArray {
  const DoubleRegister* data() const { return nullptr; }
  size_t size() const { return 0; }
  DoubleRegister operator[](size_t i) const { UNREACHABLE(); }
};

// Helper method for defining an array of unique registers for the various
// Descriptor::double_registers() methods.
template <typename... Registers>
constexpr std::array<DoubleRegister, 1 + sizeof...(Registers)>
DoubleRegisterArray(DoubleRegister first_reg, Registers... regs) {
  DCHECK(!AreAliased(first_reg, regs...));
  return {first_reg, regs...};
}

constexpr EmptyDoubleRegisterArray DoubleRegisterArray() { return {}; }

#define DECLARE_DESCRIPTOR_WITH_BASE(name, base)                  \
 public:                                                          \
  /* StaticCallInterfaceDescriptor can call Initialize methods */ \
  friend class StaticCallInterfaceDescriptor<name>;               \
  explicit name() : base(key()) {}                                \
  static inline CallDescriptors::Key key();

#define DECLARE_DEFAULT_DESCRIPTOR(name)                                  \
  DECLARE_DESCRIPTOR_WITH_BASE(name, StaticCallInterfaceDescriptor)       \
  static constexpr int kMaxRegisterParams = kMaxTFSBuiltinRegisterParams; \
                                                                          \
 protected:                                                               \
  explicit name(CallDescriptors::Key key)                                 \
      : StaticCallInterfaceDescriptor(key) {}                             \
                                                                          \
 public:

#define DECLARE_JS_COMPATIBLE_DESCRIPTOR(name)                        \
  DECLARE_DESCRIPTOR_WITH_BASE(name, StaticJSCallInterfaceDescriptor) \
 protected:                                                           \
  explicit name(CallDescriptors::Key key)                             \
      : StaticJSCallInterfaceDescriptor(key) {}                       \
                                                                      \
 public:

#define DEFINE_RESULT_AND_PARAMETERS(return_count, ...)   \
  static constexpr int kReturnCount = return_count;       \
  enum ParameterIndices {                                 \
    __dummy = -1, /* to be able to pass zero arguments */ \
    ##__VA_ARGS__,                                        \
                                                          \
    kParameterCount,                                      \
    kContext = kParameterCount /* implicit parameter */   \
  };

// This is valid only for builtins that use EntryFrame, which does not scan
// stack arguments on GC.
#define DEFINE_PARAMETERS_ENTRY(...)                        \
  static constexpr bool kNoContext = true;                  \
  static constexpr bool kNoStackScan = true;                \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kDefault;                         \
  static constexpr int kReturnCount = 1;                    \
  enum ParameterIndices {                                   \
    __dummy = -1, /* to be able to pass zero arguments */   \
    ##__VA_ARGS__,                                          \
                                                            \
    kParameterCount                                         \
  };

#define DEFINE_PARAMETERS(...) DEFINE_RESULT_AND_PARAMETERS(1, ##__VA_ARGS__)

#define DEFINE_PARAMETERS_NO_CONTEXT(...) \
  DEFINE_PARAMETERS(__VA_ARGS__)          \
  static constexpr bool kNoContext = true;

#define DEFINE_PARAMETERS_VARARGS(...)                      \
  DEFINE_PARAMETERS(__VA_ARGS__)                            \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;

#define DEFINE_PARAMETERS_NO_CONTEXT_VARARGS(...)           \
  DEFINE_PARAMETERS_NO_CONTEXT(__VA_ARGS__)                 \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;

#define DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT(return_count, ...) \
  DEFINE_RESULT_AND_PARAMETERS(return_count, ##__VA_ARGS__)        \
  static constexpr bool kNoContext = true;

#define DEFINE_RESULT_AND_PARAMETER_TYPES(...)                                \
  static constexpr bool kCustomMachineTypes = true;                           \
  static constexpr MachineType kMachineTypes[] = {__VA_ARGS__};               \
  static void InitializeTypes(CallInterfaceDescriptorData* data) {            \
    static_assert(                                                            \
        kReturnCount + kParameterCount == arraysize(kMachineTypes),           \
        "Parameter names definition is not consistent with parameter types"); \
    data->InitializeTypes(kMachineTypes, arraysize(kMachineTypes));           \
  }

#define DEFINE_PARAMETER_TYPES(...)                                        \
  DEFINE_RESULT_AND_PARAMETER_TYPES(MachineType::AnyTagged() /* result */, \
                                    ##__VA_ARGS__)

// When the extra arguments described here are located in the stack, they are
// just above the return address in the frame (first arguments).
#define DEFINE_JS_PARAMETERS(...)                           \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr int kReturnCount = 1;                    \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;                              \
  enum ParameterIndices {                                   \
    kTarget,                                                \
    kNewTarget,                                             \
    kActualArgumentsCount,                                  \
    ##__VA_ARGS__,                                          \
    kParameterCount,                                        \
    kContext = kParameterCount /* implicit parameter */     \
  };

#define DEFINE_JS_PARAMETERS_NO_CONTEXT(...)                \
  static constexpr bool kAllowVarArgs = true;               \
  static constexpr bool kNoContext = true;                  \
  static constexpr int kReturnCount = 1;                    \
  static constexpr StackArgumentOrder kStackArgumentOrder = \
      StackArgumentOrder::kJS;                              \
  enum ParameterIndices {                                   \
    kTarget,                                                \
    kNewTarget,                                             \
    kActualArgumentsCount,                                  \
    ##__VA_ARGS__,                                          \
    kParameterCount,                                        \
  };

#define DEFINE_JS_PARAMETER_TYPES(...)                                         \
  DEFINE_PARAMETER_TYPES(MachineType::AnyTagged(), /* 
"""


```