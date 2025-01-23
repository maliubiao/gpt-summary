Response:
The user wants a summary of the provided C++ header file `v8/src/common/globals.h`. I need to identify the purpose of this file and describe the functionalities it defines. The instructions also specify how to handle specific characteristics of the file, such as its name, relationship to JavaScript, code logic, common programming errors, and finally, a general summary.

Here's a breakdown of the steps:

1. **Identify the file's purpose:** Based on the name `globals.h`, it likely defines global constants, enums, and data structures that are used across different parts of the V8 engine.

2. **Analyze the content and categorize functionalities:**
    - **Scope-related enums:** `ScopeType`
    - **Allocation tracking enums:** `AllocationSiteMode`, `AllocationSiteUpdateMode`
    - **Constants:** `kHoleNan...`, `kMaxSafeInteger...`, `kMaxUInt32Double`
    - **Variable-related enums and functions:** `VariableMode`, `VariableKind`, `VariableLocation`, `InitializationFlag`, `IsStaticFlag`, `MaybeAssignedFlag`, helper functions for `VariableMode`
    - **Interpreter-related enums:** `InterpreterPushArgsMode`
    - **Hashing function:** `ObjectHash`
    - **Type feedback classes and enums:** `BinaryOperationFeedback`, `CompareOperationFeedback`, `TypeOfFeedback`, `ForInFeedback`
    - **Unicode encoding enum:** `UnicodeEncoding`
    - **Iteration and Collection kind enums:** `IterationKind`, `CollectionKind`
    - **Isolate execution mode flags:** `IsolateExecutionModeFlag`
    - **Flags for keyed property definition:** `DefineKeyedOwnPropertyInLiteralFlag`, `DefineKeyedOwnPropertyFlags`
    - **External array type enum:** `ExternalArrayType`
    - **Debug info struct:** `AssemblerDebugInfo`
    - **Tiering state enums and functions:** `TieringState`, `CachedTieringDecision`
    - **Speculation and call feedback enums:** `SpeculationMode`, `CallFeedbackContent`
    - **Blocking and concurrency enums:** `BlockingBehavior`, `ConcurrencyMode`
    - **Register aliasing enum:** `AliasingKind`
    - **Isolate address IDs enum:** `IsolateAddressId`
    - **WebAssembly trap reasons enum:** `FOREACH_WASM_TRAPREASON`
    - **Keyed access mode enums and functions:** `KeyedAccessLoadMode`, `KeyedAccessStoreMode`, helper functions
    - **Mutability enum:** `MutableMode`
    - **Ic check type enum:** `IcCheckType`
    - **Stub call mode enum:** `StubCallMode`
    - **Context requirement enum:** `NeedsContext`
    - **Constants:** `kInvalidInfoId`, `kFunctionLiteralIdTopLevel`, `kSwissNameDictionaryInitialCapacity`, `kSmallOrderedHashSetMinCapacity`, `kSmallOrderedHashMapMinCapacity`, `kJSArgcReceiverSlots`, `kDontAdaptArgumentsSentinel`, `kJSCallClosureParameterIndex`, `kMinParameterIndex`, `NO_ID`
    - **Adapt arguments enum:** `AdaptArguments`
    - **Exception status enum:** `ExceptionStatus`
    - **Variable allocation info enum:** `VariableAllocationInfo`
    - **Pointer compression class:** `PtrComprCageBase`
    - **31-bit integer class:** `int31_t`
    - **Properties enumeration mode enum:** `PropertiesEnumerationMode`
    - **String transition strategy enum:** `StringTransitionStrategy`
    - **WebAssembly code pointer type:** `WasmCodePointer`
    - **Call jump mode enum:** `CallJumpMode`
    - **Tag dispatching structs:** `AcquireLoadTag`, `RelaxedLoadTag`, `ReleaseStoreTag`, `RelaxedStoreTag`, `SeqCstAccessTag`

3. **Address specific instructions:**
    - **`.tq` extension:** The file ends with `.h`, so it's not a Torque file.
    - **JavaScript relation:** Many of these enums and constants relate to JavaScript concepts like scopes, variables, data types, and function calls. I will provide JavaScript examples where applicable.
    - **Code logic推理:**  Examples include the bitwise operations for combining type feedback or checking flags. I'll provide examples with inputs and outputs.
    - **Common programming errors:**  Issues like incorrect usage of variable modes or misunderstanding type feedback could be highlighted.

4. **Summarize the functionality:**  Combine the categorized functionalities into a concise summary.

5. **Structure the response:** Organize the information clearly with headings and examples as requested.
```cpp
"CLASS_SCOPE";
    case ScopeType::WITH_SCOPE:
      return os << "WITH_SCOPE";
    case ScopeType::SHADOW_REALM_SCOPE:
      return os << "SHADOW_REALM_SCOPE";
    case ScopeType::REPL_MODE_SCOPE:
      return os << "REPL_MODE_SCOPE";
  }
  UNREACHABLE();
}

// AllocationSiteMode controls whether allocations are tracked by an allocation
// site.
enum AllocationSiteMode {
  DONT_TRACK_ALLOCATION_SITE,
  TRACK_ALLOCATION_SITE,
  LAST_ALLOCATION_SITE_MODE = TRACK_ALLOCATION_SITE
};

enum class AllocationSiteUpdateMode { kUpdate, kCheckOnly };

// The mips architecture prior to revision 5 has inverted encoding for sNaN.
#if (V8_TARGET_ARCH_MIPS64 && !defined(_MIPS_ARCH_MIPS64R6) && \
     (!defined(USE_SIMULATOR) || !defined(_MIPS_TARGET_SIMULATOR)))
constexpr uint32_t kHoleNanUpper32 = 0xFFFF7FFF;
constexpr uint32_t kHoleNanLower32 = 0xFFFF7FFF;
#else
constexpr uint32_t kHoleNanUpper32 = 0xFFF7FFFF;
constexpr uint32_t kHoleNanLower32 = 0xFFF7FFFF;
#endif

constexpr uint64_t kHoleNanInt64 =
    (static_cast<uint64_t>(kHoleNanUpper32) << 32) | kHoleNanLower32;

// ES6 section 20.1.2.6 Number.MAX_SAFE_INTEGER
constexpr uint64_t kMaxSafeIntegerUint64 = 9007199254740991;  // 2^53-1
static_assert(kMaxSafeIntegerUint64 == (uint64_t{1} << 53) - 1);
constexpr double kMaxSafeInteger = static_cast<double>(kMaxSafeIntegerUint64);
// ES6 section 21.1.2.8 Number.MIN_SAFE_INTEGER
constexpr double kMinSafeInteger = -kMaxSafeInteger;

constexpr double kMaxUInt32Double = double{kMaxUInt32};

// The order of this enum has to be kept in sync with the predicates below.
enum class VariableMode : uint8_t {
  // User declared variables:
  kLet,  // declared via 'let' declarations (first lexical)

  kConst,  // declared via 'const' declarations

  kUsing,  // declared via 'using' declaration for explicit resource management

  kAwaitUsing,  // declared via 'await using' declaration for explicit resource
                // management
                // (last lexical)

  kVar,  // declared via 'var', and 'function' declarations

  // Variables introduced by the compiler:
  kTemporary,  // temporary variables (not user-visible), stack-allocated
               // unless the scope as a whole has forced context allocation

  kDynamic,  // always require dynamic lookup (we don't know
             // the declaration)

  kDynamicGlobal,  // requires dynamic lookup, but we know that the
                   // variable is global unless it has been shadowed
                   // by an eval-introduced variable

  kDynamicLocal,  // requires dynamic lookup, but we know that the
                  // variable is local and where it is unless it
                  // has been shadowed by an eval-introduced
                  // variable

  // Variables for private methods or accessors whose access require
  // brand check. Declared only in class scopes by the compiler
  // and allocated only in class contexts:
  kPrivateMethod,  // Does not coexist with any other variable with the same
                   // name in the same scope.

  kPrivateSetterOnly,  // Incompatible with variables with the same name but
                       // any mode other than kPrivateGetterOnly. Transition to
                       // kPrivateGetterAndSetter if a later declaration for the
                       // same name with kPrivateGetterOnly is made.

  kPrivateGetterOnly,  // Incompatible with variables with the same name but
                       // any mode other than kPrivateSetterOnly. Transition to
                       // kPrivateGetterAndSetter if a later declaration for the
                       // same name with kPrivateSetterOnly is made.

  kPrivateGetterAndSetter,  // Does not coexist with any other variable with the
                            // same name in the same scope.

  kLastLexicalVariableMode = kAwaitUsing,
};

// Printing support
#ifdef DEBUG
inline const char* VariableMode2String(VariableMode mode) {
  switch (mode) {
    case VariableMode::kVar:
      return "VAR";
    case VariableMode::kLet:
      return "LET";
    case VariableMode::kPrivateGetterOnly:
      return "PRIVATE_GETTER_ONLY";
    case VariableMode::kPrivateSetterOnly:
      return "PRIVATE_SETTER_ONLY";
    case VariableMode::kPrivateMethod:
      return "PRIVATE_METHOD";
    case VariableMode::kPrivateGetterAndSetter:
      return "PRIVATE_GETTER_AND_SETTER";
    case VariableMode::kConst:
      return "CONST";
    case VariableMode::kDynamic:
      return "DYNAMIC";
    case VariableMode::kDynamicGlobal:
      return "DYNAMIC_GLOBAL";
    case VariableMode::kDynamicLocal:
      return "DYNAMIC_LOCAL";
    case VariableMode::kTemporary:
      return "TEMPORARY";
    case VariableMode::kUsing:
      return "USING";
    case VariableMode::kAwaitUsing:
      return "AWAIT_USING";
  }
  UNREACHABLE();
}
#endif

enum VariableKind : uint8_t {
  NORMAL_VARIABLE,
  PARAMETER_VARIABLE,
  THIS_VARIABLE,
  SLOPPY_BLOCK_FUNCTION_VARIABLE,
  SLOPPY_FUNCTION_NAME_VARIABLE
};

inline bool IsDynamicVariableMode(VariableMode mode) {
  return mode >= VariableMode::kDynamic && mode <= VariableMode::kDynamicLocal;
}

inline bool IsDeclaredVariableMode(VariableMode mode) {
  static_assert(static_cast<uint8_t>(VariableMode::kLet) ==
                0);  // Implies that mode >= VariableMode::kLet.
  return mode <= VariableMode::kVar;
}

inline bool IsPrivateAccessorVariableMode(VariableMode mode) {
  return mode >= VariableMode::kPrivateSetterOnly &&
         mode <= VariableMode::kPrivateGetterAndSetter;
}

inline bool IsPrivateMethodVariableMode(VariableMode mode) {
  return mode == VariableMode::kPrivateMethod;
}

inline bool IsPrivateMethodOrAccessorVariableMode(VariableMode mode) {
  return IsPrivateMethodVariableMode(mode) ||
         IsPrivateAccessorVariableMode(mode);
}

inline bool IsSerializableVariableMode(VariableMode mode) {
  return IsDeclaredVariableMode(mode) ||
         IsPrivateMethodOrAccessorVariableMode(mode);
}

inline bool IsImmutableLexicalVariableMode(VariableMode mode) {
  return mode == VariableMode::kConst || mode == VariableMode::kUsing ||
         mode == VariableMode::kAwaitUsing;
}

inline bool IsImmutableLexicalOrPrivateVariableMode(VariableMode mode) {
  return IsImmutableLexicalVariableMode(mode) ||
         IsPrivateMethodOrAccessorVariableMode(mode);
}

inline bool IsLexicalVariableMode(VariableMode mode) {
  static_assert(static_cast<uint8_t>(VariableMode::kLet) ==
                0);  // Implies that mode >= VariableMode::kLet.
  return mode <= VariableMode::kLastLexicalVariableMode;
}

enum VariableLocation : uint8_t {
  // Before and during variable allocation, a variable whose location is
  // not yet determined. After allocation, a variable looked up as a
  // property on the global object (and possibly absent). name() is the
  // variable name, index() is invalid.
  UNALLOCATED,

  // A slot in the parameter section on the stack. index() is the
  // parameter index, counting left-to-right. The receiver is index -1;
  // the first parameter is index 0.
  PARAMETER,

  // A slot in the local section on the stack. index() is the variable
  // index in the stack frame, starting at 0.
  LOCAL,

  // An indexed slot in a heap context. index() is the variable index in
  // the context object on the heap, starting at 0. scope() is the
  // corresponding scope.
  CONTEXT,

  // A named slot in a heap context. name() is the variable name in the
  // context object on the heap, with lookup starting at the current
  // context. index() is invalid.
  LOOKUP,

  // A named slot in a module's export table.
  MODULE,

  // An indexed slot in a script context. index() is the variable
  // index in the context object on the heap, starting at 0.
  // Important: REPL_GLOBAL variables from different scripts with the
  //            same name share a single script context slot. Every
  //            script context will reserve a slot, but only one will be used.
  // REPL_GLOBAL variables are stored in script contexts, but accessed like
  // globals, i.e. they always require a lookup at runtime to find the right
  // script context.
  REPL_GLOBAL,

  kLastVariableLocation = REPL_GLOBAL
};

// ES6 specifies declarative environment records with mutable and immutable
// bindings that can be in two states: initialized and uninitialized.
// When accessing a binding, it needs to be checked for initialization.
// However in the following cases the binding is initialized immediately
// after creation so the initialization check can always be skipped:
//
// 1. Var declared local variables.
//      var foo;
// 2. A local variable introduced by a function declaration.
//      function foo() {}
// 3. Parameters
//      function x(foo) {}
// 4. Catch bound variables.
//      try {} catch (foo) {}
// 6. Function name variables of named function expressions.
//      var x = function foo() {}
// 7. Implicit binding of 'this'.
// 8. Implicit binding of 'arguments' in functions.
//
// The following enum specifies a flag that indicates if the binding needs a
// distinct initialization step (kNeedsInitialization) or if the binding is
// immediately initialized upon creation (kCreatedInitialized).
enum InitializationFlag : uint8_t { kNeedsInitialization, kCreatedInitialized };

// Static variables can only be used with the class in the closest
// class scope as receivers.
enum class IsStaticFlag : uint8_t { kNotStatic, kStatic };

enum MaybeAssignedFlag : uint8_t { kNotAssigned, kMaybeAssigned };

enum class InterpreterPushArgsMode : unsigned {
  kArrayFunction,
  kWithFinalSpread,
  kOther
};

inline size_t hash_value(InterpreterPushArgsMode mode) {
  return base::bit_cast<unsigned>(mode);
}

inline std::ostream& operator<<(std::ostream& os,
                                InterpreterPushArgsMode mode) {
  switch (mode) {
    case InterpreterPushArgsMode::kArrayFunction:
      return os << "ArrayFunction";
    case InterpreterPushArgsMode::kWithFinalSpread:
      return os << "WithFinalSpread";
    case InterpreterPushArgsMode::kOther:
      return os << "Other";
  }
  UNREACHABLE();
}

inline uint32_t ObjectHash(Address address) {
  // All objects are at least pointer aligned, so we can remove the trailing
  // zeros.
  return static_cast<uint32_t>(address >> kTaggedSizeLog2);
}

// Type feedback is encoded in such a way that, we can combine the feedback
// at different points by performing an 'OR' operation. Type feedback moves
// to a more generic type when we combine feedback.
//
//   kSignedSmall -> kSignedSmallInputs -> kNumber  -> kNumberOrOddball -> kAny
//                                                     kString          -> kAny
//                                        kBigInt64 -> kBigInt          -> kAny
//
// Technically we wouldn't need the separation between the kNumber and the
// kNumberOrOddball values here, since for binary operations, we always
// truncate oddballs to numbers. In practice though it causes TurboFan to
// generate quite a lot of unused code though if we always handle numbers
// and oddballs everywhere, although in 99% of the use sites they are only
// used with numbers.
class BinaryOperationFeedback {
 public:
  enum {
    kNone = 0x0,
    kSignedSmall = 0x1,
    kSignedSmallInputs = 0x3,
    kNumber = 0x7,
    kNumberOrOddball = 0xF,
    kString = 0x10,
    kBigInt64 = 0x20,
    kBigInt = 0x60,
    kStringWrapper = 0x80,
    kStringOrStringWrapper = 0x90,
    kAny = 0x7F
  };
};

// Type feedback is encoded in such a way that, we can combine the feedback
// at different points by performing an 'OR' operation.
// This is distinct from BinaryOperationFeedback on purpose, because the
// feedback that matters differs greatly as well as the way it is consumed.
class CompareOperationFeedback {
  enum {
    kSignedSmallFlag = 1 << 0,
    kOtherNumberFlag = 1 << 1,
    kBooleanFlag = 1 << 2,
    kNullOrUndefinedFlag = 1 << 3,
    kInternalizedStringFlag = 1 << 4,
    kOtherStringFlag = 1 << 5,
    kSymbolFlag = 1 << 6,
    kBigInt64Flag = 1 << 7,
    kOtherBigIntFlag = 1 << 8,
    kReceiverFlag = 1 << 9,
    kAnyMask = 0x3FF,
  };

 public:
  enum Type {
    kNone = 0,

    kBoolean = kBooleanFlag,
    kNullOrUndefined = kNullOrUndefinedFlag,
    kOddball = kBoolean | kNullOrUndefined,

    kSignedSmall = kSignedSmallFlag,
    kNumber = kSignedSmall | kOtherNumberFlag,
    kNumber
### 提示词
```
这是目录为v8/src/common/globals.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/globals.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
"CLASS_SCOPE";
    case ScopeType::WITH_SCOPE:
      return os << "WITH_SCOPE";
    case ScopeType::SHADOW_REALM_SCOPE:
      return os << "SHADOW_REALM_SCOPE";
    case ScopeType::REPL_MODE_SCOPE:
      return os << "REPL_MODE_SCOPE";
  }
  UNREACHABLE();
}

// AllocationSiteMode controls whether allocations are tracked by an allocation
// site.
enum AllocationSiteMode {
  DONT_TRACK_ALLOCATION_SITE,
  TRACK_ALLOCATION_SITE,
  LAST_ALLOCATION_SITE_MODE = TRACK_ALLOCATION_SITE
};

enum class AllocationSiteUpdateMode { kUpdate, kCheckOnly };

// The mips architecture prior to revision 5 has inverted encoding for sNaN.
#if (V8_TARGET_ARCH_MIPS64 && !defined(_MIPS_ARCH_MIPS64R6) && \
     (!defined(USE_SIMULATOR) || !defined(_MIPS_TARGET_SIMULATOR)))
constexpr uint32_t kHoleNanUpper32 = 0xFFFF7FFF;
constexpr uint32_t kHoleNanLower32 = 0xFFFF7FFF;
#else
constexpr uint32_t kHoleNanUpper32 = 0xFFF7FFFF;
constexpr uint32_t kHoleNanLower32 = 0xFFF7FFFF;
#endif

constexpr uint64_t kHoleNanInt64 =
    (static_cast<uint64_t>(kHoleNanUpper32) << 32) | kHoleNanLower32;

// ES6 section 20.1.2.6 Number.MAX_SAFE_INTEGER
constexpr uint64_t kMaxSafeIntegerUint64 = 9007199254740991;  // 2^53-1
static_assert(kMaxSafeIntegerUint64 == (uint64_t{1} << 53) - 1);
constexpr double kMaxSafeInteger = static_cast<double>(kMaxSafeIntegerUint64);
// ES6 section 21.1.2.8 Number.MIN_SAFE_INTEGER
constexpr double kMinSafeInteger = -kMaxSafeInteger;

constexpr double kMaxUInt32Double = double{kMaxUInt32};

// The order of this enum has to be kept in sync with the predicates below.
enum class VariableMode : uint8_t {
  // User declared variables:
  kLet,  // declared via 'let' declarations (first lexical)

  kConst,  // declared via 'const' declarations

  kUsing,  // declared via 'using' declaration for explicit resource management

  kAwaitUsing,  // declared via 'await using' declaration for explicit resource
                // management
                // (last lexical)

  kVar,  // declared via 'var', and 'function' declarations

  // Variables introduced by the compiler:
  kTemporary,  // temporary variables (not user-visible), stack-allocated
               // unless the scope as a whole has forced context allocation

  kDynamic,  // always require dynamic lookup (we don't know
             // the declaration)

  kDynamicGlobal,  // requires dynamic lookup, but we know that the
                   // variable is global unless it has been shadowed
                   // by an eval-introduced variable

  kDynamicLocal,  // requires dynamic lookup, but we know that the
                  // variable is local and where it is unless it
                  // has been shadowed by an eval-introduced
                  // variable

  // Variables for private methods or accessors whose access require
  // brand check. Declared only in class scopes by the compiler
  // and allocated only in class contexts:
  kPrivateMethod,  // Does not coexist with any other variable with the same
                   // name in the same scope.

  kPrivateSetterOnly,  // Incompatible with variables with the same name but
                       // any mode other than kPrivateGetterOnly. Transition to
                       // kPrivateGetterAndSetter if a later declaration for the
                       // same name with kPrivateGetterOnly is made.

  kPrivateGetterOnly,  // Incompatible with variables with the same name but
                       // any mode other than kPrivateSetterOnly. Transition to
                       // kPrivateGetterAndSetter if a later declaration for the
                       // same name with kPrivateSetterOnly is made.

  kPrivateGetterAndSetter,  // Does not coexist with any other variable with the
                            // same name in the same scope.

  kLastLexicalVariableMode = kAwaitUsing,
};

// Printing support
#ifdef DEBUG
inline const char* VariableMode2String(VariableMode mode) {
  switch (mode) {
    case VariableMode::kVar:
      return "VAR";
    case VariableMode::kLet:
      return "LET";
    case VariableMode::kPrivateGetterOnly:
      return "PRIVATE_GETTER_ONLY";
    case VariableMode::kPrivateSetterOnly:
      return "PRIVATE_SETTER_ONLY";
    case VariableMode::kPrivateMethod:
      return "PRIVATE_METHOD";
    case VariableMode::kPrivateGetterAndSetter:
      return "PRIVATE_GETTER_AND_SETTER";
    case VariableMode::kConst:
      return "CONST";
    case VariableMode::kDynamic:
      return "DYNAMIC";
    case VariableMode::kDynamicGlobal:
      return "DYNAMIC_GLOBAL";
    case VariableMode::kDynamicLocal:
      return "DYNAMIC_LOCAL";
    case VariableMode::kTemporary:
      return "TEMPORARY";
    case VariableMode::kUsing:
      return "USING";
    case VariableMode::kAwaitUsing:
      return "AWAIT_USING";
  }
  UNREACHABLE();
}
#endif

enum VariableKind : uint8_t {
  NORMAL_VARIABLE,
  PARAMETER_VARIABLE,
  THIS_VARIABLE,
  SLOPPY_BLOCK_FUNCTION_VARIABLE,
  SLOPPY_FUNCTION_NAME_VARIABLE
};

inline bool IsDynamicVariableMode(VariableMode mode) {
  return mode >= VariableMode::kDynamic && mode <= VariableMode::kDynamicLocal;
}

inline bool IsDeclaredVariableMode(VariableMode mode) {
  static_assert(static_cast<uint8_t>(VariableMode::kLet) ==
                0);  // Implies that mode >= VariableMode::kLet.
  return mode <= VariableMode::kVar;
}

inline bool IsPrivateAccessorVariableMode(VariableMode mode) {
  return mode >= VariableMode::kPrivateSetterOnly &&
         mode <= VariableMode::kPrivateGetterAndSetter;
}

inline bool IsPrivateMethodVariableMode(VariableMode mode) {
  return mode == VariableMode::kPrivateMethod;
}

inline bool IsPrivateMethodOrAccessorVariableMode(VariableMode mode) {
  return IsPrivateMethodVariableMode(mode) ||
         IsPrivateAccessorVariableMode(mode);
}

inline bool IsSerializableVariableMode(VariableMode mode) {
  return IsDeclaredVariableMode(mode) ||
         IsPrivateMethodOrAccessorVariableMode(mode);
}

inline bool IsImmutableLexicalVariableMode(VariableMode mode) {
  return mode == VariableMode::kConst || mode == VariableMode::kUsing ||
         mode == VariableMode::kAwaitUsing;
}

inline bool IsImmutableLexicalOrPrivateVariableMode(VariableMode mode) {
  return IsImmutableLexicalVariableMode(mode) ||
         IsPrivateMethodOrAccessorVariableMode(mode);
}

inline bool IsLexicalVariableMode(VariableMode mode) {
  static_assert(static_cast<uint8_t>(VariableMode::kLet) ==
                0);  // Implies that mode >= VariableMode::kLet.
  return mode <= VariableMode::kLastLexicalVariableMode;
}

enum VariableLocation : uint8_t {
  // Before and during variable allocation, a variable whose location is
  // not yet determined.  After allocation, a variable looked up as a
  // property on the global object (and possibly absent).  name() is the
  // variable name, index() is invalid.
  UNALLOCATED,

  // A slot in the parameter section on the stack.  index() is the
  // parameter index, counting left-to-right.  The receiver is index -1;
  // the first parameter is index 0.
  PARAMETER,

  // A slot in the local section on the stack.  index() is the variable
  // index in the stack frame, starting at 0.
  LOCAL,

  // An indexed slot in a heap context.  index() is the variable index in
  // the context object on the heap, starting at 0.  scope() is the
  // corresponding scope.
  CONTEXT,

  // A named slot in a heap context.  name() is the variable name in the
  // context object on the heap, with lookup starting at the current
  // context.  index() is invalid.
  LOOKUP,

  // A named slot in a module's export table.
  MODULE,

  // An indexed slot in a script context. index() is the variable
  // index in the context object on the heap, starting at 0.
  // Important: REPL_GLOBAL variables from different scripts with the
  //            same name share a single script context slot. Every
  //            script context will reserve a slot, but only one will be used.
  // REPL_GLOBAL variables are stored in script contexts, but accessed like
  // globals, i.e. they always require a lookup at runtime to find the right
  // script context.
  REPL_GLOBAL,

  kLastVariableLocation = REPL_GLOBAL
};

// ES6 specifies declarative environment records with mutable and immutable
// bindings that can be in two states: initialized and uninitialized.
// When accessing a binding, it needs to be checked for initialization.
// However in the following cases the binding is initialized immediately
// after creation so the initialization check can always be skipped:
//
// 1. Var declared local variables.
//      var foo;
// 2. A local variable introduced by a function declaration.
//      function foo() {}
// 3. Parameters
//      function x(foo) {}
// 4. Catch bound variables.
//      try {} catch (foo) {}
// 6. Function name variables of named function expressions.
//      var x = function foo() {}
// 7. Implicit binding of 'this'.
// 8. Implicit binding of 'arguments' in functions.
//
// The following enum specifies a flag that indicates if the binding needs a
// distinct initialization step (kNeedsInitialization) or if the binding is
// immediately initialized upon creation (kCreatedInitialized).
enum InitializationFlag : uint8_t { kNeedsInitialization, kCreatedInitialized };

// Static variables can only be used with the class in the closest
// class scope as receivers.
enum class IsStaticFlag : uint8_t { kNotStatic, kStatic };

enum MaybeAssignedFlag : uint8_t { kNotAssigned, kMaybeAssigned };

enum class InterpreterPushArgsMode : unsigned {
  kArrayFunction,
  kWithFinalSpread,
  kOther
};

inline size_t hash_value(InterpreterPushArgsMode mode) {
  return base::bit_cast<unsigned>(mode);
}

inline std::ostream& operator<<(std::ostream& os,
                                InterpreterPushArgsMode mode) {
  switch (mode) {
    case InterpreterPushArgsMode::kArrayFunction:
      return os << "ArrayFunction";
    case InterpreterPushArgsMode::kWithFinalSpread:
      return os << "WithFinalSpread";
    case InterpreterPushArgsMode::kOther:
      return os << "Other";
  }
  UNREACHABLE();
}

inline uint32_t ObjectHash(Address address) {
  // All objects are at least pointer aligned, so we can remove the trailing
  // zeros.
  return static_cast<uint32_t>(address >> kTaggedSizeLog2);
}

// Type feedback is encoded in such a way that, we can combine the feedback
// at different points by performing an 'OR' operation. Type feedback moves
// to a more generic type when we combine feedback.
//
//   kSignedSmall -> kSignedSmallInputs -> kNumber  -> kNumberOrOddball -> kAny
//                                                     kString          -> kAny
//                                        kBigInt64 -> kBigInt          -> kAny
//
// Technically we wouldn't need the separation between the kNumber and the
// kNumberOrOddball values here, since for binary operations, we always
// truncate oddballs to numbers. In practice though it causes TurboFan to
// generate quite a lot of unused code though if we always handle numbers
// and oddballs everywhere, although in 99% of the use sites they are only
// used with numbers.
class BinaryOperationFeedback {
 public:
  enum {
    kNone = 0x0,
    kSignedSmall = 0x1,
    kSignedSmallInputs = 0x3,
    kNumber = 0x7,
    kNumberOrOddball = 0xF,
    kString = 0x10,
    kBigInt64 = 0x20,
    kBigInt = 0x60,
    kStringWrapper = 0x80,
    kStringOrStringWrapper = 0x90,
    kAny = 0x7F
  };
};

// Type feedback is encoded in such a way that, we can combine the feedback
// at different points by performing an 'OR' operation.
// This is distinct from BinaryOperationFeedback on purpose, because the
// feedback that matters differs greatly as well as the way it is consumed.
class CompareOperationFeedback {
  enum {
    kSignedSmallFlag = 1 << 0,
    kOtherNumberFlag = 1 << 1,
    kBooleanFlag = 1 << 2,
    kNullOrUndefinedFlag = 1 << 3,
    kInternalizedStringFlag = 1 << 4,
    kOtherStringFlag = 1 << 5,
    kSymbolFlag = 1 << 6,
    kBigInt64Flag = 1 << 7,
    kOtherBigIntFlag = 1 << 8,
    kReceiverFlag = 1 << 9,
    kAnyMask = 0x3FF,
  };

 public:
  enum Type {
    kNone = 0,

    kBoolean = kBooleanFlag,
    kNullOrUndefined = kNullOrUndefinedFlag,
    kOddball = kBoolean | kNullOrUndefined,

    kSignedSmall = kSignedSmallFlag,
    kNumber = kSignedSmall | kOtherNumberFlag,
    kNumberOrBoolean = kNumber | kBoolean,
    kNumberOrOddball = kNumber | kOddball,

    kInternalizedString = kInternalizedStringFlag,
    kString = kInternalizedString | kOtherStringFlag,

    kReceiver = kReceiverFlag,
    kReceiverOrNullOrUndefined = kReceiver | kNullOrUndefined,

    kBigInt64 = kBigInt64Flag,
    kBigInt = kBigInt64Flag | kOtherBigIntFlag,
    kSymbol = kSymbolFlag,

    kAny = kAnyMask,
  };
};

class TypeOfFeedback {
  enum {
    kNumberFlag = 1,
    kFunctionFlag = 1 << 1,
    kStringFlag = 1 << 2,
  };

 public:
  enum Result {
    kNone = 0,
    kNumber = kNumberFlag,
    kFunction = kFunctionFlag,
    kString = kStringFlag,
    kAny = kNumberFlag | kFunctionFlag | kStringFlag,
  };
};

// Type feedback is encoded in such a way that, we can combine the feedback
// at different points by performing an 'OR' operation. Type feedback moves
// to a more generic type when we combine feedback.
// kNone -> kEnumCacheKeysAndIndices -> kEnumCacheKeys -> kAny
enum class ForInFeedback : uint8_t {
  kNone = 0x0,
  kEnumCacheKeysAndIndices = 0x1,
  kEnumCacheKeys = 0x3,
  kAny = 0x7
};
static_assert((static_cast<int>(ForInFeedback::kNone) |
               static_cast<int>(ForInFeedback::kEnumCacheKeysAndIndices)) ==
              static_cast<int>(ForInFeedback::kEnumCacheKeysAndIndices));
static_assert((static_cast<int>(ForInFeedback::kEnumCacheKeysAndIndices) |
               static_cast<int>(ForInFeedback::kEnumCacheKeys)) ==
              static_cast<int>(ForInFeedback::kEnumCacheKeys));
static_assert((static_cast<int>(ForInFeedback::kEnumCacheKeys) |
               static_cast<int>(ForInFeedback::kAny)) ==
              static_cast<int>(ForInFeedback::kAny));

enum class UnicodeEncoding : uint8_t {
  // Different unicode encodings in a |word32|:
  UTF16,  // hi 16bits -> trailing surrogate or 0, low 16bits -> lead surrogate
  UTF32,  // full UTF32 code unit / Unicode codepoint
};

inline size_t hash_value(UnicodeEncoding encoding) {
  return static_cast<uint8_t>(encoding);
}

inline std::ostream& operator<<(std::ostream& os, UnicodeEncoding encoding) {
  switch (encoding) {
    case UnicodeEncoding::UTF16:
      return os << "UTF16";
    case UnicodeEncoding::UTF32:
      return os << "UTF32";
  }
  UNREACHABLE();
}

enum class IterationKind { kKeys, kValues, kEntries };

inline std::ostream& operator<<(std::ostream& os, IterationKind kind) {
  switch (kind) {
    case IterationKind::kKeys:
      return os << "IterationKind::kKeys";
    case IterationKind::kValues:
      return os << "IterationKind::kValues";
    case IterationKind::kEntries:
      return os << "IterationKind::kEntries";
  }
  UNREACHABLE();
}

enum class CollectionKind { kMap, kSet };

inline std::ostream& operator<<(std::ostream& os, CollectionKind kind) {
  switch (kind) {
    case CollectionKind::kMap:
      return os << "CollectionKind::kMap";
    case CollectionKind::kSet:
      return os << "CollectionKind::kSet";
  }
  UNREACHABLE();
}

enum class IsolateExecutionModeFlag : uint8_t {
  // Default execution mode.
  kNoFlags = 0,
  // Set if the Isolate is being profiled. Causes collection of extra compile
  // info.
  kIsProfiling = 1 << 0,
  // Set if side effect checking is enabled for the Isolate.
  // See Debug::StartSideEffectCheckMode().
  kCheckSideEffects = 1 << 1,
};

// Flags for the runtime function kDefineKeyedOwnPropertyInLiteral.
// - Whether the function name should be set or not.
enum class DefineKeyedOwnPropertyInLiteralFlag {
  kNoFlags = 0,
  kSetFunctionName = 1 << 0
};
using DefineKeyedOwnPropertyInLiteralFlags =
    base::Flags<DefineKeyedOwnPropertyInLiteralFlag>;
DEFINE_OPERATORS_FOR_FLAGS(DefineKeyedOwnPropertyInLiteralFlags)

enum class DefineKeyedOwnPropertyFlag {
  kNoFlags = 0,
  kSetFunctionName = 1 << 0
};
using DefineKeyedOwnPropertyFlags = base::Flags<DefineKeyedOwnPropertyFlag>;
DEFINE_OPERATORS_FOR_FLAGS(DefineKeyedOwnPropertyFlags)

enum ExternalArrayType {
  kExternalInt8Array = 1,
  kExternalUint8Array,
  kExternalInt16Array,
  kExternalUint16Array,
  kExternalInt32Array,
  kExternalUint32Array,
  kExternalFloat16Array,
  kExternalFloat32Array,
  kExternalFloat64Array,
  kExternalUint8ClampedArray,
  kExternalBigInt64Array,
  kExternalBigUint64Array,
};

struct AssemblerDebugInfo {
  AssemblerDebugInfo(const char* name, const char* file, int line)
      : name(name), file(file), line(line) {}
  const char* name;
  const char* file;
  int line;
};

inline std::ostream& operator<<(std::ostream& os,
                                const AssemblerDebugInfo& info) {
  os << "(" << info.name << ":" << info.file << ":" << info.line << ")";
  return os;
}

using FileAndLine = std::pair<const char*, int>;

// The state kInProgress (= an optimization request for this function is
// currently being serviced) currently means that no other tiering action can
// happen. Define this constant so we can static_assert it at related code
// sites.
static constexpr bool kTieringStateInProgressBlocksTierup = true;

#ifndef V8_ENABLE_LEAPTIERING

#define TIERING_STATE_LIST(V)           \
  V(None, 0b000)                        \
  V(InProgress, 0b001)                  \
  V(RequestMaglev_Synchronous, 0b010)   \
  V(RequestMaglev_Concurrent, 0b011)    \
  V(RequestTurbofan_Synchronous, 0b100) \
  V(RequestTurbofan_Concurrent, 0b101)

enum class TieringState : int32_t {
#define V(Name, Value) k##Name = Value,
  TIERING_STATE_LIST(V)
#undef V
      kLastTieringState = kRequestTurbofan_Concurrent,
};

// To efficiently check whether a marker is kNone or kInProgress using a single
// mask, we expect the kNone to be 0 and kInProgress to be 1 so that we can
// mask off the lsb for checking.
static_assert(static_cast<int>(TieringState::kNone) == 0b00 &&
              static_cast<int>(TieringState::kInProgress) == 0b01);
static_assert(static_cast<int>(TieringState::kLastTieringState) <= 0b111);
static constexpr uint32_t kNoneOrInProgressMask = 0b110;

#define V(Name, Value)                          \
  constexpr bool Is##Name(TieringState state) { \
    return state == TieringState::k##Name;      \
  }
TIERING_STATE_LIST(V)
#undef V

constexpr bool IsRequestMaglev(TieringState state) {
  return IsRequestMaglev_Concurrent(state) ||
         IsRequestMaglev_Synchronous(state);
}
constexpr bool IsRequestTurbofan(TieringState state) {
  return IsRequestTurbofan_Concurrent(state) ||
         IsRequestTurbofan_Synchronous(state);
}

constexpr const char* ToString(TieringState marker) {
  switch (marker) {
#define V(Name, Value)        \
  case TieringState::k##Name: \
    return "TieringState::k" #Name;
    TIERING_STATE_LIST(V)
#undef V
  }
}

inline std::ostream& operator<<(std::ostream& os, TieringState marker) {
  return os << ToString(marker);
}

#undef TIERING_STATE_LIST

#endif  // !V8_ENABLE_LEAPTIERING

// State machine:
// S(tate)0: kPending
// S1: kEarlySparkplug
// S2: kDelayMaglev
// S3: kEarlyMaglev
// S4: kEarlyTurbofan
// S5: kNormal
//
// C(ondition)0: sparkplug compile
// C1: maglev compile
// C2: deopt early
// C3: ic was stable early
// C4: turbofan compile
// C5: ic change or deopt
//
// S0 - C0 -> S1 - C1 - C3 -> S3 - C4 -> S4 -|
//                 |    |                    |
//                 |    |--------------------|
//                 |             |
//                 C2            C5
//                 |             |
//                 --> S2        --> S5
enum class CachedTieringDecision : int32_t {
  kPending,
  kEarlySparkplug,
  kDelayMaglev,
  kEarlyMaglev,
  kEarlyTurbofan,
  kNormal,
};

enum class SpeculationMode { kAllowSpeculation, kDisallowSpeculation };
enum class CallFeedbackContent { kTarget, kReceiver };

inline std::ostream& operator<<(std::ostream& os,
                                SpeculationMode speculation_mode) {
  switch (speculation_mode) {
    case SpeculationMode::kAllowSpeculation:
      return os << "SpeculationMode::kAllowSpeculation";
    case SpeculationMode::kDisallowSpeculation:
      return os << "SpeculationMode::kDisallowSpeculation";
  }
}

enum class BlockingBehavior { kBlock, kDontBlock };

enum class ConcurrencyMode : uint8_t { kSynchronous, kConcurrent };

constexpr bool IsSynchronous(ConcurrencyMode mode) {
  return mode == ConcurrencyMode::kSynchronous;
}
constexpr bool IsConcurrent(ConcurrencyMode mode) {
  return mode == ConcurrencyMode::kConcurrent;
}

constexpr const char* ToString(ConcurrencyMode mode) {
  switch (mode) {
    case ConcurrencyMode::kSynchronous:
      return "ConcurrencyMode::kSynchronous";
    case ConcurrencyMode::kConcurrent:
      return "ConcurrencyMode::kConcurrent";
  }
}
inline std::ostream& operator<<(std::ostream& os, ConcurrencyMode mode) {
  return os << ToString(mode);
}

// An architecture independent representation of the sets of registers available
// for instruction creation.
enum class AliasingKind {
  // Registers alias a single register of every other size (e.g. Intel).
  kOverlap,
  // Registers alias two registers of the next smaller size (e.g. ARM).
  kCombine,
  // SIMD128 Registers are independent of every other size (e.g Riscv)
  kIndependent
};

#define FOR_EACH_ISOLATE_ADDRESS_NAME(C)                            \
  C(Handler, handler)                                               \
  C(CEntryFP, c_entry_fp)                                           \
  C(CFunction, c_function)                                          \
  C(Context, context)                                               \
  C(Exception, exception)                                           \
  C(TopmostScriptHavingContext, topmost_script_having_context)      \
  C(PendingHandlerContext, pending_handler_context)                 \
  C(PendingHandlerEntrypoint, pending_handler_entrypoint)           \
  C(PendingHandlerConstantPool, pending_handler_constant_pool)      \
  C(PendingHandlerFP, pending_handler_fp)                           \
  C(PendingHandlerSP, pending_handler_sp)                           \
  C(NumFramesAbovePendingHandler, num_frames_above_pending_handler) \
  C(IsOnCentralStackFlag, is_on_central_stack_flag)                 \
  C(JSEntrySP, js_entry_sp)

enum IsolateAddressId {
#define DECLARE_ENUM(CamelName, hacker_name) k##CamelName##Address,
  FOR_EACH_ISOLATE_ADDRESS_NAME(DECLARE_ENUM)
#undef DECLARE_ENUM
      kIsolateAddressCount
};

// The reason for a WebAssembly trap.
#define FOREACH_WASM_TRAPREASON(V) \
  V(TrapUnreachable)               \
  V(TrapMemOutOfBounds)            \
  V(TrapUnalignedAccess)           \
  V(TrapDivByZero)                 \
  V(TrapDivUnrepresentable)        \
  V(TrapRemByZero)                 \
  V(TrapFloatUnrepresentable)      \
  V(TrapFuncSigMismatch)           \
  V(TrapDataSegmentOutOfBounds)    \
  V(TrapElementSegmentOutOfBounds) \
  V(TrapTableOutOfBounds)          \
  V(TrapRethrowNull)               \
  V(TrapNullDereference)           \
  V(TrapIllegalCast)               \
  V(TrapArrayOutOfBounds)          \
  V(TrapArrayTooLarge)             \
  V(TrapStringOffsetOutOfBounds)

enum class KeyedAccessLoadMode {
  kInBounds = 0b00,
  kHandleOOB = 0b01,
  kHandleHoles = 0b10,
  kHandleOOBAndHoles = 0b11,
};

inline KeyedAccessLoadMode CreateKeyedAccessLoadMode(bool handle_oob,
                                                     bool handle_holes) {
  return static_cast<KeyedAccessLoadMode>(
      static_cast<int>(handle_oob) | (static_cast<int>(handle_holes) << 1));
}

inline KeyedAccessLoadMode GeneralizeKeyedAccessLoadMode(
    KeyedAccessLoadMode mode1, KeyedAccessLoadMode mode2) {
  using T = std::underlying_type<KeyedAccessLoadMode>::type;
  return static_cast<KeyedAccessLoadMode>(static_cast<T>(mode1) |
                                          static_cast<T>(mode2));
}

inline bool LoadModeHandlesOOB(KeyedAccessLoadMode load_mode) {
  using T = std::underlying_type<KeyedAccessLoadMode>::type;
  return (static_cast<T>(load_mode) &
          static_cast<T>(KeyedAccessLoadMode::kHandleOOB)) != 0;
}

inline bool LoadModeHandlesHoles(KeyedAccessLoadMode load_mode) {
  using T = std::underlying_type<KeyedAccessLoadMode>::type;
  return (static_cast<T>(load_mode) &
          static_cast<T>(KeyedAccessLoadMode::kHandleHoles)) != 0;
}

enum class KeyedAccessStoreMode {
  kInBounds,
  kGrowAndHandleCOW,
  kIgnoreTypedArrayOOB,
  kHandleCOW,
};

inline std::ostream& operator<<(std::ostream& os, KeyedAccessStoreMode mode) {
  switch (mode) {
    case KeyedAccessStoreMode::kInBounds:
      return os << "kInBounds";
    case KeyedAccessStoreMode::kGrowAndHandleCOW:
      return os << "kGrowAndHandleCOW";
    case KeyedAccessStoreMode::kIgnoreTypedArrayOOB:
      return os << "kIgnoreTypedArrayOOB";
    case KeyedAccessStoreMode::kHandleCOW:
      return os << "kHandleCOW";
  }
  UNREACHABLE();
}

enum MutableMode { MUTABLE, IMMUTABLE };

inline bool StoreModeIsInBounds(KeyedAccessStoreMode store_mode) {
  return store_mode == KeyedAccessStoreMode::kInBounds;
}

inline bool StoreModeHandlesCOW(KeyedAccessStoreMode store_mode) {
  return store_mode == KeyedAccessStoreMode::kHandleCOW ||
         store_mode == KeyedAccessStoreMode::kGrowAndHandleCOW;
}

inline bool StoreModeSupportsTypeArray(KeyedAccessStoreMode store_mode) {
  return store_mode == KeyedAccessStoreMode::kInBounds ||
         store_mode == KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
}

inline bool StoreModeIgnoresTypeArrayOOB(KeyedAccessStoreMode store_mode) {
  return store_mode == KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
}

inline bool StoreModeCanGrow(KeyedAccessStoreMode store_mode) {
  return store_mode == KeyedAccessStoreMode::kGrowAndHandleCOW;
}

enum class IcCheckType { kElement, kProperty };

// Helper stubs can be called in different ways depending on where the target
// code is located and how the call sequence is expected to look like:
//  - CodeObject: Call on-heap {Code} object via {RelocInfo::CODE_TARGET}.
//  - WasmRuntimeStub: Call native {WasmCode} stub via
//    {RelocInfo::WASM_STUB_CALL}.
//  - BuiltinPointer: Call a builtin based on a builtin pointer with dynamic
//    contents. If builtins are embedded, we call directly into off-heap code
//    without going through the on-heap Code trampoline.
enum class StubCallMode {
  kCallCodeObject,
#if V8_ENABLE_WEBASSEMBLY
  kCallWasmRuntimeStub,
#endif  // V8_ENABLE_WEBASSEMBLY
  kCallBuiltinPointer,
};

enum class NeedsContext { kYes, kNo };

constexpr int kInvalidInfoId = -1;
constexpr int kFunctionLiteralIdTopLevel = 0;

constexpr int kSwissNameDictionaryInitialCapacity = 4;

constexpr int kSmallOrderedHashSetMinCapacity = 4;
constexpr int kSmallOrderedHashMapMinCapacity = 4;

enum class AdaptArguments { kYes, kNo };
constexpr AdaptArguments kAdapt = AdaptArguments::kYes;
constexpr AdaptArguments kDontAdapt = AdaptArguments::kNo;

constexpr int kJSArgcReceiverSlots = 1;
constexpr uint16_t kDontAdaptArgumentsSentinel = 0;

// Helper to get the parameter count for functions with JS linkage.
inline constexpr int JSParameterCount(int param_count_without_receiver) {
  return param_count_without_receiver + kJSArgcReceiverSlots;
}

// A special {Parameter} index for JSCalls that represents the closure.
// The constant is defined here for accessibility (without having to include TF
// internals), even though it is mostly relevant to Turbofan.
constexpr int kJSCallClosureParameterIndex = -1;
constexpr int kMinParameterIndex = kJSCallClosureParameterIndex;

// Opaque data type for identifying stack frames. Used extensively
// by the debugger.
// ID_MIN_VALUE and ID_MAX_VALUE are specified to ensure that enumeration type
// has correct value range (see Issue 830 for more details).
enum StackFrameId { ID_MIN_VALUE = kMinInt, ID_MAX_VALUE = kMaxInt, NO_ID = 0 };

enum class ExceptionStatus : bool { kException = false, kSuccess = true };
V8_INLINE bool operator!(ExceptionStatus status) {
  return !static_cast<bool>(status);
}

// Used in the ScopeInfo flags fields for the function name variable for named
// function expressions, and for the receiver. Must be declared here so that it
// can be used in Torque.
enum class VariableAllocationInfo { NONE, STACK, CONTEXT, UNUSED };

#ifdef V8_COMPRESS_POINTERS
class PtrComprCageBase {
 public:
  explicit constexpr PtrComprCageBase(Address address) : address_(address) {}
  // NOLINTNEXTLINE
  inline PtrComprCageBase(const Isolate* isolate);
  // NOLINTNEXTLINE
  inline PtrComprCageBase(const LocalIsolate* isolate);

  inline Address address() const { return address_; }

  bool operator==(const PtrComprCageBase& other) const {
    return address_ == other.address_;
  }

 private:
  Address address_;
};
#else
class PtrComprCageBase {
 public:
  explicit constexpr PtrComprCageBase(Address address) {}
  PtrComprCageBase() = default;
  // NOLINTNEXTLINE
  PtrComprCageBase(const Isolate* isolate) {}
  // NOLINTNEXTLINE
  PtrComprCageBase(const LocalIsolate* isolate) {}
};
#endif

class int31_t {
 public:
  constexpr int31_t() : value_(0) {}
  constexpr int31_t(int value) : value_(value) {  // NOLINT(runtime/explicit)
    DCHECK_EQ((value & 0x80000000) != 0, (value & 0x40000000) != 0);
  }
  int31_t& operator=(int value) {
    DCHECK_EQ((value & 0x80000000) != 0, (value & 0x40000000) != 0);
    value_ = value;
    return *this;
  }
  int32_t value() const { return value_; }
  operator int32_t() const { return value_; }

 private:
  int32_t value_;
};

enum PropertiesEnumerationMode {
  // String and then Symbol properties according to the spec
  // ES#sec-object.assign
  kEnumerationOrder,
  // Order of property addition
  kPropertyAdditionOrder,
};

enum class StringTransitionStrategy {
  // The string must be transitioned to a new representation by first copying.
  kCopy,
  // The string can be transitioned in-place by changing its map.
  kInPlace,
  // The string is already transitioned to the desired representation.
  kAlreadyTransitioned
};

#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
using WasmCodePointer = uint32_t;
#else
using WasmCodePointer = Address;
#endif

enum CallJumpMode { kCall, kTailCall };

}  // namespace internal

// Tag dispatching support for atomic loads and stores.
struct AcquireLoadTag {};
struct RelaxedLoadTag {};
struct ReleaseStoreTag {};
struct RelaxedStoreTag {};
struct SeqCstAccessTag {};
static constexpr AcquireLoadTag kAcquireLoad;
static constexpr RelaxedLoadTag kRelaxedLoad;
static constexpr ReleaseStoreTag kReleaseStore;
static constexpr RelaxedStoreTag kRelaxedStore;
static constexpr SeqCstAccessTag kSeqCstAccess;

}  // namespace v8

namespace i = v8::internal;

#endif  // V8_COMMON_GLOBALS_H_
```