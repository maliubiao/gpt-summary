Response:
Let's break down the thought process for analyzing this C++ header file and generating the response.

**1. Understanding the Goal:**

The request asks for the functionality of the `builtin-call-descriptors.h` file within the V8 Turboshaft compiler. It also prompts for connections to JavaScript, examples, code logic, and common errors. The "Part 1" designation suggests a comprehensive analysis is expected, to be followed by another part.

**2. Initial Scan and Keyword Identification:**

Quickly scanning the code reveals key terms and patterns:

* `#ifndef`, `#define`, `#include`: Standard C++ header guard. Not directly functional but important for compilation.
* `namespace v8::internal::compiler::turboshaft`:  Indicates the file's location and purpose within the V8 project, specifically the Turboshaft compiler.
* `struct BuiltinCallDescriptor`: The central structure, suggesting it defines descriptors for calling built-in functions.
* `template <typename Derived> struct Descriptor`: A template for creating specific call descriptors. This is the core mechanism.
* `Builtin::k...`:  References to built-in functions. This is a strong indicator of the file's primary purpose.
* `arguments_t`, `results_t`: Type aliases likely representing the input arguments and return values of built-in calls.
* `kNeedsFrameState`, `kNeedsContext`, `kProperties`, `kEffects`:  Metadata associated with each built-in call, likely used for optimization and correctness.
* `GENERIC_BINOP_LIST`, `GENERIC_UNOP_LIST`: Macros suggesting a systematic way of defining descriptors for binary and unary operations.
* Specific built-in names (e.g., `CheckTurbofanType`, `ToNumber`, `StringAdd_CheckNone`). These hint at the JavaScript functionalities these built-ins relate to.
* WASM-related built-ins (`WasmStringAsWtf8`, `WasmMemoryGrow`, etc.): Indicates support for WebAssembly within this file.

**3. Deconstructing the `Descriptor` Template:**

This template is crucial. It defines how call descriptors are created. Key observations:

* `Create()`:  This static method is responsible for generating a `TSCallDescriptor`. It uses `Builtins::CallInterfaceDescriptorFor()` to get information about the built-in.
* `Verify()`:  A debug-only function that checks the consistency of the generated descriptor (argument and result types, frame state, properties). This highlights a focus on correctness.
* Type checking (`AllowsRepresentation`):  Ensures the data types used in the descriptor are compatible with the underlying machine representations.

**4. Analyzing Individual Built-in Descriptors:**

Each struct within `BuiltinCallDescriptor` (e.g., `CheckTurbofanType`, `ToNumber`) represents a specific built-in function. For each one:

* **Identify `kFunction`:** This links the descriptor to a specific built-in.
* **Examine `arguments_t` and `results_t`:** These reveal the expected input and output types. Relate these types to V8's internal representation system (e.g., `V<Object>`, `V<Number>`, `V<String>`).
* **Understand the flags (`kNeedsFrameState`, `kNeedsContext`, `kProperties`, `kEffects`):**  Try to deduce the meaning of each flag. For example:
    * `kNeedsFrameState`: The built-in might need access to the current stack frame.
    * `kNeedsContext`: The built-in might require the current JavaScript context.
    * `kNoThrow`, `kNoDeopt`:  Optimization hints.
    * `kEffects`: Describes the side effects of the built-in (memory access, allocation, etc.).
* **Connect to JavaScript:** Based on the built-in name and argument/result types, infer the corresponding JavaScript functionality. For instance, `ToNumber` clearly relates to JavaScript's `Number()` conversion.

**5. Identifying Common Themes and Functionality:**

After analyzing several descriptors, patterns emerge:

* **Type Conversion:** Many built-ins deal with converting between JavaScript types (`ToNumber`, `ToString`, `ToBoolean`, etc.).
* **String Operations:**  A significant number of built-ins are related to string manipulation (`StringAdd_CheckNone`, `StringEqual`, `StringSubstring`, etc.).
* **WebAssembly Integration:** The presence of `Wasm...` built-ins clearly indicates support for WebAssembly.
* **Internal Checks and Utilities:** Built-ins like `CheckTurbofanType` and `DebugPrintFloat64` seem to be internal tools for type checking and debugging within the compiler.
* **Object and Array Manipulation:**  Built-ins like `CopyFastSmiOrObjectElements` and `GrowFastElements` suggest operations on JavaScript objects and arrays.
* **Function Creation:** `FastNewClosure`, `CreateFunctionContext` point to the mechanisms for creating JavaScript functions.

**6. Formulating the Summary and Examples:**

Based on the analysis, synthesize a high-level summary of the file's purpose. Then, for illustrative purposes:

* **JavaScript Examples:** Choose a few prominent built-ins and demonstrate their usage in JavaScript.
* **Code Logic Reasoning:** Select a simpler built-in (like `ToBoolean`) and explain the assumed inputs and outputs.
* **Common Programming Errors:**  Link built-in functionality to potential JavaScript errors. For example, incorrect type assumptions leading to errors in type conversion.

**7. Addressing Specific Constraints:**

* **`.tq` extension:** Explain that this header file is C++ and not Torque.
* **"Part 1 of 2":**  Indicate that this is a preliminary analysis and more details might follow in the next part.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing solely on the individual built-ins might miss the bigger picture. Recognize the overarching purpose of defining call descriptors for the Turboshaft compiler.
* **Realization:**  The `Descriptor` template is the key mechanism. Understanding its role is crucial.
* **Constraint Check:**  Ensure all parts of the request are addressed, including JavaScript examples and common errors. Don't just list the built-ins; explain their *functionality*.
* **Clarity:**  Use clear and concise language. Avoid overly technical jargon where possible. Explain V8-specific terms if necessary.

By following this structured approach, we can effectively analyze the C++ header file and generate a comprehensive and informative response that addresses all aspects of the user's request.
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_BUILTIN_CALL_DESCRIPTORS_H_
#define V8_COMPILER_TURBOSHAFT_BUILTIN_CALL_DESCRIPTORS_H_

#include "src/builtins/builtins.h"
#include "src/codegen/callable.h"
#include "src/codegen/interface-descriptors.h"
#include "src/compiler/frame.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/objects/js-function.h"

namespace v8::internal::compiler::turboshaft {

struct BuiltinCallDescriptor {
 private:
  template <typename Derived>
  struct Descriptor {
    static const TSCallDescriptor* Create(
        StubCallMode call_mode, Zone* zone,
        LazyDeoptOnThrow lazy_deopt_on_throw = LazyDeoptOnThrow::kNo) {
      CallInterfaceDescriptor interface_descriptor =
          Builtins::CallInterfaceDescriptorFor(Derived::kFunction);
      auto descriptor = Linkage::GetStubCallDescriptor(
          zone, interface_descriptor,
          interface_descriptor.GetStackParameterCount(),
          Derived::kNeedsFrameState ? CallDescriptor::kNeedsFrameState
                                    : CallDescriptor::kNoFlags,
          Derived::kProperties, call_mode);
#ifdef DEBUG
      Derived::Verify(descriptor);
#endif  // DEBUG
      bool can_throw = !(Derived::kProperties & Operator::kNoThrow);
      return TSCallDescriptor::Create(
          descriptor, can_throw ? CanThrow::kYes : CanThrow::kNo,
          lazy_deopt_on_throw, zone);
    }

#ifdef DEBUG
    static void Verify(const CallDescriptor* desc) {
      using results_t = typename Derived::results_t;
      using arguments_t = typename Derived::arguments_t;
      DCHECK_EQ(desc->ReturnCount(), std::tuple_size_v<results_t>);
      if constexpr (std::tuple_size_v<results_t> >= 1) {
        using result0_t = std::tuple_element_t<0, results_t>;
        DCHECK(AllowsRepresentation<result0_t>(
            RegisterRepresentation::FromMachineRepresentation(
                desc->GetReturnType(0).representation())));
      }
      if constexpr (std::tuple_size_v<results_t> >= 2) {
        using result1_t = std::tuple_element_t<1, results_t>;
        DCHECK(AllowsRepresentation<result1_t>(
            RegisterRepresentation::FromMachineRepresentation(
                desc->GetReturnType(1).representation())));
      }
      DCHECK_EQ(desc->NeedsFrameState(), Derived::kNeedsFrameState);
      DCHECK_EQ(desc->properties(), Derived::kProperties);
      DCHECK_EQ(desc->ParameterCount(), std::tuple_size_v<arguments_t> +
                                            (Derived::kNeedsContext ? 1 : 0));
      DCHECK(VerifyArguments<arguments_t>(desc));
    }

    template <typename Arguments>
    static bool VerifyArguments(const CallDescriptor* desc) {
      return VerifyArgumentsImpl<Arguments>(
          desc, std::make_index_sequence<std::tuple_size_v<Arguments>>());
    }

   private:
    template <typename T>
    static bool AllowsRepresentation(RegisterRepresentation rep) {
      if constexpr (std::is_same_v<T, OpIndex>) {
        return true;
      } else {
        // T is V<...>
        return T::allows_representation(rep);
      }
    }
    template <typename Arguments, size_t... Indices>
    static bool VerifyArgumentsImpl(const CallDescriptor* desc,
                                    std::index_sequence<Indices...>) {
      return (AllowsRepresentation<std::tuple_element_t<Indices, Arguments>>(
                  RegisterRepresentation::FromMachineRepresentation(
                      desc->GetParameterType(Indices).representation())) &&
              ...);
    }
#endif  // DEBUG
  };

  static constexpr OpEffects base_effects = OpEffects().CanDependOnChecks();
  // TODO(nicohartmann@): Unfortunately, we cannot define builtins with
  // void/never return types properly (e.g. in Torque), but they typically have
  // a JSAny dummy return type. Use Void/Never sentinels to express that in
  // Turboshaft's descriptors. We should find a better way to model this.
  using Void = std::tuple<OpIndex>;
  using Never = std::tuple<OpIndex>;

 public:
  struct CheckTurbofanType : public Descriptor<CheckTurbofanType> {
    static constexpr auto kFunction = Builtin::kCheckTurbofanType;
    using arguments_t = std::tuple<V<Object>, V<TurbofanType>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoThrow | Operator::kNoDeopt;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().RequiredWhenUnused();
  };

#define DECL_GENERIC_BINOP(Name)                                          \
  struct Name : public Descriptor<Name> {                                 \
    static constexpr auto kFunction = Builtin::k##Name;                   \
    using arguments_t = std::tuple<V<Object>, V<Object>>;                 \
    using results_t = std::tuple<V<Object>>;                              \
                                                                          \
    static constexpr bool kNeedsFrameState = true;                        \
    static constexpr bool kNeedsContext = true;                           \
    static constexpr Operator::Properties kProperties =                   \
        Operator::kNoProperties;                                          \
    static constexpr OpEffects kEffects = base_effects.CanCallAnything(); \
  };
  GENERIC_BINOP_LIST(DECL_GENERIC_BINOP)
#undef DECL_GENERIC_BINOP

#define DECL_GENERIC_UNOP(Name)                                           \
  struct Name : public Descriptor<Name> {                                 \
    static constexpr auto kFunction = Builtin::k##Name;                   \
    using arguments_t = std::tuple<V<Object>>;                            \
    using results_t = std::tuple<V<Object>>;                              \
                                                                          \
    static constexpr bool kNeedsFrameState = true;                        \
    static constexpr bool kNeedsContext = true;                           \
    static constexpr Operator::Properties kProperties =                   \
        Operator::kNoProperties;                                          \
    static constexpr OpEffects kEffects = base_effects.CanCallAnything(); \
  };
  GENERIC_UNOP_LIST(DECL_GENERIC_UNOP)
#undef DECL_GENERIC_UNOP

  struct ToNumber : public Descriptor<ToNumber> {
    static constexpr auto kFunction = Builtin::kToNumber;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct NonNumberToNumber : public Descriptor<NonNumberToNumber> {
    static constexpr auto kFunction = Builtin::kNonNumberToNumber;
    using arguments_t = std::tuple<V<JSAnyNotNumber>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct ToNumeric : public Descriptor<ToNumeric> {
    static constexpr auto kFunction = Builtin::kToNumeric;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Numeric>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct NonNumberToNumeric : public Descriptor<NonNumberToNumeric> {
    static constexpr auto kFunction = Builtin::kNonNumberToNumeric;
    using arguments_t = std::tuple<V<JSAnyNotNumber>>;
    using results_t = std::tuple<V<Numeric>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct CopyFastSmiOrObjectElements
      : public Descriptor<CopyFastSmiOrObjectElements> {
    static constexpr auto kFunction = Builtin::kCopyFastSmiOrObjectElements;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanWriteMemory().CanReadMemory().CanAllocate();
  };

  template <Builtin B, typename Input>
  struct DebugPrint : public Descriptor<DebugPrint<B, Input>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Input>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoThrow | Operator::kNoDeopt;
    static constexpr OpEffects kEffects = base_effects.RequiredWhenUnused();
  };
  using DebugPrintFloat64 = DebugPrint<Builtin::kDebugPrintFloat64, Float64>;
  using DebugPrintWordPtr = DebugPrint<Builtin::kDebugPrintWordPtr, WordPtr>;

  template <Builtin B>
  struct FindOrderedHashEntry : public Descriptor<FindOrderedHashEntry<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Object>, V<Smi>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.AssumesConsistentHeap().CanReadMemory().CanAllocate();
  };
  using FindOrderedHashMapEntry =
      FindOrderedHashEntry<Builtin::kFindOrderedHashMapEntry>;
  using FindOrderedHashSetEntry =
      FindOrderedHashEntry<Builtin::kFindOrderedHashSetEntry>;

  template <Builtin B>
  struct GrowFastElements : public Descriptor<GrowFastElements<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Object>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanWriteMemory().CanReadMemory().CanAllocate();
  };
  using GrowFastDoubleElements =
      GrowFastElements<Builtin::kGrowFastDoubleElements>;
  using GrowFastSmiOrObjectElements =
      GrowFastElements<Builtin::kGrowFastSmiOrObjectElements>;

  template <Builtin B>
  struct NewArgumentsElements : public Descriptor<NewArgumentsElements<B>> {
    static constexpr auto kFunction = B;
    // TODO(nicohartmann@): First argument should be replaced by a proper
    // RawPtr.
    using arguments_t = std::tuple<V<WordPtr>, V<WordPtr>, V<Smi>>;
    using results_t = std::tuple<V<FixedArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanAllocate();
  };
  using NewSloppyArgumentsElements =
      NewArgumentsElements<Builtin::kNewSloppyArgumentsElements>;
  using NewStrictArgumentsElements =
      NewArgumentsElements<Builtin::kNewStrictArgumentsElements>;
  using NewRestArgumentsElements =
      NewArgumentsElements<Builtin::kNewRestArgumentsElements>;

  struct NumberToString : public Descriptor<NumberToString> {
    static constexpr auto kFunction = Builtin::kNumberToString;
    using arguments_t = std::tuple<V<Number>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct ToString : public Descriptor<ToString> {
    static constexpr auto kFunction = Builtin::kToString;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct PlainPrimitiveToNumber : public Descriptor<PlainPrimitiveToNumber> {
    static constexpr auto kFunction = Builtin::kPlainPrimitiveToNumber;
    using arguments_t = std::tuple<V<PlainPrimitive>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct SameValue : public Descriptor<SameValue> {
    static constexpr auto kFunction = Builtin::kSameValue;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  struct SameValueNumbersOnly : public Descriptor<SameValueNumbersOnly> {
    static constexpr auto kFunction = Builtin::kSameValueNumbersOnly;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct StringAdd_CheckNone : public Descriptor<StringAdd_CheckNone> {
    static constexpr auto kFunction = Builtin::kStringAdd_CheckNone;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoWrite;
    // This will only write in a fresh object, so the writes are not visible
    // from Turboshaft, and CanAllocate is enough.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringEqual : public Descriptor<StringEqual> {
    static constexpr auto kFunction = Builtin::kStringEqual;
    using arguments_t = std::tuple<V<String>, V<String>, V<WordPtr>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    // If the strings aren't flat, StringEqual could flatten them, which will
    // allocate new strings.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringFromCodePointAt : public Descriptor<StringFromCodePointAt> {
    static constexpr auto kFunction = Builtin::kStringFromCodePointAt;
    using arguments_t = std::tuple<V<String>, V<WordPtr>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringIndexOf : public Descriptor<StringIndexOf> {
    static constexpr auto kFunction = Builtin::kStringIndexOf;
    using arguments_t = std::tuple<V<String>, V<String>, V<Smi>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    // StringIndexOf does a ToString on the receiver, which can allocate a new
    // string.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringCompare : public Descriptor<StringCompare> {
    static constexpr auto kFunction = Builtin::kStringCompare;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  template <Builtin B>
  struct StringComparison : public Descriptor<StringComparison<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };
  using StringLessThan = StringComparison<Builtin::kStringLessThan>;
  using StringLessThanOrEqual =
      StringComparison<Builtin::kStringLessThanOrEqual>;

  struct StringSubstring : public Descriptor<StringSubstring> {
    static constexpr auto kFunction = Builtin::kStringSubstring;
    using arguments_t = std::tuple<V<String>, V<WordPtr>, V<WordPtr>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

#ifdef V8_INTL_SUPPORT
  struct StringToLowerCaseIntl : public Descriptor<StringToLowerCaseIntl> {
    static constexpr auto kFunction = Builtin::kStringToLowerCaseIntl;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };
#endif  // V8_INTL_SUPPORT

  struct StringToNumber : public Descriptor<StringToNumber> {
    static constexpr auto kFunction = Builtin::kStringToNumber;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct ToBoolean : public Descriptor<ToBoolean> {
    static constexpr auto kFunction = Builtin::kToBoolean;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct ToObject : public Descriptor<ToObject> {
    static constexpr auto kFunction = Builtin::kToObject;
    using arguments_t = std::tuple<V<JSPrimitive>>;
    using results_t = std::tuple<V<JSReceiver>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  template <Builtin B>
  struct CreateFunctionContext : public Descriptor<CreateFunctionContext<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<ScopeInfo>, V<Word32>>;
    using results_t = std::tuple<V<Context>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  using FastNewFunctionContextFunction =
      CreateFunctionContext<Builtin::kFastNewFunctionContextFunction>;
  using FastNewFunctionContextEval =
      CreateFunctionContext<Builtin::kFastNewFunctionContextEval>;

  struct FastNewClosure : public Descriptor<FastNewClosure> {
    static constexpr auto kFunction = Builtin::kFastNewClosure;
    using arguments_t = std::tuple<V<SharedFunctionInfo>, V<FeedbackCell>>;
    using results_t = std::tuple<V<JSFunction>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kEliminatable | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanAllocate();
  };

  struct Typeof : public Descriptor<Typeof> {
    static constexpr auto kFunction = Builtin::kTypeof;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct CheckTurboshaftWord32Type
      : public Descriptor<CheckTurboshaftWord32Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftWord32Type;
    using arguments_t = std::tuple<V<Word32>, V<TurboshaftWord32Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftWord64Type
      : public Descriptor<CheckTurboshaftWord64Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftWord64Type;
    using arguments_t =
        std::tuple<V<Word32>, V<Word32>, V<TurboshaftWord64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftFloat32Type
      : public Descriptor<CheckTurboshaftFloat32Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftFloat32Type;
    using arguments_t =
        std::tuple<V<Float32>, V<TurboshaftFloat64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftFloat64Type
      : public Descriptor<CheckTurboshaftFloat64Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftFloat64Type;
    using arguments_t =
        std::tuple<V<Float64>, V<TurboshaftFloat64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

#ifdef V8_ENABLE_WEBASSEMBLY

  struct WasmStringAsWtf8 : public Descriptor<WasmStringAsWtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringAsWtf8;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<ByteArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringAsWtf16 : public Descriptor<WasmStringAsWtf16> {
    static constexpr auto kFunction = Builtin::kWasmStringAsWtf16;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmInt32ToHeapNumber : public Descriptor<WasmInt32ToHeapNumber> {
    static constexpr auto kFunction = Builtin::kWasmInt32ToHeapNumber;
    using arguments_t = std::tuple<V
### 提示词
```
这是目录为v8/src/compiler/turboshaft/builtin-call-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/builtin-call-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_BUILTIN_CALL_DESCRIPTORS_H_
#define V8_COMPILER_TURBOSHAFT_BUILTIN_CALL_DESCRIPTORS_H_

#include "src/builtins/builtins.h"
#include "src/codegen/callable.h"
#include "src/codegen/interface-descriptors.h"
#include "src/compiler/frame.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/objects/js-function.h"

namespace v8::internal::compiler::turboshaft {

struct BuiltinCallDescriptor {
 private:
  template <typename Derived>
  struct Descriptor {
    static const TSCallDescriptor* Create(
        StubCallMode call_mode, Zone* zone,
        LazyDeoptOnThrow lazy_deopt_on_throw = LazyDeoptOnThrow::kNo) {
      CallInterfaceDescriptor interface_descriptor =
          Builtins::CallInterfaceDescriptorFor(Derived::kFunction);
      auto descriptor = Linkage::GetStubCallDescriptor(
          zone, interface_descriptor,
          interface_descriptor.GetStackParameterCount(),
          Derived::kNeedsFrameState ? CallDescriptor::kNeedsFrameState
                                    : CallDescriptor::kNoFlags,
          Derived::kProperties, call_mode);
#ifdef DEBUG
      Derived::Verify(descriptor);
#endif  // DEBUG
      bool can_throw = !(Derived::kProperties & Operator::kNoThrow);
      return TSCallDescriptor::Create(
          descriptor, can_throw ? CanThrow::kYes : CanThrow::kNo,
          lazy_deopt_on_throw, zone);
    }

#ifdef DEBUG
    static void Verify(const CallDescriptor* desc) {
      using results_t = typename Derived::results_t;
      using arguments_t = typename Derived::arguments_t;
      DCHECK_EQ(desc->ReturnCount(), std::tuple_size_v<results_t>);
      if constexpr (std::tuple_size_v<results_t> >= 1) {
        using result0_t = std::tuple_element_t<0, results_t>;
        DCHECK(AllowsRepresentation<result0_t>(
            RegisterRepresentation::FromMachineRepresentation(
                desc->GetReturnType(0).representation())));
      }
      if constexpr (std::tuple_size_v<results_t> >= 2) {
        using result1_t = std::tuple_element_t<1, results_t>;
        DCHECK(AllowsRepresentation<result1_t>(
            RegisterRepresentation::FromMachineRepresentation(
                desc->GetReturnType(1).representation())));
      }
      DCHECK_EQ(desc->NeedsFrameState(), Derived::kNeedsFrameState);
      DCHECK_EQ(desc->properties(), Derived::kProperties);
      DCHECK_EQ(desc->ParameterCount(), std::tuple_size_v<arguments_t> +
                                            (Derived::kNeedsContext ? 1 : 0));
      DCHECK(VerifyArguments<arguments_t>(desc));
    }

    template <typename Arguments>
    static bool VerifyArguments(const CallDescriptor* desc) {
      return VerifyArgumentsImpl<Arguments>(
          desc, std::make_index_sequence<std::tuple_size_v<Arguments>>());
    }

   private:
    template <typename T>
    static bool AllowsRepresentation(RegisterRepresentation rep) {
      if constexpr (std::is_same_v<T, OpIndex>) {
        return true;
      } else {
        // T is V<...>
        return T::allows_representation(rep);
      }
    }
    template <typename Arguments, size_t... Indices>
    static bool VerifyArgumentsImpl(const CallDescriptor* desc,
                                    std::index_sequence<Indices...>) {
      return (AllowsRepresentation<std::tuple_element_t<Indices, Arguments>>(
                  RegisterRepresentation::FromMachineRepresentation(
                      desc->GetParameterType(Indices).representation())) &&
              ...);
    }
#endif  // DEBUG
  };

  static constexpr OpEffects base_effects = OpEffects().CanDependOnChecks();
  // TODO(nicohartmann@): Unfortunately, we cannot define builtins with
  // void/never return types properly (e.g. in Torque), but they typically have
  // a JSAny dummy return type. Use Void/Never sentinels to express that in
  // Turboshaft's descriptors. We should find a better way to model this.
  using Void = std::tuple<OpIndex>;
  using Never = std::tuple<OpIndex>;

 public:
  struct CheckTurbofanType : public Descriptor<CheckTurbofanType> {
    static constexpr auto kFunction = Builtin::kCheckTurbofanType;
    using arguments_t = std::tuple<V<Object>, V<TurbofanType>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoThrow | Operator::kNoDeopt;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().RequiredWhenUnused();
  };

#define DECL_GENERIC_BINOP(Name)                                          \
  struct Name : public Descriptor<Name> {                                 \
    static constexpr auto kFunction = Builtin::k##Name;                   \
    using arguments_t = std::tuple<V<Object>, V<Object>>;                 \
    using results_t = std::tuple<V<Object>>;                              \
                                                                          \
    static constexpr bool kNeedsFrameState = true;                        \
    static constexpr bool kNeedsContext = true;                           \
    static constexpr Operator::Properties kProperties =                   \
        Operator::kNoProperties;                                          \
    static constexpr OpEffects kEffects = base_effects.CanCallAnything(); \
  };
  GENERIC_BINOP_LIST(DECL_GENERIC_BINOP)
#undef DECL_GENERIC_BINOP

#define DECL_GENERIC_UNOP(Name)                                           \
  struct Name : public Descriptor<Name> {                                 \
    static constexpr auto kFunction = Builtin::k##Name;                   \
    using arguments_t = std::tuple<V<Object>>;                            \
    using results_t = std::tuple<V<Object>>;                              \
                                                                          \
    static constexpr bool kNeedsFrameState = true;                        \
    static constexpr bool kNeedsContext = true;                           \
    static constexpr Operator::Properties kProperties =                   \
        Operator::kNoProperties;                                          \
    static constexpr OpEffects kEffects = base_effects.CanCallAnything(); \
  };
  GENERIC_UNOP_LIST(DECL_GENERIC_UNOP)
#undef DECL_GENERIC_UNOP

  struct ToNumber : public Descriptor<ToNumber> {
    static constexpr auto kFunction = Builtin::kToNumber;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct NonNumberToNumber : public Descriptor<NonNumberToNumber> {
    static constexpr auto kFunction = Builtin::kNonNumberToNumber;
    using arguments_t = std::tuple<V<JSAnyNotNumber>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct ToNumeric : public Descriptor<ToNumeric> {
    static constexpr auto kFunction = Builtin::kToNumeric;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Numeric>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct NonNumberToNumeric : public Descriptor<NonNumberToNumeric> {
    static constexpr auto kFunction = Builtin::kNonNumberToNumeric;
    using arguments_t = std::tuple<V<JSAnyNotNumber>>;
    using results_t = std::tuple<V<Numeric>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct CopyFastSmiOrObjectElements
      : public Descriptor<CopyFastSmiOrObjectElements> {
    static constexpr auto kFunction = Builtin::kCopyFastSmiOrObjectElements;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanWriteMemory().CanReadMemory().CanAllocate();
  };

  template <Builtin B, typename Input>
  struct DebugPrint : public Descriptor<DebugPrint<B, Input>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Input>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoThrow | Operator::kNoDeopt;
    static constexpr OpEffects kEffects = base_effects.RequiredWhenUnused();
  };
  using DebugPrintFloat64 = DebugPrint<Builtin::kDebugPrintFloat64, Float64>;
  using DebugPrintWordPtr = DebugPrint<Builtin::kDebugPrintWordPtr, WordPtr>;

  template <Builtin B>
  struct FindOrderedHashEntry : public Descriptor<FindOrderedHashEntry<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Object>, V<Smi>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.AssumesConsistentHeap().CanReadMemory().CanAllocate();
  };
  using FindOrderedHashMapEntry =
      FindOrderedHashEntry<Builtin::kFindOrderedHashMapEntry>;
  using FindOrderedHashSetEntry =
      FindOrderedHashEntry<Builtin::kFindOrderedHashSetEntry>;

  template <Builtin B>
  struct GrowFastElements : public Descriptor<GrowFastElements<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<Object>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanWriteMemory().CanReadMemory().CanAllocate();
  };
  using GrowFastDoubleElements =
      GrowFastElements<Builtin::kGrowFastDoubleElements>;
  using GrowFastSmiOrObjectElements =
      GrowFastElements<Builtin::kGrowFastSmiOrObjectElements>;

  template <Builtin B>
  struct NewArgumentsElements : public Descriptor<NewArgumentsElements<B>> {
    static constexpr auto kFunction = B;
    // TODO(nicohartmann@): First argument should be replaced by a proper
    // RawPtr.
    using arguments_t = std::tuple<V<WordPtr>, V<WordPtr>, V<Smi>>;
    using results_t = std::tuple<V<FixedArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanAllocate();
  };
  using NewSloppyArgumentsElements =
      NewArgumentsElements<Builtin::kNewSloppyArgumentsElements>;
  using NewStrictArgumentsElements =
      NewArgumentsElements<Builtin::kNewStrictArgumentsElements>;
  using NewRestArgumentsElements =
      NewArgumentsElements<Builtin::kNewRestArgumentsElements>;

  struct NumberToString : public Descriptor<NumberToString> {
    static constexpr auto kFunction = Builtin::kNumberToString;
    using arguments_t = std::tuple<V<Number>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct ToString : public Descriptor<ToString> {
    static constexpr auto kFunction = Builtin::kToString;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct PlainPrimitiveToNumber : public Descriptor<PlainPrimitiveToNumber> {
    static constexpr auto kFunction = Builtin::kPlainPrimitiveToNumber;
    using arguments_t = std::tuple<V<PlainPrimitive>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct SameValue : public Descriptor<SameValue> {
    static constexpr auto kFunction = Builtin::kSameValue;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  struct SameValueNumbersOnly : public Descriptor<SameValueNumbersOnly> {
    static constexpr auto kFunction = Builtin::kSameValueNumbersOnly;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct StringAdd_CheckNone : public Descriptor<StringAdd_CheckNone> {
    static constexpr auto kFunction = Builtin::kStringAdd_CheckNone;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoWrite;
    // This will only write in a fresh object, so the writes are not visible
    // from Turboshaft, and CanAllocate is enough.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringEqual : public Descriptor<StringEqual> {
    static constexpr auto kFunction = Builtin::kStringEqual;
    using arguments_t = std::tuple<V<String>, V<String>, V<WordPtr>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    // If the strings aren't flat, StringEqual could flatten them, which will
    // allocate new strings.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringFromCodePointAt : public Descriptor<StringFromCodePointAt> {
    static constexpr auto kFunction = Builtin::kStringFromCodePointAt;
    using arguments_t = std::tuple<V<String>, V<WordPtr>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringIndexOf : public Descriptor<StringIndexOf> {
    static constexpr auto kFunction = Builtin::kStringIndexOf;
    using arguments_t = std::tuple<V<String>, V<String>, V<Smi>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    // StringIndexOf does a ToString on the receiver, which can allocate a new
    // string.
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct StringCompare : public Descriptor<StringCompare> {
    static constexpr auto kFunction = Builtin::kStringCompare;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  template <Builtin B>
  struct StringComparison : public Descriptor<StringComparison<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };
  using StringLessThan = StringComparison<Builtin::kStringLessThan>;
  using StringLessThanOrEqual =
      StringComparison<Builtin::kStringLessThanOrEqual>;

  struct StringSubstring : public Descriptor<StringSubstring> {
    static constexpr auto kFunction = Builtin::kStringSubstring;
    using arguments_t = std::tuple<V<String>, V<WordPtr>, V<WordPtr>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

#ifdef V8_INTL_SUPPORT
  struct StringToLowerCaseIntl : public Descriptor<StringToLowerCaseIntl> {
    static constexpr auto kFunction = Builtin::kStringToLowerCaseIntl;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };
#endif  // V8_INTL_SUPPORT

  struct StringToNumber : public Descriptor<StringToNumber> {
    static constexpr auto kFunction = Builtin::kStringToNumber;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Number>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct ToBoolean : public Descriptor<ToBoolean> {
    static constexpr auto kFunction = Builtin::kToBoolean;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<Boolean>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct ToObject : public Descriptor<ToObject> {
    static constexpr auto kFunction = Builtin::kToObject;
    using arguments_t = std::tuple<V<JSPrimitive>>;
    using results_t = std::tuple<V<JSReceiver>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  template <Builtin B>
  struct CreateFunctionContext : public Descriptor<CreateFunctionContext<B>> {
    static constexpr auto kFunction = B;
    using arguments_t = std::tuple<V<ScopeInfo>, V<Word32>>;
    using results_t = std::tuple<V<Context>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  using FastNewFunctionContextFunction =
      CreateFunctionContext<Builtin::kFastNewFunctionContextFunction>;
  using FastNewFunctionContextEval =
      CreateFunctionContext<Builtin::kFastNewFunctionContextEval>;

  struct FastNewClosure : public Descriptor<FastNewClosure> {
    static constexpr auto kFunction = Builtin::kFastNewClosure;
    using arguments_t = std::tuple<V<SharedFunctionInfo>, V<FeedbackCell>>;
    using results_t = std::tuple<V<JSFunction>>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties =
        Operator::kEliminatable | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanAllocate();
  };

  struct Typeof : public Descriptor<Typeof> {
    static constexpr auto kFunction = Builtin::kTypeof;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct CheckTurboshaftWord32Type
      : public Descriptor<CheckTurboshaftWord32Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftWord32Type;
    using arguments_t = std::tuple<V<Word32>, V<TurboshaftWord32Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftWord64Type
      : public Descriptor<CheckTurboshaftWord64Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftWord64Type;
    using arguments_t =
        std::tuple<V<Word32>, V<Word32>, V<TurboshaftWord64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftFloat32Type
      : public Descriptor<CheckTurboshaftFloat32Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftFloat32Type;
    using arguments_t =
        std::tuple<V<Float32>, V<TurboshaftFloat64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct CheckTurboshaftFloat64Type
      : public Descriptor<CheckTurboshaftFloat64Type> {
    static constexpr auto kFunction = Builtin::kCheckTurboshaftFloat64Type;
    using arguments_t =
        std::tuple<V<Float64>, V<TurboshaftFloat64Type>, V<Smi>>;
    using results_t = std::tuple<V<Oddball>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

#ifdef V8_ENABLE_WEBASSEMBLY

  struct WasmStringAsWtf8 : public Descriptor<WasmStringAsWtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringAsWtf8;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<ByteArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringAsWtf16 : public Descriptor<WasmStringAsWtf16> {
    static constexpr auto kFunction = Builtin::kWasmStringAsWtf16;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmInt32ToHeapNumber : public Descriptor<WasmInt32ToHeapNumber> {
    static constexpr auto kFunction = Builtin::kWasmInt32ToHeapNumber;
    using arguments_t = std::tuple<V<Word32>>;
    using results_t = std::tuple<V<HeapNumber>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kPure;
    static constexpr OpEffects kEffects =
        base_effects.CanAllocateWithoutIdentity();
  };

  struct WasmRefFunc : public Descriptor<WasmRefFunc> {
    static constexpr auto kFunction = Builtin::kWasmRefFunc;
    using arguments_t = std::tuple<V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<WasmFuncRef>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoThrow;
    // TODO(nicohartmann@): Use more precise effects.
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct WasmGetOwnProperty : public Descriptor<WasmGetOwnProperty> {
    static constexpr auto kFunction = Builtin::kWasmGetOwnProperty;
    using arguments_t = std::tuple<V<Object>, V<Symbol>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadHeapMemory();
  };

  struct WasmRethrow : public Descriptor<WasmRethrow> {
    static constexpr auto kFunction = Builtin::kWasmRethrow;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<OpIndex>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct WasmThrowRef : public Descriptor<WasmThrowRef> {
    static constexpr auto kFunction = Builtin::kWasmThrowRef;
    using arguments_t = std::tuple<V<Object>>;
    using results_t = std::tuple<OpIndex>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct WasmMemoryGrow : public Descriptor<WasmMemoryGrow> {
    static constexpr auto kFunction = Builtin::kWasmMemoryGrow;
    using arguments_t = std::tuple<V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory();
  };

  struct WasmStringFromCodePoint : public Descriptor<WasmStringFromCodePoint> {
    static constexpr auto kFunction = Builtin::kWasmStringFromCodePoint;
    using arguments_t = std::tuple<V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoWrite;
    static constexpr OpEffects kEffects =
        base_effects.CanAllocateWithoutIdentity().CanLeaveCurrentFunction();
  };

  struct WasmStringNewWtf8Array : public Descriptor<WasmStringNewWtf8Array> {
    static constexpr auto kFunction = Builtin::kWasmStringNewWtf8Array;
    using arguments_t = std::tuple<V<Word32>, V<Word32>, V<WasmArray>, V<Smi>>;
    using results_t = std::tuple<V<WasmStringRefNullable>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadHeapMemory()
                                              .CanAllocateWithoutIdentity()
                                              .CanLeaveCurrentFunction();
  };

  struct WasmStringNewWtf16Array : public Descriptor<WasmStringNewWtf16Array> {
    static constexpr auto kFunction = Builtin::kWasmStringNewWtf16Array;
    using arguments_t = std::tuple<V<WasmArray>, V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadHeapMemory()
                                              .CanAllocateWithoutIdentity()
                                              .CanLeaveCurrentFunction();
  };

  struct WasmStringViewWtf8Slice : public Descriptor<WasmStringViewWtf8Slice> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf8Slice;
    using arguments_t = std::tuple<V<ByteArray>, V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringViewWtf16Slice
      : public Descriptor<WasmStringViewWtf16Slice> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf16Slice;
    using arguments_t = std::tuple<V<String>, V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringEncodeWtf8Array
      : public Descriptor<WasmStringEncodeWtf8Array> {
    static constexpr auto kFunction = Builtin::kWasmStringEncodeWtf8Array;
    using arguments_t = std::tuple<V<String>, V<WasmArray>, V<Word32>, V<Smi>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteHeapMemory
```