Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Identification of Key Elements:**

The first step is a quick read-through to identify the main structural components. I see:

* **Copyright and Header Guards:** Standard boilerplate for C++ header files. Indicates this is an official V8 file.
* **Includes:**  `globals.h`, `operator.h`, `operations.h`, `runtime.h`. These hint at the file's purpose – dealing with runtime calls within the compiler. "turboshaft" in the path further suggests a connection to a newer compiler pipeline.
* **Namespace:** `v8::internal::compiler::turboshaft`. Confirms the location within the V8 codebase.
* **`RuntimeCallDescriptor` struct:** This is clearly the core of the file.
* **Nested `Descriptor` struct (template):** This looks like a helper for defining specific runtime call descriptors. The template structure is a clue that it's used to generate code for various runtime functions.
* **`using Void = ...;` and `using Never = ...;`:** Interesting type aliases. The comment suggests these are workarounds for limitations in Torque.
* **A series of structs inheriting from `Descriptor`:** `Abort`, `BigIntUnaryOp`, `DateCurrentTime`, etc. These seem to represent individual runtime functions. The names are quite descriptive.
* **`static constexpr` members within these structs:** `kFunction`, `arguments_t`, `result_t`, `kNeedsFrameState`, `kProperties`. These likely define the characteristics of each runtime call.

**2. Deciphering the `Descriptor` Template:**

The `Descriptor` template is crucial. I analyze its members:

* **`Create` method:** Takes a `Zone` (likely for memory management) and `LazyDeoptOnThrow`. It uses `Linkage::GetRuntimeCallDescriptor` to get a lower-level call descriptor. The `DCHECK_IMPLIES` suggests a connection between lazy deoptimization and frame states. The `#ifdef DEBUG` block indicates some verification logic in debug builds.
* **`Verify` method (within `#ifdef DEBUG`):**  This confirms the expected properties of the `CallDescriptor`, like return count, argument count, and frame state requirements. The `VerifyArguments` logic checks the types of the arguments.
* **`VerifyArguments` and `VerifyArgumentsImpl`:**  These use template metaprogramming to iterate over the argument types and ensure they are compatible with the call descriptor.

**3. Understanding the Specific Runtime Call Descriptors:**

Now I examine the structs inheriting from `Descriptor`:

* **`kFunction`:**  Links each descriptor to a `Runtime::k...` enum value. This is the actual runtime function being described.
* **`arguments_t`:**  A `std::tuple` defining the types of the arguments passed to the runtime function. The `V<>` template likely represents a value with a specific representation.
* **`result_t`:** Defines the return type of the runtime function. The use of `Void` and `Never` catches my attention due to the earlier comment.
* **`kNeedsFrameState`:** A boolean indicating if the runtime call requires a stack frame to be set up.
* **`kProperties`:** An `Operator::Properties` enum. This likely encodes information about the runtime call's behavior, such as whether it can deoptimize or throw exceptions.

**4. Connecting to JavaScript Functionality:**

This requires thinking about what these runtime functions actually *do*. The names are often a strong hint:

* **`Abort`:**  Likely related to unrecoverable errors.
* **`BigIntUnaryOp`:** Clearly operates on BigInts. This is a JavaScript language feature.
* **`DateCurrentTime`:**  Retrieves the current time, used by `Date` objects in JavaScript.
* **`DebugPrint`:** A debugging utility.
* **`StackGuard`:**  Manages stack overflow protection. Important for JavaScript execution.
* **The `Throw...` variants:**  These directly relate to JavaScript exception handling.
* **`NewClosure`:** Creates JavaScript closures (functions with captured context).
* **`HasInPrototypeChain`:** Implements the `in` operator and prototype chain lookup in JavaScript.

**5. Considering `.tq` Files and Torque:**

The prompt mentions `.tq` files and Torque. Based on my knowledge of V8, Torque is a language used to generate C++ code for runtime functions. The comment about `Void` and `Never` being workarounds "in Torque" strongly suggests that this header file defines the *interface* for runtime functions that are *implemented* in Torque. Thus, this header file is *not* a Torque file itself.

**6. Generating Examples and Reasoning:**

With the understanding of the runtime functions' purposes, I can create JavaScript examples that would trigger these runtime calls. The key is to identify the JavaScript operations that rely on these lower-level functions.

**7. Identifying Potential Programming Errors:**

The `Throw...` runtime functions are the most direct link to common JavaScript errors. I focus on those.

**8. Refining and Structuring the Answer:**

Finally, I organize the information logically, addressing each part of the prompt:

* **Functionality:**  Describe the overall purpose of the header file.
* **`.tq` extension:** Explain that it's not a Torque file, but describes interfaces for Torque-implemented functions.
* **JavaScript relationship:** Provide clear JavaScript examples for relevant runtime calls.
* **Logic and I/O:**  Offer simple examples to illustrate the input and output of specific runtime calls.
* **Common errors:**  Link the `Throw...` runtime calls to corresponding JavaScript errors.

This structured approach, moving from high-level overview to detailed analysis, and then connecting the C++ code back to JavaScript concepts, allows for a comprehensive understanding of the given header file.
This C++ header file (`runtime-call-descriptors.h`) in the V8 JavaScript engine defines descriptors for calling runtime functions from the Turboshaft compiler. Let's break down its functionalities:

**Core Functionality:**

1. **Defining Runtime Call Interfaces:** The primary purpose of this file is to establish a standardized way for the Turboshaft compiler (V8's newer optimizing compiler) to interact with the V8 runtime system. It defines the signature and properties of various runtime functions that Turboshaft might need to call during code generation.

2. **Abstraction Layer:**  It acts as an abstraction layer between the Turboshaft compiler and the actual implementation of the runtime functions. Turboshaft doesn't need to know the low-level details of how these functions are implemented; it only needs to know their input and output types, and other properties like whether they can throw exceptions.

3. **Type Safety:** The use of templates and explicit type definitions (`arguments_t`, `result_t`) enforces type safety when calling runtime functions from Turboshaft. This helps prevent errors during compilation and runtime.

4. **Metadata about Runtime Functions:** Each `struct` (like `Abort`, `BigIntUnaryOp`, etc.) within `RuntimeCallDescriptor` represents a specific runtime function and stores crucial metadata about it:
    * `kFunction`:  The actual `Runtime::k...` enum value identifying the runtime function.
    * `arguments_t`: A `std::tuple` defining the expected types of the arguments to the runtime function.
    * `result_t`: The expected return type of the runtime function.
    * `kNeedsFrameState`: Indicates whether the runtime call requires a proper stack frame to be set up.
    * `kProperties`:  Flags indicating properties of the runtime call, such as whether it can deoptimize or throw exceptions.

**Regarding the `.tq` extension:**

The header file you provided (`runtime-call-descriptors.h`) does **not** end with `.tq`. Therefore, it is **not** a V8 Torque source file. Torque files are typically used to define the implementation of runtime functions and built-in JavaScript functions in a more high-level, type-safe manner. This `.h` file defines the *interface* for those runtime functions that might be implemented in Torque or C++.

**Relationship with JavaScript Functionality and Examples:**

Many of the runtime functions described in this file are directly related to fundamental JavaScript operations. Here are some examples:

* **`Abort`:**  This runtime function is likely called when a critical error occurs within the V8 engine that prevents further execution. This isn't directly triggered by user JavaScript code in a predictable way but signifies internal engine failures.

* **`BigIntUnaryOp`:** This handles unary operations (like negation `-`) on `BigInt` values in JavaScript.
   ```javascript
   const bigIntValue = 9007199254740991n;
   const negativeBigInt = -bigIntValue; // This might trigger a call to Runtime::kBigIntUnaryOp
   console.log(negativeBigInt); // Output: -9007199254740991n
   ```
   **Hypothetical Input/Output:**
   * **Input (to `Runtime::kBigIntUnaryOp`):**  The `BigInt` value `9007199254740991n` and an identifier for the negation operation.
   * **Output:** The negated `BigInt` value `-9007199254740991n`.

* **`DateCurrentTime`:**  Used to get the current time for `Date` objects.
   ```javascript
   const now = new Date(); // This might trigger a call to Runtime::kDateCurrentTime internally
   console.log(now.getTime());
   ```
   **Hypothetical Input/Output:**
   * **Input (to `Runtime::kDateCurrentTime`):**  (Potentially no direct input, relies on system time).
   * **Output:** A numerical timestamp representing the current time.

* **`DebugPrint`:**  Allows developers to print values during debugging (often used internally in V8 development). This is usually not directly accessible in standard JavaScript.

* **`StackGuard` and `StackGuardWithGap`:** These are crucial for preventing stack overflow errors in JavaScript. When the call stack gets too deep (due to excessive recursion, for example), these runtime functions are invoked to handle the situation.

* **`StringCharCodeAt`:**  Implements the `charCodeAt()` method of strings.
   ```javascript
   const str = "hello";
   const charCode = str.charCodeAt(1); // This would call Runtime::kStringCharCodeAt
   console.log(charCode); // Output: 101 (ASCII code for 'e')
   ```
   **Hypothetical Input/Output:**
   * **Input (to `Runtime::kStringCharCodeAt`):** The string "hello" and the index 1.
   * **Output:** The Smi (small integer) value 101.

* **`StringToUpperCaseIntl`:**  Handles converting strings to uppercase, potentially considering locale-specific rules (if `V8_INTL_SUPPORT` is enabled).
   ```javascript
   const str = "hello";
   const upperStr = str.toUpperCase(); // Could call Runtime::kStringToUpperCaseIntl
   console.log(upperStr); // Output: HELLO
   ```
   **Hypothetical Input/Output:**
   * **Input (to `Runtime::kStringToUpperCaseIntl`):** The string "hello".
   * **Output:** The string "HELLO".

* **`SymbolDescriptiveString`:**  Retrieves the description of a Symbol object.
   ```javascript
   const mySymbol = Symbol("myDescription");
   const description = String(mySymbol); // Might call Runtime::kSymbolDescriptiveString
   console.log(description); // Output: Symbol(myDescription)
   ```
   **Hypothetical Input/Output:**
   * **Input (to `Runtime::kSymbolDescriptiveString`):** The Symbol object `mySymbol`.
   * **Output:** The string "myDescription".

* **The `Throw...` runtime functions:** These are called when JavaScript code performs operations that result in errors.

**Common Programming Errors and Corresponding Runtime Functions:**

The `Throw...` structs in this file directly correspond to common JavaScript programming errors:

* **`ThrowAccessedUninitializedVariable`:** Occurs when you try to use a variable before it has been assigned a value (within its scope).
   ```javascript
   function example() {
     console.log(x); // Error: Cannot access 'x' before initialization
     let x = 10;
   }
   example(); // This would trigger Runtime::kThrowAccessedUninitializedVariable
   ```

* **`ThrowConstructorReturnedNonObject`:**  Happens when a constructor function explicitly returns a primitive value instead of an object.
   ```javascript
   function MyClass() {
     this.value = 5;
     return 10; // Invalid: Should return an object or nothing (implicit return of 'this')
   }
   new MyClass(); // This would trigger Runtime::kThrowConstructorReturnedNonObject
   ```

* **`ThrowNotSuperConstructor`:**  Occurs when `super()` is called outside of a derived class constructor or when the class being extended is not a valid constructor.

* **`ThrowSuperAlreadyCalledError`:**  Triggered when `super()` is called multiple times within a derived class constructor.

* **`ThrowSuperNotCalled`:**  Happens when the `super()` call is missing in a derived class constructor.

* **`ThrowCalledNonCallable`:**  Occurs when you try to call a value that is not a function.
   ```javascript
   const notAFunction = 5;
   notAFunction(); // Error: notAFunction is not a function
   ```

* **`ThrowInvalidStringLength`:**  Happens when you try to create a string with a negative or excessively large length.
   ```javascript
   const str = "a".repeat(-1); // Error: Invalid count value
   ```

**In summary, `v8/src/compiler/turboshaft/runtime-call-descriptors.h` is a crucial header file that defines the interface between the Turboshaft compiler and the V8 runtime system. It provides a structured and type-safe way for the compiler to call upon the functionality implemented in the runtime, many of which are fundamental to the execution of JavaScript code.**

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/runtime-call-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/runtime-call-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_RUNTIME_CALL_DESCRIPTORS_H_
#define V8_COMPILER_TURBOSHAFT_RUNTIME_CALL_DESCRIPTORS_H_

#include "src/compiler/globals.h"
#include "src/compiler/operator.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/runtime/runtime.h"

namespace v8::internal::compiler::turboshaft {

struct RuntimeCallDescriptor {
 private:
  template <typename Derived>
  struct Descriptor {
    static const TSCallDescriptor* Create(
        Zone* zone, LazyDeoptOnThrow lazy_deopt_on_throw) {
      DCHECK_IMPLIES(lazy_deopt_on_throw == LazyDeoptOnThrow::kYes,
                     Derived::kNeedsFrameState);
      auto descriptor = Linkage::GetRuntimeCallDescriptor(
          zone, Derived::kFunction,
          std::tuple_size_v<typename Derived::arguments_t>,
          Derived::kProperties,
          Derived::kNeedsFrameState ? CallDescriptor::kNeedsFrameState
                                    : CallDescriptor::kNoFlags);
#ifdef DEBUG
      Derived::Verify(descriptor);
#endif  // DEBUG
      CanThrow can_throw = (Derived::kProperties & Operator::kNoThrow)
                               ? CanThrow::kNo
                               : CanThrow::kYes;
      return TSCallDescriptor::Create(descriptor, can_throw,
                                      lazy_deopt_on_throw, zone);
    }

#ifdef DEBUG
    static void Verify(const CallDescriptor* desc) {
      using result_t = typename Derived::result_t;
      using arguments_t = typename Derived::arguments_t;
      if constexpr (std::is_same_v<result_t, void>) {
        DCHECK_EQ(desc->ReturnCount(), 0);
      } else {
        DCHECK_EQ(desc->ReturnCount(), 1);
        DCHECK(result_t::allows_representation(
            RegisterRepresentation::FromMachineRepresentation(
                desc->GetReturnType(0).representation())));
      }
      DCHECK_EQ(desc->NeedsFrameState(), Derived::kNeedsFrameState);
      DCHECK_EQ(desc->properties(), Derived::kProperties);
      constexpr int additional_stub_arguments =
          3;  // function id, argument count, context (or NoContextConstant)
      DCHECK_EQ(desc->ParameterCount(),
                std::tuple_size_v<arguments_t> + additional_stub_arguments);
      DCHECK(VerifyArguments<arguments_t>(desc));
    }

    template <typename Arguments>
    static bool VerifyArguments(const CallDescriptor* desc) {
      return VerifyArgumentsImpl<Arguments>(
          desc, std::make_index_sequence<std::tuple_size_v<Arguments>>());
    }

   private:
    template <typename Arguments, size_t... Indices>
    static bool VerifyArgumentsImpl(const CallDescriptor* desc,
                                    std::index_sequence<Indices...>) {
      return (std::tuple_element_t<Indices, Arguments>::allows_representation(
                  RegisterRepresentation::FromMachineRepresentation(
                      desc->GetParameterType(Indices).representation())) &&
              ...);
    }
#endif  // DEBUG
  };

  // TODO(nicohartmann@): Unfortunately, we cannot define builtins with
  // void/never return types properly (e.g. in Torque), but they typically have
  // a JSAny dummy return type. Use Void/Never sentinels to express that in
  // Turboshaft's descriptors. We should find a better way to model this.
  using Void = V<Any>;
  using Never = V<Any>;

 public:
  struct Abort : public Descriptor<Abort> {
    static constexpr auto kFunction = Runtime::kAbort;
    using arguments_t = std::tuple<V<Smi>>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct BigIntUnaryOp : public Descriptor<BigIntUnaryOp> {
    static constexpr auto kFunction = Runtime::kBigIntUnaryOp;
    using arguments_t = std::tuple<V<BigInt>, V<Smi>>;
    using result_t = V<BigInt>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct DateCurrentTime : public Descriptor<DateCurrentTime> {
    static constexpr auto kFunction = Runtime::kDateCurrentTime;
    using arguments_t = std::tuple<>;
    using result_t = V<Number>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct DebugPrint : public Descriptor<DebugPrint> {
    static constexpr auto kFunction = Runtime::kDebugPrint;
    using arguments_t = std::tuple<V<Object>>;
    using result_t = Void;  // No actual result

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct StackGuard : public Descriptor<StackGuard> {
    static constexpr auto kFunction = Runtime::kStackGuard;
    using arguments_t = std::tuple<>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = false;
    // TODO(nicohartmann@): Verify this.
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct StackGuardWithGap : public Descriptor<StackGuardWithGap> {
    static constexpr auto kFunction = Runtime::kStackGuardWithGap;
    using arguments_t = std::tuple<V<Smi>>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = true;
    // TODO(nicohartmann@): Verify this.
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct HandleNoHeapWritesInterrupts
      : public Descriptor<HandleNoHeapWritesInterrupts> {
    static constexpr auto kFunction = Runtime::kHandleNoHeapWritesInterrupts;
    using arguments_t = std::tuple<>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoWrite;
  };

  struct PropagateException : public Descriptor<PropagateException> {
    static constexpr auto kFunction = Runtime::kPropagateException;
    using arguments_t = std::tuple<>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ReThrow : public Descriptor<ReThrow> {
    static constexpr auto kFunction = Runtime::kReThrow;
    using arguments_t = std::tuple<V<Object>>;
    using result_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties = Operator::kNoThrow;
  };

  struct StringCharCodeAt : public Descriptor<StringCharCodeAt> {
    static constexpr auto kFunction = Runtime::kStringCharCodeAt;
    using arguments_t = std::tuple<V<String>, V<Number>>;
    using result_t = V<Smi>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

#ifdef V8_INTL_SUPPORT
  struct StringToUpperCaseIntl : public Descriptor<StringToUpperCaseIntl> {
    static constexpr auto kFunction = Runtime::kStringToUpperCaseIntl;
    using arguments_t = std::tuple<V<String>>;
    using result_t = V<String>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };
#endif  // V8_INTL_SUPPORT

  struct SymbolDescriptiveString : public Descriptor<SymbolDescriptiveString> {
    static constexpr auto kFunction = Runtime::kSymbolDescriptiveString;
    using arguments_t = std::tuple<V<Symbol>>;
    using result_t = V<String>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoDeopt;
  };

  struct TerminateExecution : public Descriptor<TerminateExecution> {
    static constexpr auto kFunction = Runtime::kTerminateExecution;
    using arguments_t = std::tuple<>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoDeopt;
  };

  struct TransitionElementsKind : public Descriptor<TransitionElementsKind> {
    static constexpr auto kFunction = Runtime::kTransitionElementsKind;
    using arguments_t = std::tuple<V<HeapObject>, V<Map>>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct TryMigrateInstance : public Descriptor<TryMigrateInstance> {
    static constexpr auto kFunction = Runtime::kTryMigrateInstance;
    using arguments_t = std::tuple<V<HeapObject>>;
    using result_t = V<Object>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
  };

  struct ThrowAccessedUninitializedVariable
      : public Descriptor<ThrowAccessedUninitializedVariable> {
    static constexpr auto kFunction =
        Runtime::kThrowAccessedUninitializedVariable;
    using arguments_t = std::tuple<V<Object>>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowConstructorReturnedNonObject
      : public Descriptor<ThrowConstructorReturnedNonObject> {
    static constexpr auto kFunction =
        Runtime::kThrowConstructorReturnedNonObject;
    using arguments_t = std::tuple<>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowNotSuperConstructor
      : public Descriptor<ThrowNotSuperConstructor> {
    static constexpr auto kFunction = Runtime::kThrowNotSuperConstructor;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowSuperAlreadyCalledError
      : public Descriptor<ThrowSuperAlreadyCalledError> {
    static constexpr auto kFunction = Runtime::kThrowSuperAlreadyCalledError;
    using arguments_t = std::tuple<>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowSuperNotCalled : public Descriptor<ThrowSuperNotCalled> {
    static constexpr auto kFunction = Runtime::kThrowSuperNotCalled;
    using arguments_t = std::tuple<>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowCalledNonCallable : public Descriptor<ThrowCalledNonCallable> {
    static constexpr auto kFunction = Runtime::kThrowCalledNonCallable;
    using arguments_t = std::tuple<V<Object>>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct ThrowInvalidStringLength
      : public Descriptor<ThrowInvalidStringLength> {
    static constexpr auto kFunction = Runtime::kThrowInvalidStringLength;
    using arguments_t = std::tuple<>;
    // Doesn't actually return something, but the actual runtime call descriptor
    // (returned by Linkage::GetRuntimeCallDescriptor) returns 1 instead of 0.
    using result_t = Never;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };

  struct NewClosure : public Descriptor<NewClosure> {
    static constexpr auto kFunction = Runtime::kNewClosure;
    using arguments_t = std::tuple<V<SharedFunctionInfo>, V<FeedbackCell>>;
    using result_t = V<JSFunction>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties = Operator::kNoThrow;
  };

  struct NewClosure_Tenured : public Descriptor<NewClosure_Tenured> {
    static constexpr auto kFunction = Runtime::kNewClosure_Tenured;
    using arguments_t = std::tuple<V<SharedFunctionInfo>, V<FeedbackCell>>;
    using result_t = V<JSFunction>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr Operator::Properties kProperties = Operator::kNoThrow;
  };

  struct HasInPrototypeChain : public Descriptor<HasInPrototypeChain> {
    static constexpr auto kFunction = Runtime::kHasInPrototypeChain;
    using arguments_t = std::tuple<V<Object>, V<HeapObject>>;
    using result_t = V<Boolean>;

    static constexpr bool kNeedsFrameState = true;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
  };
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_RUNTIME_CALL_DESCRIPTORS_H_

"""

```