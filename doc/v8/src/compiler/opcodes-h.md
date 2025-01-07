Response:
Let's break down the thought process for analyzing this `opcodes.h` file.

**1. Initial Scan and Keywords:**

The first step is a quick skim of the file, looking for obvious patterns and keywords. I immediately see:

* `#ifndef`, `#define`, `#endif`: This strongly indicates a header file used for preventing multiple inclusions. This isn't about functionality *per se*, but it's important context.
* `#include`:  Standard C++ header inclusion. `iosfwd` and `src/common/globals.h` suggest this is part of a larger C++ project (V8).
* `#define CONTROL_OP_LIST(V)`, `#define MACHINE_LEVEL_CONSTANT_OP_LIST(V)`, etc.: This is the most striking pattern. The repeated structure with `_OP_LIST` and a macro argument `V` strongly suggests a mechanism for defining sets of opcodes.
* Comments like "// Opcodes for control operators." give direct hints about the purpose of each section.
* Names like `Start`, `Loop`, `Branch`, `Int32Constant`, `JSAdd`, `NumberAdd`, `Word32Add`, `Float64Add`: These look like names of operations, varying in specificity (JS level, machine level, etc.).

**2. Understanding the Macro Pattern:**

The key to understanding the file is grasping how the `_OP_LIST` macros work. The `#define` followed by a name ending in `_OP_LIST(V)` and then a series of `V(...)` is a common C preprocessor technique.

* **Hypothesis:** The macro `V` acts as a placeholder. When these macros are used elsewhere in the V8 codebase, `V` will be replaced with something that performs an action on each opcode in the list.

* **Example:** Imagine a function that needs to iterate over all control opcodes. It might use the `CONTROL_OP_LIST` macro like this:

   ```c++
   void ProcessControlOpcodes(OpcodeAction action) {
     #define V(opcode) action(opcode)
     CONTROL_OP_LIST(V);
     #undef V
   }
   ```

   In this hypothetical example, `action` is a function or function object that takes an opcode as input. The macro substitution would generate:

   ```c++
   action(Start);
   action(Loop);
   action(Branch);
   // ... and so on
   ```

* **Confirmation:**  The sheer number of these `_OP_LIST` macros reinforces this idea. It's a systematic way to organize and reuse lists of operations.

**3. Categorizing the Opcodes:**

The comments and the prefixes in the opcode names are crucial for categorization:

* **Control Flow:** `CONTROL_OP_LIST` -  Operations that control the execution order of code (loops, branches, returns, etc.).
* **Constants:** `CONSTANT_OP_LIST`, `MACHINE_LEVEL_CONSTANT_OP_LIST`, `JS_LEVEL_CONSTANT_OP_LIST` -  Representing constant values of different types.
* **Intermediate/Internal:** `INNER_OP_LIST` - Operations used within the compiler's internal representation of code.
* **JavaScript Operations:** `JS_OP_LIST`, and its sub-lists (`JS_COMPARE_BINOP_LIST`, `JS_ARITH_BINOP_LIST`, etc.) - Operations that directly correspond to JavaScript language features.
* **Simplified/Virtual Machine:** `SIMPLIFIED_OP_LIST` - Operations at a lower level than JavaScript, representing more basic actions. This seems like an intermediate representation during compilation.
* **Machine Level:** `MACHINE_OP_LIST` - Operations that map relatively closely to the instructions of the target processor.
* **SIMD:** `MACHINE_SIMD128_OP_LIST` -  Operations for Single Instruction, Multiple Data (SIMD) processing, indicating optimization for parallel operations.

**4. Identifying Connections to JavaScript:**

The `JS_OP_LIST` and its sub-lists clearly have a direct relationship to JavaScript. I can start mapping specific opcodes to JavaScript concepts:

* `JSAdd`: The `+` operator. Example: `let sum = a + b;`
* `JSLoadProperty`: Accessing object properties. Example: `let value = obj.property;` or `let value = obj['property'];`
* `JSCall`: Calling functions. Example: `functionName();` or `object.method();`
* `JSCreateArray`: Creating arrays. Example: `let arr = [1, 2, 3];`
* `JSToNumber`: Converting values to numbers. Example: `Number("10");`

**5. Inferring Functionality and Purpose:**

Based on the categories and the names of the opcodes, I can infer the overall purpose of the file:

* **Defining the Building Blocks of Compilation:**  This file defines the fundamental operations that the V8 compiler uses to represent and manipulate code as it translates JavaScript into machine code.
* **Abstraction Layers:** The different categories of opcodes (JS, Simplified, Machine) represent different levels of abstraction during the compilation process. The compiler likely starts with high-level JS opcodes and gradually lowers them to machine-level opcodes.
* **Optimization:**  Opcodes like the SIMD instructions indicate that V8 performs optimizations to leverage hardware capabilities.
* **Internal Representation:**  The `INNER_OP_LIST` suggests that the compiler uses its own internal representation of the code graph.

**6. Considering Potential Errors:**

Thinking about how these opcodes relate to JavaScript errors leads to examples:

* **Type Errors:** Opcodes like `JSToNumber` and `JSAdd` imply that the compiler needs to handle type conversions. A common error is trying to add values of incompatible types, leading to `NaN` or exceptions.
* **Reference Errors:**  `JSLoadProperty` and `JSStoreProperty` suggest potential errors when accessing non-existent properties.
* **Call Stack Errors:** The control flow opcodes (`Loop`, `Branch`, `Return`) are related to how functions are called and executed. Infinite loops or stack overflows are potential issues.

**7. Refining the Summary:**

Finally, I synthesize the observations into a concise summary, emphasizing the key functionalities: defining opcodes, categorizing them by abstraction level, and their role in the V8 compilation pipeline.

This iterative process of scanning, hypothesizing, confirming, categorizing, and connecting to higher-level concepts is essential for understanding complex code like this.
Let's break down the functionality of `v8/src/compiler/opcodes.h` step-by-step.

**Core Functionality: Defining Opcodes for V8's Compiler**

The primary function of `v8/src/compiler/opcodes.h` is to define a comprehensive set of *opcodes* used within V8's optimizing compiler (Turbofan). Opcodes are essentially symbolic names representing specific operations or instructions. Think of them as the vocabulary of the compiler's internal language.

**Explanation of the Structure:**

The file uses C preprocessor macros (`#define`) extensively to create lists of opcodes. The general pattern is:

```c++
#define CATEGORY_OP_LIST(V) \
  V(OpcodeName1)          \
  V(OpcodeName2)          \
  V(OpcodeName3)          \
  ...
```

The macro `V` acts as a placeholder. When these lists are used elsewhere in the V8 codebase, `V` will be replaced with something that performs an action on each opcode in the list (e.g., defining an enum value, creating a string representation, etc.).

**Categorization of Opcodes:**

The opcodes are organized into several logical categories, reflecting different stages of compilation or levels of abstraction:

* **`CONTROL_OP_LIST`:**  Opcodes related to control flow, such as `Start`, `Loop`, `Branch`, `Return`, `IfTrue`, `IfFalse`, etc. These represent how the execution path of the compiled code is managed.

* **`CONSTANT_OP_LIST` (and its sub-lists):** Opcodes for representing constant values. This is further divided into:
    * `MACHINE_LEVEL_CONSTANT_OP_LIST`: Constants at the machine level (integers, floats).
    * `JS_LEVEL_CONSTANT_OP_LIST`: Constants related to JavaScript concepts (external constants, numbers, heap objects).

* **`INNER_OP_LIST`:** Opcodes for internal operations within the compiler, such as `Phi` (for merging values from different control flow paths), `Call`, `Parameter`, `FrameState` (representing the state of the call stack).

* **`COMMON_OP_LIST`:** A combination of constant and inner opcodes, along with some general-purpose opcodes like `Unreachable` and `DeadValue`.

* **`JS_OP_LIST` (and its sub-lists):** This is a large category containing opcodes that directly correspond to JavaScript language features and operations. It's further broken down into:
    * `JS_COMPARE_BINOP_LIST`, `JS_BITWISE_BINOP_LIST`, `JS_ARITH_BINOP_LIST`: Binary operators.
    * `JS_CONVERSION_UNOP_LIST`, `JS_BITWISE_UNOP_LIST`, `JS_ARITH_UNOP_LIST`: Unary operators.
    * `JS_CREATE_OP_LIST`: Operations for creating JavaScript objects, arrays, functions, etc.
    * `JS_OBJECT_OP_LIST`: Operations for working with JavaScript objects (loading properties, setting properties).
    * `JS_CONTEXT_OP_LIST`: Operations related to JavaScript execution contexts.
    * `JS_CALL_OP_LIST`, `JS_CONSTRUCT_OP_LIST`: Operations for calling and constructing JavaScript functions.
    * `JS_OTHER_OP_LIST`:  Various other JavaScript-related operations.

* **`SIMPLIFIED_OP_LIST` (and its sub-lists):** Opcodes at a lower level than the JavaScript opcodes, representing more fundamental operations. This is often an intermediate representation used during compilation. It includes operations for:
    * Type conversions (`SIMPLIFIED_CHANGE_OP_LIST`).
    * Checked arithmetic (`SIMPLIFIED_CHECKED_OP_LIST`).
    * Comparisons (`SIMPLIFIED_COMPARE_BINOP_LIST`).
    * Number and BigInt operations (`SIMPLIFIED_NUMBER_BINOP_LIST`, `SIMPLIFIED_BIGINT_BINOP_LIST`, etc.).
    * Memory allocation and access.
    * Type checks and assertions.

* **`MACHINE_OP_LIST` (and its sub-lists):** Opcodes that represent machine-level instructions, often closely mapping to the instruction set of the target architecture (e.g., x64, ARM). It includes operations for:
    * Arithmetic and bitwise operations on words (integers).
    * Comparisons.
    * Floating-point operations.
    * Atomic operations.
    * Memory access (load and store).
    * Control flow at the machine level.

* **`MACHINE_SIMD128_OP_LIST`:** Opcodes for Single Instruction, Multiple Data (SIMD) operations, allowing for parallel processing of data.

**If `v8/src/compiler/opcodes.h` ended in `.tq`:**

If the file ended in `.tq`, it would indeed be a V8 Torque source file. Torque is a domain-specific language used within V8 for defining built-in functions and certain compiler components in a more type-safe and maintainable way than raw C++. This particular file, however, uses standard C++ preprocessor directives.

**Relationship to JavaScript Functionality and Examples:**

The opcodes defined in this file are the underlying building blocks used to implement JavaScript functionality. Here are some examples illustrating the connection:

* **JavaScript Addition (`+`)**: The `JSAdd` opcode in `JS_ARITH_BINOP_LIST` corresponds directly to the JavaScript addition operator. When the V8 compiler encounters `a + b` in your JavaScript code, it might generate a `JSAdd` opcode in its internal representation.

   ```javascript
   let x = 5;
   let y = 10;
   let sum = x + y; // This operation will likely involve the JSAdd opcode internally.
   ```

* **JavaScript Object Property Access (`.`)**: The `JSLoadProperty` opcode in `JS_OBJECT_OP_LIST` is used when accessing properties of JavaScript objects.

   ```javascript
   const myObject = { name: "Alice", age: 30 };
   let personName = myObject.name; // This access will likely involve the JSLoadProperty opcode.
   ```

* **JavaScript Function Call**: The `JSCall` opcode in `JS_CALL_OP_LIST` is fundamental for executing JavaScript functions.

   ```javascript
   function greet(name) {
     console.log("Hello, " + name + "!");
   }
   greet("Bob"); // This function call will involve the JSCall opcode.
   ```

* **JavaScript `if` Statement**: The `IfTrue` and `IfFalse` opcodes in `CONTROL_OP_LIST` are used to implement conditional execution.

   ```javascript
   let condition = true;
   if (condition) { // This if statement will use IfTrue/IfFalse opcodes.
     console.log("Condition is true");
   } else {
     console.log("Condition is false");
   }
   ```

**Code Logic Reasoning (Hypothetical):**

Let's consider a simple JavaScript function and how it might be translated to opcodes:

**Hypothetical Input (JavaScript):**

```javascript
function add(a, b) {
  return a + b;
}
```

**Hypothetical Output (Simplified Opcodes - simplified for illustration):**

1. **`Parameter`**:  Get the value of parameter `a`.
2. **`Parameter`**:  Get the value of parameter `b`.
3. **`JSAdd`**: Perform JavaScript addition on the two parameter values.
4. **`Return`**: Return the result of the addition.

**User Common Programming Errors:**

Understanding opcodes can indirectly help understand the cost of certain operations and potential performance pitfalls. Here are examples of how common errors relate to these low-level concepts:

* **Type Mismatches**:  JavaScript's dynamic typing means you can try to add values of incompatible types (e.g., a number and a string). The compiler will generate opcodes like `JSToNumber` or `JSToString` for implicit type conversions. Frequent implicit conversions can sometimes be a performance bottleneck.

   ```javascript
   let num = 10;
   let str = "20";
   let result = num + str; // JavaScript will convert `num` to a string before concatenation.
   ```

* **Accessing Non-Existent Properties**: Trying to access a property that doesn't exist on an object will result in `undefined`. Internally, this might involve `JSLoadProperty` and checks for the property's existence. Repeatedly accessing potentially missing properties can be inefficient.

   ```javascript
   const obj = { name: "Charlie" };
   console.log(obj.age); // Accessing a non-existent property.
   ```

* **Inefficient Loops**:  Complex loop conditions or operations within loops can translate to a larger number of control flow opcodes and JavaScript opcodes, potentially impacting performance.

   ```javascript
   for (let i = 0; i < largeArray.length; i++) {
     // Complex operations inside the loop
   }
   ```

**Summary of Functionality (Part 1):**

In summary, `v8/src/compiler/opcodes.h` serves as the central definition of the *vocabulary* used by V8's optimizing compiler. It enumerates a wide range of operations, categorized by their level of abstraction (from high-level JavaScript operations down to low-level machine instructions). This file is crucial for the compiler's ability to translate JavaScript code into efficient machine code. The opcodes represent the fundamental actions the compiler can perform during this translation process.

Prompt: 
```
这是目录为v8/src/compiler/opcodes.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/opcodes.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_OPCODES_H_
#define V8_COMPILER_OPCODES_H_

#include <iosfwd>

#include "src/common/globals.h"

// Opcodes for control operators.
#define CONTROL_OP_LIST(V) \
  V(Start)                 \
  V(Loop)                  \
  V(Branch)                \
  V(Switch)                \
  V(IfTrue)                \
  V(IfFalse)               \
  V(IfSuccess)             \
  V(IfException)           \
  V(IfValue)               \
  V(IfDefault)             \
  V(Merge)                 \
  V(Deoptimize)            \
  V(DeoptimizeIf)          \
  V(DeoptimizeUnless)      \
  V(Assert)                \
  V(TrapIf)                \
  V(TrapUnless)            \
  V(Return)                \
  V(TailCall)              \
  V(Terminate)             \
  V(Throw)                 \
  V(End)

#define MACHINE_LEVEL_CONSTANT_OP_LIST(V) \
  V(Int32Constant)                        \
  V(Int64Constant)                        \
  V(TaggedIndexConstant)                  \
  V(Float32Constant)                      \
  V(Float64Constant)                      \
  V(CompressedHeapConstant)               \
  V(RelocatableInt32Constant)             \
  V(RelocatableInt64Constant)

#define JS_LEVEL_CONSTANT_OP_LIST(V) \
  V(ExternalConstant)                \
  V(NumberConstant)                  \
  V(PointerConstant)                 \
  V(HeapConstant)                    \
  V(TrustedHeapConstant)

// Opcodes for constant operators.
#define CONSTANT_OP_LIST(V)    \
  JS_LEVEL_CONSTANT_OP_LIST(V) \
  MACHINE_LEVEL_CONSTANT_OP_LIST(V)

#define INNER_OP_LIST(V)    \
  V(Select)                 \
  V(Phi)                    \
  V(EffectPhi)              \
  V(InductionVariablePhi)   \
  V(Checkpoint)             \
  V(BeginRegion)            \
  V(FinishRegion)           \
  V(FrameState)             \
  V(StateValues)            \
  V(TypedStateValues)       \
  V(ArgumentsElementsState) \
  V(ArgumentsLengthState)   \
  V(ObjectState)            \
  V(ObjectId)               \
  V(TypedObjectState)       \
  V(Call)                   \
  V(Parameter)              \
  V(OsrValue)               \
  V(LoopExit)               \
  V(LoopExitValue)          \
  V(LoopExitEffect)         \
  V(Projection)             \
  V(Retain)                 \
  V(MapGuard)               \
  V(TypeGuard)              \
  V(EnterMachineGraph)      \
  V(ExitMachineGraph)

#define COMMON_OP_LIST(V) \
  CONSTANT_OP_LIST(V)     \
  INNER_OP_LIST(V)        \
  V(Unreachable)          \
  V(DeadValue)            \
  V(Dead)                 \
  V(Plug)                 \
  V(SLVerifierHint)       \
  V(StaticAssert)

// Opcodes for JavaScript operators.
// Arguments are JSName (the name with a 'JS' prefix), and Name.
#define JS_COMPARE_BINOP_LIST(V)        \
  V(JSEqual, Equal)                     \
  V(JSStrictEqual, StrictEqual)         \
  V(JSLessThan, LessThan)               \
  V(JSGreaterThan, GreaterThan)         \
  V(JSLessThanOrEqual, LessThanOrEqual) \
  V(JSGreaterThanOrEqual, GreaterThanOrEqual)

#define JS_BITWISE_BINOP_LIST(V) \
  V(JSBitwiseOr, BitwiseOr)      \
  V(JSBitwiseXor, BitwiseXor)    \
  V(JSBitwiseAnd, BitwiseAnd)    \
  V(JSShiftLeft, ShiftLeft)      \
  V(JSShiftRight, ShiftRight)    \
  V(JSShiftRightLogical, ShiftRightLogical)

#define JS_ARITH_BINOP_LIST(V) \
  V(JSAdd, Add)                \
  V(JSSubtract, Subtract)      \
  V(JSMultiply, Multiply)      \
  V(JSDivide, Divide)          \
  V(JSModulus, Modulus)        \
  V(JSExponentiate, Exponentiate)

#define JS_SIMPLE_BINOP_LIST(V) \
  JS_COMPARE_BINOP_LIST(V)      \
  JS_BITWISE_BINOP_LIST(V)      \
  JS_ARITH_BINOP_LIST(V)        \
  V(JSHasInPrototypeChain)      \
  V(JSInstanceOf)               \
  V(JSOrdinaryHasInstance)

#define JS_CONVERSION_UNOP_LIST(V) \
  V(JSToLength)                    \
  V(JSToName)                      \
  V(JSToNumber)                    \
  V(JSToNumberConvertBigInt)       \
  V(JSToBigInt)                    \
  V(JSToBigIntConvertNumber)       \
  V(JSToNumeric)                   \
  V(JSToObject)                    \
  V(JSToString)                    \
  V(JSParseInt)

#define JS_BITWISE_UNOP_LIST(V) \
  V(JSBitwiseNot, BitwiseNot)   \
  V(JSNegate, Negate)

#define JS_ARITH_UNOP_LIST(V) \
  V(JSDecrement, Decrement)   \
  V(JSIncrement, Increment)

#define JS_SIMPLE_UNOP_LIST(V) \
  JS_ARITH_UNOP_LIST(V)        \
  JS_BITWISE_UNOP_LIST(V)      \
  JS_CONVERSION_UNOP_LIST(V)

#define JS_CREATE_OP_LIST(V)     \
  V(JSCloneObject)               \
  V(JSCreate)                    \
  V(JSCreateArguments)           \
  V(JSCreateArray)               \
  V(JSCreateArrayFromIterable)   \
  V(JSCreateArrayIterator)       \
  V(JSCreateAsyncFunctionObject) \
  V(JSCreateBoundFunction)       \
  V(JSCreateClosure)             \
  V(JSCreateCollectionIterator)  \
  V(JSCreateEmptyLiteralArray)   \
  V(JSCreateEmptyLiteralObject)  \
  V(JSCreateGeneratorObject)     \
  V(JSCreateIterResultObject)    \
  V(JSCreateKeyValueArray)       \
  V(JSCreateLiteralArray)        \
  V(JSCreateLiteralObject)       \
  V(JSCreateLiteralRegExp)       \
  V(JSCreateObject)              \
  V(JSCreateStringWrapper)       \
  V(JSCreatePromise)             \
  V(JSCreateStringIterator)      \
  V(JSCreateTypedArray)          \
  V(JSGetTemplateObject)

#define JS_OBJECT_OP_LIST(V)           \
  JS_CREATE_OP_LIST(V)                 \
  V(JSLoadProperty)                    \
  V(JSLoadNamed)                       \
  V(JSLoadNamedFromSuper)              \
  V(JSLoadGlobal)                      \
  V(JSSetKeyedProperty)                \
  V(JSDefineKeyedOwnProperty)          \
  V(JSSetNamedProperty)                \
  V(JSDefineNamedOwnProperty)          \
  V(JSStoreGlobal)                     \
  V(JSDefineKeyedOwnPropertyInLiteral) \
  V(JSStoreInArrayLiteral)             \
  V(JSDeleteProperty)                  \
  V(JSHasProperty)                     \
  V(JSGetSuperConstructor)             \
  V(JSFindNonDefaultConstructorOrConstruct)

#define JS_CONTEXT_OP_LIST(V) \
  V(JSHasContextExtension)    \
  V(JSLoadContext)            \
  V(JSLoadScriptContext)      \
  V(JSStoreContext)           \
  V(JSStoreScriptContext)     \
  V(JSCreateFunctionContext)  \
  V(JSCreateCatchContext)     \
  V(JSCreateWithContext)      \
  V(JSCreateBlockContext)

#define JS_CALL_OP_LIST(V) \
  V(JSCall)                \
  V(JSCallForwardVarargs)  \
  V(JSCallWithArrayLike)   \
  V(JSCallWithSpread)      \
  IF_WASM(V, JSWasmCall)

#define JS_CONSTRUCT_OP_LIST(V) \
  V(JSConstructForwardVarargs)  \
  V(JSConstructForwardAllArgs)  \
  V(JSConstruct)                \
  V(JSConstructWithArrayLike)   \
  V(JSConstructWithSpread)

#define JS_OTHER_OP_LIST(V)            \
  JS_CALL_OP_LIST(V)                   \
  JS_CONSTRUCT_OP_LIST(V)              \
  V(JSAsyncFunctionEnter)              \
  V(JSAsyncFunctionReject)             \
  V(JSAsyncFunctionResolve)            \
  V(JSCallRuntime)                     \
  V(JSForInEnumerate)                  \
  V(JSForInNext)                       \
  V(JSForInPrepare)                    \
  V(JSGetIterator)                     \
  V(JSLoadMessage)                     \
  V(JSStoreMessage)                    \
  V(JSLoadModule)                      \
  V(JSStoreModule)                     \
  V(JSGetImportMeta)                   \
  V(JSGeneratorStore)                  \
  V(JSGeneratorRestoreContinuation)    \
  V(JSGeneratorRestoreContext)         \
  V(JSGeneratorRestoreRegister)        \
  V(JSGeneratorRestoreInputOrDebugPos) \
  V(JSFulfillPromise)                  \
  V(JSPerformPromiseThen)              \
  V(JSPromiseResolve)                  \
  V(JSRejectPromise)                   \
  V(JSResolvePromise)                  \
  V(JSStackCheck)                      \
  V(JSObjectIsArray)                   \
  V(JSRegExpTest)                      \
  V(JSDebugger)

#define JS_OP_LIST(V)     \
  JS_SIMPLE_BINOP_LIST(V) \
  JS_SIMPLE_UNOP_LIST(V)  \
  JS_OBJECT_OP_LIST(V)    \
  JS_CONTEXT_OP_LIST(V)   \
  JS_OTHER_OP_LIST(V)

// Opcodes for VirtuaMachine-level operators.
#define SIMPLIFIED_CHANGE_OP_LIST(V) \
  V(ChangeTaggedSignedToInt32)       \
  V(ChangeTaggedSignedToInt64)       \
  V(ChangeTaggedToInt32)             \
  V(ChangeTaggedToInt64)             \
  V(ChangeTaggedToUint32)            \
  V(ChangeTaggedToFloat64)           \
  V(ChangeTaggedToTaggedSigned)      \
  V(ChangeInt31ToTaggedSigned)       \
  V(ChangeInt32ToTagged)             \
  V(ChangeInt64ToTagged)             \
  V(ChangeUint32ToTagged)            \
  V(ChangeUint64ToTagged)            \
  V(ChangeFloat64ToTagged)           \
  V(ChangeFloat64ToTaggedPointer)    \
  V(ChangeTaggedToBit)               \
  V(ChangeBitToTagged)               \
  V(ChangeInt64ToBigInt)             \
  V(ChangeUint64ToBigInt)            \
  V(TruncateBigIntToWord64)          \
  V(TruncateTaggedToWord32)          \
  V(TruncateTaggedToFloat64)         \
  V(TruncateTaggedToBit)             \
  V(TruncateTaggedPointerToBit)

#define SIMPLIFIED_CHECKED_OP_LIST(V) \
  V(CheckedInt32Add)                  \
  V(CheckedInt32Sub)                  \
  V(CheckedInt32Div)                  \
  V(CheckedInt32Mod)                  \
  V(CheckedUint32Div)                 \
  V(CheckedUint32Mod)                 \
  V(CheckedInt32Mul)                  \
  V(CheckedInt64Add)                  \
  V(CheckedInt64Sub)                  \
  V(CheckedInt64Mul)                  \
  V(CheckedInt64Div)                  \
  V(CheckedInt64Mod)                  \
  V(CheckedInt32ToTaggedSigned)       \
  V(CheckedInt64ToInt32)              \
  V(CheckedInt64ToTaggedSigned)       \
  V(CheckedUint32Bounds)              \
  V(CheckedUint32ToInt32)             \
  V(CheckedUint32ToTaggedSigned)      \
  V(CheckedUint64Bounds)              \
  V(CheckedUint64ToInt32)             \
  V(CheckedUint64ToInt64)             \
  V(CheckedUint64ToTaggedSigned)      \
  V(CheckedFloat64ToInt32)            \
  V(CheckedFloat64ToInt64)            \
  V(CheckedTaggedSignedToInt32)       \
  V(CheckedTaggedToInt32)             \
  V(CheckedTaggedToArrayIndex)        \
  V(CheckedTruncateTaggedToWord32)    \
  V(CheckedTaggedToFloat64)           \
  V(CheckedTaggedToInt64)             \
  V(CheckedTaggedToTaggedSigned)      \
  V(CheckedTaggedToTaggedPointer)

#define SIMPLIFIED_COMPARE_BINOP_LIST(V) \
  V(NumberEqual)                         \
  V(NumberLessThan)                      \
  V(NumberLessThanOrEqual)               \
  V(SpeculativeNumberEqual)              \
  V(SpeculativeNumberLessThan)           \
  V(SpeculativeNumberLessThanOrEqual)    \
  V(ReferenceEqual)                      \
  V(SameValue)                           \
  V(SameValueNumbersOnly)                \
  V(NumberSameValue)                     \
  V(StringEqual)                         \
  V(StringLessThan)                      \
  V(StringLessThanOrEqual)               \
  V(BigIntEqual)                         \
  V(BigIntLessThan)                      \
  V(BigIntLessThanOrEqual)               \
  V(SpeculativeBigIntEqual)              \
  V(SpeculativeBigIntLessThan)           \
  V(SpeculativeBigIntLessThanOrEqual)

#define SIMPLIFIED_NUMBER_BINOP_LIST(V) \
  V(NumberAdd)                          \
  V(NumberSubtract)                     \
  V(NumberMultiply)                     \
  V(NumberDivide)                       \
  V(NumberModulus)                      \
  V(NumberBitwiseOr)                    \
  V(NumberBitwiseXor)                   \
  V(NumberBitwiseAnd)                   \
  V(NumberShiftLeft)                    \
  V(NumberShiftRight)                   \
  V(NumberShiftRightLogical)            \
  V(NumberAtan2)                        \
  V(NumberImul)                         \
  V(NumberMax)                          \
  V(NumberMin)                          \
  V(NumberPow)

#define SIMPLIFIED_BIGINT_BINOP_LIST(V) \
  V(BigIntAdd)                          \
  V(BigIntSubtract)                     \
  V(BigIntMultiply)                     \
  V(BigIntDivide)                       \
  V(BigIntModulus)                      \
  V(BigIntBitwiseAnd)                   \
  V(BigIntBitwiseOr)                    \
  V(BigIntBitwiseXor)                   \
  V(BigIntShiftLeft)                    \
  V(BigIntShiftRight)

#define SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(V) \
  V(SpeculativeNumberAdd)                           \
  V(SpeculativeNumberSubtract)                      \
  V(SpeculativeNumberMultiply)                      \
  V(SpeculativeNumberPow)                           \
  V(SpeculativeNumberDivide)                        \
  V(SpeculativeNumberModulus)                       \
  V(SpeculativeNumberBitwiseAnd)                    \
  V(SpeculativeNumberBitwiseOr)                     \
  V(SpeculativeNumberBitwiseXor)                    \
  V(SpeculativeNumberShiftLeft)                     \
  V(SpeculativeNumberShiftRight)                    \
  V(SpeculativeNumberShiftRightLogical)             \
  V(SpeculativeSafeIntegerAdd)                      \
  V(SpeculativeSafeIntegerSubtract)

#define SIMPLIFIED_NUMBER_UNOP_LIST(V) \
  V(NumberAbs)                         \
  V(NumberAcos)                        \
  V(NumberAcosh)                       \
  V(NumberAsin)                        \
  V(NumberAsinh)                       \
  V(NumberAtan)                        \
  V(NumberAtanh)                       \
  V(NumberCbrt)                        \
  V(NumberCeil)                        \
  V(NumberClz32)                       \
  V(NumberCos)                         \
  V(NumberCosh)                        \
  V(NumberExp)                         \
  V(NumberExpm1)                       \
  V(NumberFloor)                       \
  V(NumberFround)                      \
  V(NumberLog)                         \
  V(NumberLog1p)                       \
  V(NumberLog2)                        \
  V(NumberLog10)                       \
  V(NumberRound)                       \
  V(NumberSign)                        \
  V(NumberSin)                         \
  V(NumberSinh)                        \
  V(NumberSqrt)                        \
  V(NumberTan)                         \
  V(NumberTanh)                        \
  V(NumberTrunc)                       \
  V(NumberToBoolean)                   \
  V(NumberToInt32)                     \
  V(NumberToString)                    \
  V(NumberToUint32)                    \
  V(NumberToUint8Clamped)              \
  V(Integral32OrMinusZeroToBigInt)     \
  V(NumberSilenceNaN)

#define SIMPLIFIED_BIGINT_UNOP_LIST(V) \
  V(BigIntNegate)                      \
  V(CheckBigInt)                       \
  V(CheckedBigIntToBigInt64)

#define SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(V) V(SpeculativeToNumber)

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
#define SIMPLIFIED_CPED_OP_LIST(V)        \
  V(GetContinuationPreservedEmbedderData) \
  V(SetContinuationPreservedEmbedderData)
#else
#define SIMPLIFIED_CPED_OP_LIST(V)
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

#define SIMPLIFIED_OTHER_OP_LIST(V)     \
  V(Allocate)                           \
  V(AllocateRaw)                        \
  V(ArgumentsLength)                    \
  V(AssertType)                         \
  V(BooleanNot)                         \
  V(ChangeFloat64HoleToTagged)          \
  V(CheckBounds)                        \
  V(CheckClosure)                       \
  V(CheckEqualsInternalizedString)      \
  V(CheckEqualsSymbol)                  \
  V(CheckFloat64Hole)                   \
  V(CheckHeapObject)                    \
  V(CheckIf)                            \
  V(CheckInternalizedString)            \
  V(CheckMaps)                          \
  V(CheckNotTaggedHole)                 \
  V(CheckNumber)                        \
  V(CheckReceiver)                      \
  V(CheckReceiverOrNullOrUndefined)     \
  V(CheckSmi)                           \
  V(CheckString)                        \
  V(CheckStringOrStringWrapper)         \
  V(CheckSymbol)                        \
  V(CheckTurboshaftTypeOf)              \
  V(CompareMaps)                        \
  V(ConvertReceiver)                    \
  V(ConvertTaggedHoleToUndefined)       \
  V(DateNow)                            \
  V(DoubleArrayMax)                     \
  V(DoubleArrayMin)                     \
  V(EnsureWritableFastElements)         \
  V(FastApiCall)                        \
  V(FindOrderedHashMapEntry)            \
  V(FindOrderedHashMapEntryForInt32Key) \
  V(FindOrderedHashSetEntry)            \
  V(InitializeImmutableInObject)        \
  V(LoadDataViewElement)                \
  V(LoadElement)                        \
  V(LoadField)                          \
  V(LoadFieldByIndex)                   \
  V(LoadFromObject)                     \
  V(LoadImmutableFromObject)            \
  V(LoadMessage)                        \
  V(LoadStackArgument)                  \
  V(LoadTypedElement)                   \
  V(MaybeGrowFastElements)              \
  V(NewArgumentsElements)               \
  V(NewConsString)                      \
  V(NewDoubleElements)                  \
  V(NewSmiOrObjectElements)             \
  V(NumberIsFinite)                     \
  V(NumberIsFloat64Hole)                \
  V(NumberIsInteger)                    \
  V(NumberIsMinusZero)                  \
  V(NumberIsNaN)                        \
  V(NumberIsSafeInteger)                \
  V(ObjectIsArrayBufferView)            \
  V(ObjectIsBigInt)                     \
  V(ObjectIsCallable)                   \
  V(ObjectIsConstructor)                \
  V(ObjectIsDetectableCallable)         \
  V(ObjectIsFiniteNumber)               \
  V(ObjectIsInteger)                    \
  V(ObjectIsMinusZero)                  \
  V(ObjectIsNaN)                        \
  V(ObjectIsNonCallable)                \
  V(ObjectIsNumber)                     \
  V(ObjectIsReceiver)                   \
  V(ObjectIsSafeInteger)                \
  V(ObjectIsSmi)                        \
  V(ObjectIsString)                     \
  V(ObjectIsSymbol)                     \
  V(ObjectIsUndetectable)               \
  V(PlainPrimitiveToFloat64)            \
  V(PlainPrimitiveToNumber)             \
  V(PlainPrimitiveToWord32)             \
  V(RestLength)                         \
  V(RuntimeAbort)                       \
  V(StoreDataViewElement)               \
  V(StoreElement)                       \
  V(StoreField)                         \
  V(StoreMessage)                       \
  V(StoreSignedSmallElement)            \
  V(StoreToObject)                      \
  V(StoreTypedElement)                  \
  V(StringCharCodeAt)                   \
  V(StringCodePointAt)                  \
  V(StringConcat)                       \
  V(StringFromCodePointAt)              \
  V(StringFromSingleCharCode)           \
  V(StringFromSingleCodePoint)          \
  V(StringIndexOf)                      \
  V(StringLength)                       \
  V(StringWrapperLength)                \
  V(StringSubstring)                    \
  V(StringToLowerCaseIntl)              \
  V(StringToNumber)                     \
  V(StringToUpperCaseIntl)              \
  V(ToBoolean)                          \
  V(TransitionAndStoreElement)          \
  V(TransitionAndStoreNonNumberElement) \
  V(TransitionAndStoreNumberElement)    \
  V(TransitionElementsKind)             \
  V(TypeOf)                             \
  V(Unsigned32Divide)                   \
  V(VerifyType)                         \
  SIMPLIFIED_CPED_OP_LIST(V)

#define SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(V) \
  V(SpeculativeBigIntAdd)                           \
  V(SpeculativeBigIntSubtract)                      \
  V(SpeculativeBigIntMultiply)                      \
  V(SpeculativeBigIntDivide)                        \
  V(SpeculativeBigIntModulus)                       \
  V(SpeculativeBigIntBitwiseAnd)                    \
  V(SpeculativeBigIntBitwiseOr)                     \
  V(SpeculativeBigIntBitwiseXor)                    \
  V(SpeculativeBigIntShiftLeft)                     \
  V(SpeculativeBigIntShiftRight)

#define SIMPLIFIED_SPECULATIVE_BIGINT_UNOP_LIST(V) \
  V(SpeculativeBigIntAsIntN)                       \
  V(SpeculativeBigIntAsUintN)                      \
  V(SpeculativeBigIntNegate)                       \
  V(SpeculativeToBigInt)

#define SIMPLIFIED_WASM_OP_LIST(V) \
  V(AssertNotNull)                 \
  V(IsNull)                        \
  V(IsNotNull)                     \
  V(Null)                          \
  V(RttCanon)                      \
  V(WasmTypeCast)                  \
  V(WasmTypeCastAbstract)          \
  V(WasmTypeCheck)                 \
  V(WasmTypeCheckAbstract)         \
  V(WasmAnyConvertExtern)          \
  V(WasmExternConvertAny)          \
  V(WasmStructGet)                 \
  V(WasmStructSet)                 \
  V(WasmArrayGet)                  \
  V(WasmArraySet)                  \
  V(WasmArrayLength)               \
  V(WasmArrayInitializeLength)     \
  V(StringAsWtf16)                 \
  V(StringPrepareForGetCodeunit)

#define SIMPLIFIED_OP_LIST(V)                 \
  SIMPLIFIED_CHANGE_OP_LIST(V)                \
  SIMPLIFIED_CHECKED_OP_LIST(V)               \
  SIMPLIFIED_COMPARE_BINOP_LIST(V)            \
  SIMPLIFIED_NUMBER_BINOP_LIST(V)             \
  SIMPLIFIED_BIGINT_BINOP_LIST(V)             \
  SIMPLIFIED_SPECULATIVE_NUMBER_BINOP_LIST(V) \
  SIMPLIFIED_NUMBER_UNOP_LIST(V)              \
  SIMPLIFIED_BIGINT_UNOP_LIST(V)              \
  SIMPLIFIED_SPECULATIVE_NUMBER_UNOP_LIST(V)  \
  SIMPLIFIED_SPECULATIVE_BIGINT_UNOP_LIST(V)  \
  SIMPLIFIED_SPECULATIVE_BIGINT_BINOP_LIST(V) \
  IF_WASM(SIMPLIFIED_WASM_OP_LIST, V)         \
  SIMPLIFIED_OTHER_OP_LIST(V)

// Opcodes for Machine-level operators.
#define MACHINE_UNOP_32_LIST(V) \
  V(Word32Clz)                  \
  V(Word32Ctz)                  \
  V(Int32AbsWithOverflow)       \
  V(Word32ReverseBits)          \
  V(Word32ReverseBytes)

#define MACHINE_COMPARE_BINOP_LIST(V) \
  V(Word32Equal)                      \
  V(Word64Equal)                      \
  V(Int32LessThan)                    \
  V(Int32LessThanOrEqual)             \
  V(Uint32LessThan)                   \
  V(Uint32LessThanOrEqual)            \
  V(Int64LessThan)                    \
  V(Int64LessThanOrEqual)             \
  V(Uint64LessThan)                   \
  V(Uint64LessThanOrEqual)            \
  V(Float32Equal)                     \
  V(Float32LessThan)                  \
  V(Float32LessThanOrEqual)           \
  V(Float64Equal)                     \
  V(Float64LessThan)                  \
  V(Float64LessThanOrEqual)

#define MACHINE_BINOP_32_LIST(V) \
  V(Word32And)                   \
  V(Word32Or)                    \
  V(Word32Xor)                   \
  V(Word32Shl)                   \
  V(Word32Shr)                   \
  V(Word32Sar)                   \
  V(Word32Rol)                   \
  V(Word32Ror)                   \
  V(Int32Add)                    \
  V(Int32AddWithOverflow)        \
  V(Int32Sub)                    \
  V(Int32SubWithOverflow)        \
  V(Int32Mul)                    \
  V(Int32MulWithOverflow)        \
  V(Int32MulHigh)                \
  V(Int32Div)                    \
  V(Int32Mod)                    \
  V(Uint32Div)                   \
  V(Uint32Mod)                   \
  V(Uint32MulHigh)

#define MACHINE_BINOP_64_LIST(V) \
  V(Word64And)                   \
  V(Word64Or)                    \
  V(Word64Xor)                   \
  V(Word64Shl)                   \
  V(Word64Shr)                   \
  V(Word64Sar)                   \
  V(Word64Rol)                   \
  V(Word64Ror)                   \
  V(Word64RolLowerable)          \
  V(Word64RorLowerable)          \
  V(Int64Add)                    \
  V(Int64AddWithOverflow)        \
  V(Int64Sub)                    \
  V(Int64SubWithOverflow)        \
  V(Int64Mul)                    \
  V(Int64MulHigh)                \
  V(Int64MulWithOverflow)        \
  V(Int64Div)                    \
  V(Int64Mod)                    \
  V(Uint64Div)                   \
  V(Uint64Mod)                   \
  V(Uint64MulHigh)

#define MACHINE_FLOAT32_UNOP_LIST(V) \
  V(Float32Abs)                      \
  V(Float32Neg)                      \
  V(Float32RoundDown)                \
  V(Float32RoundTiesEven)            \
  V(Float32RoundTruncate)            \
  V(Float32RoundUp)                  \
  V(Float32Sqrt)

#define MACHINE_FLOAT32_BINOP_LIST(V) \
  V(Float32Add)                       \
  V(Float32Sub)                       \
  V(Float32Mul)                       \
  V(Float32Div)                       \
  V(Float32Max)                       \
  V(Float32Min)

#define MACHINE_FLOAT64_UNOP_LIST(V) \
  V(Float64Abs)                      \
  V(Float64Acos)                     \
  V(Float64Acosh)                    \
  V(Float64Asin)                     \
  V(Float64Asinh)                    \
  V(Float64Atan)                     \
  V(Float64Atanh)                    \
  V(Float64Cbrt)                     \
  V(Float64Cos)                      \
  V(Float64Cosh)                     \
  V(Float64Exp)                      \
  V(Float64Expm1)                    \
  V(Float64Log)                      \
  V(Float64Log1p)                    \
  V(Float64Log10)                    \
  V(Float64Log2)                     \
  V(Float64Neg)                      \
  V(Float64RoundDown)                \
  V(Float64RoundTiesAway)            \
  V(Float64RoundTiesEven)            \
  V(Float64RoundTruncate)            \
  V(Float64RoundUp)                  \
  V(Float64Sin)                      \
  V(Float64Sinh)                     \
  V(Float64Sqrt)                     \
  V(Float64Tan)                      \
  V(Float64Tanh)

#define MACHINE_FLOAT64_BINOP_LIST(V) \
  V(Float64Atan2)                     \
  V(Float64Max)                       \
  V(Float64Min)                       \
  V(Float64Add)                       \
  V(Float64Sub)                       \
  V(Float64Mul)                       \
  V(Float64Div)                       \
  V(Float64Mod)                       \
  V(Float64Pow)

#define MACHINE_ATOMIC_OP_LIST(V)    \
  V(Word32AtomicLoad)                \
  V(Word32AtomicStore)               \
  V(Word32AtomicExchange)            \
  V(Word32AtomicCompareExchange)     \
  V(Word32AtomicAdd)                 \
  V(Word32AtomicSub)                 \
  V(Word32AtomicAnd)                 \
  V(Word32AtomicOr)                  \
  V(Word32AtomicXor)                 \
  V(Word32AtomicPairLoad)            \
  V(Word32AtomicPairStore)           \
  V(Word32AtomicPairAdd)             \
  V(Word32AtomicPairSub)             \
  V(Word32AtomicPairAnd)             \
  V(Word32AtomicPairOr)              \
  V(Word32AtomicPairXor)             \
  V(Word32AtomicPairExchange)        \
  V(Word32AtomicPairCompareExchange) \
  V(Word64AtomicLoad)                \
  V(Word64AtomicStore)               \
  V(Word64AtomicAdd)                 \
  V(Word64AtomicSub)                 \
  V(Word64AtomicAnd)                 \
  V(Word64AtomicOr)                  \
  V(Word64AtomicXor)                 \
  V(Word64AtomicExchange)            \
  V(Word64AtomicCompareExchange)

#define MACHINE_OP_LIST(V)               \
  MACHINE_UNOP_32_LIST(V)                \
  MACHINE_BINOP_32_LIST(V)               \
  MACHINE_BINOP_64_LIST(V)               \
  MACHINE_COMPARE_BINOP_LIST(V)          \
  MACHINE_FLOAT32_BINOP_LIST(V)          \
  MACHINE_FLOAT32_UNOP_LIST(V)           \
  MACHINE_FLOAT64_BINOP_LIST(V)          \
  MACHINE_FLOAT64_UNOP_LIST(V)           \
  MACHINE_ATOMIC_OP_LIST(V)              \
  V(AbortCSADcheck)                      \
  V(DebugBreak)                          \
  V(Comment)                             \
  V(Load)                                \
  V(LoadImmutable)                       \
  V(Store)                               \
  V(StorePair)                           \
  V(StoreIndirectPointer)                \
  V(StackSlot)                           \
  V(Word32Popcnt)                        \
  V(Word64Popcnt)                        \
  V(Word64Clz)                           \
  V(Word64Ctz)                           \
  V(Word64ClzLowerable)                  \
  V(Word64CtzLowerable)                  \
  V(Word64ReverseBits)                   \
  V(Word64ReverseBytes)                  \
  V(Simd128ReverseBytes)                 \
  V(Int64AbsWithOverflow)                \
  V(BitcastTaggedToWord)                 \
  V(BitcastTaggedToWordForTagAndSmiBits) \
  V(BitcastWordToTagged)                 \
  V(BitcastWordToTaggedSigned)           \
  V(TruncateFloat64ToWord32)             \
  V(ChangeFloat32ToFloat64)              \
  V(ChangeFloat64ToInt32)                \
  V(ChangeFloat64ToInt64)                \
  V(ChangeFloat64ToUint32)               \
  V(ChangeFloat64ToUint64)               \
  V(Float64SilenceNaN)                   \
  V(TruncateFloat64ToInt64)              \
  V(TruncateFloat64ToUint32)             \
  V(TruncateFloat32ToInt32)              \
  V(TruncateFloat32ToUint32)             \
  V(TryTruncateFloat32ToInt64)           \
  V(TryTruncateFloat64ToInt64)           \
  V(TryTruncateFloat32ToUint64)          \
  V(TryTruncateFloat64ToUint64)          \
  V(TryTruncateFloat64ToInt32)           \
  V(TryTruncateFloat64ToUint32)          \
  V(ChangeInt32ToFloat64)                \
  V(BitcastWord32ToWord64)               \
  V(ChangeInt32ToInt64)                  \
  V(ChangeInt64ToFloat64)                \
  V(ChangeUint32ToFloat64)               \
  V(ChangeUint32ToUint64)                \
  V(TruncateFloat64ToFloat32)            \
  V(TruncateFloat64ToFloat16RawBits)     \
  V(TruncateInt64ToInt32)                \
  V(RoundFloat64ToInt32)                 \
  V(RoundInt32ToFloat32)                 \
  V(RoundInt64ToFloat32)                 \
  V(RoundInt64ToFloat64)                 \
  V(RoundUint32ToFloat32)                \
  V(RoundUint64ToFloat32)                \
  V(RoundUint64ToFloat64)                \
  V(BitcastFloat32ToInt32)               \
  V(BitcastFloat64ToInt64)               \
  V(BitcastInt32ToFloat32)               \
  V(BitcastInt64ToFloat64)               \
  V(Float64ExtractLowWord32)             \
  V(Float64ExtractHighWord32)            \
  V(Float64InsertLowWord32)              \
  V(Float64InsertHighWord32)             \
  V(Word32Select)                        \
  V(Word64Select)                        \
  V(Float32Select)                       \
  V(Float64Select)                       \
  V(LoadStackCheckOffset)                \
  V(LoadFramePointer)                    \
  IF_WASM(V, LoadStackPointer)           \
  IF_WASM(V, SetStackPointer)            \
  V(LoadParentFramePointer)              \
  V(LoadRootRegister)                    \
  V(UnalignedLoad)                       \
  V(UnalignedStore)                      \
  V(Int32PairAdd)                        \
  V(Int32PairSub)                        \
  V(Int32PairMul)                        \
  V(Word32PairShl)                       \
  V(Word32PairShr)                       \
  V(Word32PairSar)                       \
  V(ProtectedLoad)                       \
  V(ProtectedStore)                      \
  V(LoadTrapOnNull)                      \
  V(StoreTrapOnNull)                     \
  V(MemoryBarrier)                       \
  V(SignExtendWord8ToInt32)              \
  V(SignExtendWord16ToInt32)             \
  V(SignExtendWord8ToInt64)              \
  V(SignExtendWord16ToInt64)             \
  V(SignExtendWord32ToInt64)             \
  V(StackPointerGreaterThan)             \
  V(TraceInstruction)

#define MACHINE_SIMD128_OP_LIST(V)        \
  IF_WASM(V, F64x2Splat)                  \
  IF_WASM(V, F64x2ExtractLane)            \
  IF_WASM(V, F64x2ReplaceLane)            \
  IF_WASM(V, F64x2Abs)                    \
  IF_WASM(V, F64x2Neg)                    \
  IF_WASM(V, F64x2Sqrt)                   \
  IF_WASM(V, F64x2Add)                    \
  IF_WASM(V, F64x2Sub)                    \
  IF_WASM(V, F64x2Mul)                    \
  IF_WASM(V, F64x2Div)                    \
  IF_WASM(V, F64x2Min)                    \
  IF_WASM(V, F64x2Max)                    \
  IF_WASM(V, F64x2Eq)                     \
  IF_WASM(V, F64x2Ne)                     \
  IF_WASM(V, F64x2Lt)                     \
  IF_WASM(V, F64x2Le)                     \
  IF_WASM(V, F64x2Qfma)                   \
  IF_WASM(V, F64x2Qfms)           
"""


```