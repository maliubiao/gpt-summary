Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Scan and Obvious Clues:**

* **Filename:** `runtime.h` in the `v8/src/runtime` directory. This immediately suggests it defines runtime functionalities for V8. The `.h` extension confirms it's a C++ header file, primarily for declarations.
* **Copyright and License:**  Standard boilerplate, indicating V8 project ownership and the BSD license. Good to note but not central to functional analysis.
* **Includes:**  `<memory>`, `v8-maybe.h`, `globals.h`, etc. These point to dependencies on other V8 internal components and standard C++ libraries. This reinforces that we're looking at core V8 functionality.
* **Namespace:** `namespace v8 { namespace internal { ... } }`. This confirms we're dealing with internal V8 implementation details, not the public API.
* **Comments about Intrinsics:**  The extensive comment block explaining how intrinsics work ( `%#name`, `%_#name`, `Runtime::k##name`, `Runtime_##name`) is crucial. This is the core concept the file revolves around.

**2. Understanding Intrinsics:**

The comments explain that intrinsics are functions exposed to JavaScript. There are two main forms:

* **`%#name` (Runtime Call):**  Always a direct call to the C++ implementation.
* **`%_#name` (Potentially Inlined):** Can be either a runtime call or inlined by the compiler for optimization.

This distinction is important for understanding performance characteristics.

**3. Analyzing the Macros (`FOR_EACH_INTRINSIC_*`):**

These macros are the heart of the file. They define lists of intrinsics categorized by functionality (array, atomics, bigint, classes, etc.). The structure `F(name, number of arguments, number of return values)` is consistent.

* **Purpose of Macros:** These macros likely serve to generate code automatically. Instead of manually writing declarations or definitions for each intrinsic in multiple places, a single entry in the macro list can be used to create the necessary components (the `Runtime::k##name` ID, the `Runtime_##name` implementation, etc.). This reduces redundancy and potential errors.

**4. Categorizing the Intrinsics:**

As I go through the `FOR_EACH_INTRINSIC_*` macros, I start grouping them by their names. This reveals the different areas of JavaScript functionality that these intrinsics support:

* **Arrays:** `ArrayIncludes_Slow`, `ArrayIndexOf`, `IsArray`, `NewArray`, etc. Clearly related to JavaScript Array operations.
* **Atomics:** `AtomicsLoad64`, `AtomicsStore64`, `AtomicsAdd`, etc. Related to concurrent programming features in JavaScript.
* **BigInt:** `BigIntCompareToNumber`, `BigIntToNumber`, `ToBigInt`, etc. Operations on the BigInt data type.
* **Classes:** `DefineClass`, `LoadFromSuper`, `ThrowConstructorNonCallableError`, etc. Support for JavaScript class syntax and inheritance.
* **Collections (Maps, Sets):** `MapGrow`, `SetGrow`, `WeakCollectionDelete`, etc. Operations on built-in collection types.
* **Compiler:** `CompileOptimizedOSR`, `CompileLazy`, `InstallBaselineCode`, etc. Internals related to V8's compilation pipeline and optimization strategies.
* **Date:** `DateCurrentTime`. Getting the current time.
* **Debug:** `ClearStepping`, `CollectGarbage`, `DebugBreakAtEntry`, etc. Functions for debugging and inspecting the V8 runtime.
* **For...in:** `ForInEnumerate`, `ForInHasProperty`. Support for the `for...in` loop.
* **Function:** `Call`, `FunctionGetScriptSource`, etc. Operations related to JavaScript functions.
* **Generator/Async Functions:** `AsyncFunctionAwait`, `CreateJSGeneratorObject`, `GeneratorClose`, etc. Implementation of asynchronous JavaScript features.
* **Intl:**  (If `V8_INTL_SUPPORT` is defined) Functions related to internationalization (formatting lists, converting case based on locale).
* **Internal (Throwing):** `Throw`, `ThrowTypeError`, etc. Functions for raising exceptions within the V8 runtime.
* **Internal (General):** `AllocateByteArray`, `CreateListFromArrayLike`, `StackGuard`, `Typeof`, etc. Lower-level runtime functionalities.
* **Literals:** `CreateArrayLiteral`, `CreateObjectLiteral`, `CreateRegExpLiteral`. Creating literal values in JavaScript.
* **Module:** `DynamicImportCall`, `GetImportMetaObject`, `GetModuleNamespace`. Support for JavaScript modules.
* **Numbers:** `ArrayBufferMaxByteLength`, `IsSmi`, `NumberToStringSlow`, `StringToNumber`. Operations on numbers.
* **Object:** `AddDictionaryProperty`, `CreateDataProperty`, `DeleteProperty`, `GetProperty`, `SetProperty`, etc. Fundamental object manipulation functions.
* **Operators:** `Add`, `Equal`, `GreaterThan`, etc. Implementation of JavaScript operators.
* **Promise:** `EnqueueMicrotask`, `RejectPromise`, `ResolvePromise`, etc. Implementation of the Promise API.
* **Proxy:** `CheckProxyGetSetTrapResult`, `IsJSProxy`, `SetPropertyWithReceiver`. Support for JavaScript Proxy objects.
* **RegExp:** `RegExpExec`, `RegExpReplaceRT`, `RegExpSplit`, etc. Regular expression functionality.
* **Scopes:** `DeclareEvalFunction`, `LoadLookupSlot`, `NewClosure`, etc. Managing variable scopes and closures.
* **ShadowRealm:** `ShadowRealmWrappedFunctionCreate`, `ShadowRealmImportValue`. Support for the ShadowRealm API.
* **Strings:** `FlattenString`, `StringAdd`, `StringCompare`, `StringSubstring`, etc. String manipulation functions.
* **Symbol:** `CreatePrivateNameSymbol`, `SymbolDescriptiveString`, etc. Support for the Symbol data type.
* **Temporal:** `IsInvalidTemporalCalendarField`. Functions related to the Temporal API (for date/time).
* **Test:**  A wide range of functions for internal testing and debugging V8's behavior.
* **TypedArray:** `ArrayBufferDetach`, `TypedArrayCopyElements`, `TypedArraySet`, etc. Operations on TypedArrays.
* **Wasm:** (If `V8_ENABLE_DRUMBRAKE` is defined) WebAssembly related functions.

**5. Answering the Specific Questions:**

Now that I have a good understanding of the file's content, I can address the specific questions:

* **Functionality:** It defines the interface and identifiers for V8's runtime functions (intrinsics) that are called from JavaScript or by the V8 engine itself.
* **`.tq` Extension:** The file ends in `.h`, so it's a C++ header file, *not* a Torque file. Torque files have the `.tq` extension.
* **Relationship to JavaScript:**  Many intrinsics directly correspond to JavaScript features. Examples are provided for array manipulation, object properties, and string operations.
* **Code Logic Reasoning:**  Examples are given to illustrate how an intrinsic like `ArrayIndexOf` might work with sample inputs and outputs.
* **Common Programming Errors:** Examples are provided showing how using an incorrect number of arguments with an intrinsic or attempting to call a non-callable object can lead to errors.
* **Summary:** The file provides a central declaration of V8's runtime capabilities, bridging the gap between JavaScript code and the underlying C++ implementation.

**Self-Correction/Refinement:**

Initially, I might have simply listed the categories of intrinsics. However, to provide a more comprehensive answer, I elaborated on *why* these intrinsics are important (they connect JavaScript to C++) and gave concrete examples. I also made sure to address all parts of the prompt, including the `.tq` extension and the distinction between runtime calls and potentially inlined calls. Finally, adding examples of common errors makes the explanation more practical.
好的，我们来分析一下 `v8/src/runtime/runtime.h` 这个V8源代码文件的功能。

**文件功能归纳:**

`v8/src/runtime/runtime.h` 文件是 V8 JavaScript 引擎的核心组成部分，它定义了 **V8 引擎在运行时可以调用的内置函数（intrinsics）的接口和标识符**。 这些内置函数是用 C++ 实现的，提供了 JavaScript 语言内置对象和操作的底层实现。

更具体地说，这个头文件做了以下几件事：

1. **声明宏定义 (Macros):**  定义了一系列的宏，例如 `FOR_EACH_INTRINSIC_ARRAY`、`FOR_EACH_INTRINSIC_OBJECT` 等，这些宏用于方便地声明和组织不同的内置函数。
2. **列举内置函数 (Intrinsics):**  通过这些宏，文件内部实际上列举了大量的内置函数。每个内置函数都有一个唯一的名称、参数数量和返回值数量。
3. **定义调用约定:**  注释中明确了如何在 JavaScript 中调用这些内置函数（`%#name` 和 `_%#name`）以及它们在 C++ 代码中的命名约定 (`Runtime_##name`) 和常量定义 (`Runtime::k##name`)。
4. **分类组织:**  将内置函数按照功能模块进行分类，例如数组操作、原子操作、BigInt 操作、类操作、集合操作、编译器相关、日期操作、调试、函数操作、生成器、国际化、内部操作、字面量、模块、数字操作、对象操作、运算符、Promise、代理、正则表达式、作用域、字符串操作、Symbol 操作、TypedArray 操作和 WebAssembly 操作等。

**关于文件扩展名和 Torque:**

根据您的描述，如果 `v8/src/runtime/runtime.h` 以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。 然而，当前提供的文件是以 `.h` 结尾的，**所以它是一个 C++ 头文件**，用于声明接口。 Torque 文件通常用于定义 V8 的内置函数，并使用一种特殊的语法进行类型检查和代码生成。  `.h` 文件则更多用于 C++ 的声明。

**与 JavaScript 功能的关系和举例:**

`v8/src/runtime/runtime.h` 中定义的内置函数直接对应着 JavaScript 的各种内置功能。 当 JavaScript 代码执行到需要调用这些功能时，V8 引擎就会调用相应的内置函数。

以下是一些 JavaScript 功能和其可能对应的内置函数的例子：

* **数组操作:**
    ```javascript
    const arr = [1, 2, 3];
    arr.push(4); // 可能对应内置函数：Runtime_ArrayPush
    arr.indexOf(2); // 可能对应内置函数：Runtime_ArrayIndexOf
    Array.isArray(arr); // 可能对应内置函数：Runtime_ArrayIsArray
    ```
    这里 `ArrayIndexOf` 在 `runtime.h` 中被列出：`F(ArrayIndexOf, 3, 1)`。 这意味着它是一个内置函数，接受 3 个参数（要搜索的数组，要查找的元素，起始索引）并返回 1 个值（元素的索引或 -1）。

* **对象操作:**
    ```javascript
    const obj = { a: 1, b: 2 };
    obj.c = 3; // 可能对应内置函数：Runtime_SetProperty
    delete obj.a; // 可能对应内置函数：Runtime_DeleteProperty
    Object.keys(obj); // 可能对应内置函数：Runtime_ObjectKeys
    ```
    `ObjectKeys` 在 `runtime.h` 中被列出：`F(ObjectKeys, 1, 1)`，表示接受一个对象作为参数并返回一个包含其键的数组。

* **字符串操作:**
    ```javascript
    const str = "hello";
    str.substring(1, 4); // 可能对应内置函数：Runtime_StringSubstring
    str.indexOf("l"); //  由于可能有优化的内联版本，这里可能对应 Runtime_StringIndexOf 或者内联代码。
    ```
    `StringSubstring` 在 `runtime.h` 中被列出：`F(StringSubstring, 3, 1)`，接受字符串，起始索引和结束索引作为参数。

* **Promise 操作:**
    ```javascript
    const promise = new Promise((resolve, reject) => {
        setTimeout(resolve, 100);
    });
    promise.then(() => console.log("resolved")); // 可能涉及到 Runtime_PromiseThen 等
    ```
    `PromiseHookAfter`、`PromiseHookBefore`、`ResolvePromise` 等在 `runtime.h` 中列出，表明 Promise 的生命周期管理涉及这些内置函数。

**代码逻辑推理示例 (假设输入与输出):**

假设我们看 `F(ArrayIndexOf, 3, 1)` 这个内置函数。

* **假设输入:**
    * 参数 1 (数组): `[10, 20, 30, 40]`
    * 参数 2 (要查找的元素): `30`
    * 参数 3 (起始索引): `0`

* **输出:** `2` (因为元素 `30` 在数组中的索引是 2)

* **另一个假设输入:**
    * 参数 1 (数组): `[10, 20, 30, 40]`
    * 参数 2 (要查找的元素): `50`
    * 参数 3 (起始索引): `0`

* **输出:** `-1` (因为元素 `50` 不在数组中)

**用户常见的编程错误示例:**

一些 JavaScript 常见的编程错误可能最终会导致调用到这些内置函数，并且如果参数不符合预期，V8 可能会抛出错误。

* **调用内置函数时参数数量错误:**
    例如，错误地尝试使用少于 3 个参数调用 `%ArrayIndexOf` (虽然用户不能直接调用 `%ArrayIndexOf`，但 V8 内部的调用可能因为某些逻辑错误导致参数不足)。这可能会导致 V8 内部的 C++ 代码出错。

* **对非对象调用对象方法:**
    ```javascript
    let str = "hello";
    Object.keys(str); // 错误：尝试获取原始类型字符串的键
    ```
    在这种情况下，`Object.keys` 最终会调用到 `Runtime_ObjectKeys`，但是由于传入的是一个原始类型，可能会导致类型错误或返回一个空数组。

* **对非函数对象进行函数调用:**
    ```javascript
    const obj = { a: 1 };
    obj(); // TypeError: obj is not a function
    ```
    V8 会检查 `obj` 是否可调用，如果不可调用，则会抛出一个 `TypeError`，这可能涉及到 `ThrowCalledNonCallable` 这个内置函数。

**总结:**

`v8/src/runtime/runtime.h` 是 V8 引擎的核心头文件，它定义了大量用于实现 JavaScript 语言特性的底层 C++ 函数的接口。 这些内置函数涵盖了从基本类型操作到复杂的语言特性（如 Promise、Async/Await、模块等）的各个方面。 开发者通常不会直接修改这个文件，但理解它的内容有助于深入理解 V8 引擎的工作原理以及 JavaScript 代码的执行过程。  它就像一个“功能清单”，列出了 V8 引擎能够提供的所有底层操作。

### 提示词
```
这是目录为v8/src/runtime/runtime.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_RUNTIME_RUNTIME_H_
#define V8_RUNTIME_RUNTIME_H_

#include <memory>

#include "include/v8-maybe.h"
#include "src/base/bit-field.h"
#include "src/common/globals.h"
#include "src/handles/handles.h"
#include "src/strings/unicode.h"
#include "src/utils/allocation.h"

namespace v8 {
namespace internal {

// * Each intrinsic is exposed in JavaScript via:
//    * %#name, which is always a runtime call.
//    * (optionally) %_#name, which can be inlined or just a runtime call, the
//      compiler in question decides.
//
// * IntrinsicTypes are Runtime::RUNTIME and Runtime::INLINE, respectively.
//
// * IDs are Runtime::k##name and Runtime::kInline##name, respectively.
//
// * All intrinsics have a C++ implementation Runtime_##name.
//
// * Each compiler has an explicit list of intrisics it supports, falling back
//   to a simple runtime call if necessary.

// Entries have the form F(name, number of arguments, number of return values):
// A variable number of arguments is specified by a -1, additional restrictions
// are specified by inline comments. To declare only the runtime version (no
// inline), use the F macro below. To declare the runtime version and the inline
// version simultaneously, use the I macro below.

#define FOR_EACH_INTRINSIC_ARRAY(F, I) \
  F(ArrayIncludes_Slow, 3, 1)          \
  F(ArrayIndexOf, 3, 1)                \
  F(ArrayIsArray, 1, 1)                \
  F(ArraySpeciesConstructor, 1, 1)     \
  F(GrowArrayElements, 2, 1)           \
  F(IsArray, 1, 1)                     \
  F(NewArray, -1 /* >= 3 */, 1)        \
  F(NormalizeElements, 1, 1)           \
  F(TransitionElementsKind, 2, 1)      \
  F(TransitionElementsKindWithKind, 2, 1)

#define FOR_EACH_INTRINSIC_ATOMICS(F, I)                       \
  F(AtomicsLoad64, 2, 1)                                       \
  F(AtomicsStore64, 3, 1)                                      \
  F(AtomicsAdd, 3, 1)                                          \
  F(AtomicsAnd, 3, 1)                                          \
  F(AtomicsCompareExchange, 4, 1)                              \
  F(AtomicsExchange, 3, 1)                                     \
  F(AtomicsNumWaitersForTesting, 2, 1)                         \
  F(AtomicsNumUnresolvedAsyncPromisesForTesting, 2, 1)         \
  F(AtomicsOr, 3, 1)                                           \
  F(AtomicsSub, 3, 1)                                          \
  F(AtomicsXor, 3, 1)                                          \
  F(SetAllowAtomicsWait, 1, 1)                                 \
  F(AtomicsLoadSharedStructOrArray, 2, 1)                      \
  F(AtomicsStoreSharedStructOrArray, 3, 1)                     \
  F(AtomicsExchangeSharedStructOrArray, 3, 1)                  \
  F(AtomicsCompareExchangeSharedStructOrArray, 4, 1)           \
  F(AtomicsSynchronizationPrimitiveNumWaitersForTesting, 1, 1) \
  F(AtomicsSychronizationNumAsyncWaitersInIsolateForTesting, 0, 1)

#define FOR_EACH_INTRINSIC_BIGINT(F, I) \
  F(BigIntCompareToNumber, 3, 1)        \
  F(BigIntCompareToString, 3, 1)        \
  F(BigIntEqualToBigInt, 2, 1)          \
  F(BigIntEqualToNumber, 2, 1)          \
  F(BigIntEqualToString, 2, 1)          \
  F(BigIntExponentiate, 2, 1)           \
  F(BigIntMaxLengthBits, 0, 1)          \
  F(BigIntToNumber, 1, 1)               \
  F(BigIntUnaryOp, 2, 1)                \
  F(ToBigInt, 1, 1)                     \
  F(ToBigIntConvertNumber, 1, 1)

#define FOR_EACH_THROWING_INTRINSIC_CLASSES(F, I) \
  F(ThrowConstructorNonCallableError, 1, 1)       \
  F(ThrowNotSuperConstructor, 2, 1)               \
  F(ThrowStaticPrototypeError, 0, 1)              \
  F(ThrowSuperAlreadyCalledError, 0, 1)           \
  F(ThrowSuperNotCalled, 0, 1)                    \
  F(ThrowUnsupportedSuperError, 0, 1)

#define FOR_EACH_INTRINSIC_CLASSES(F, I)    \
  FOR_EACH_THROWING_INTRINSIC_CLASSES(F, I) \
  F(DefineClass, -1 /* >= 3 */, 1)          \
  F(LoadFromSuper, 3, 1)                    \
  F(LoadKeyedFromSuper, 3, 1)               \
  F(StoreKeyedToSuper, 4, 1)                \
  F(StoreToSuper, 4, 1)

#define FOR_EACH_INTRINSIC_COLLECTIONS(F, I) \
  F(MapGrow, 1, 1)                           \
  F(MapShrink, 1, 1)                         \
  F(OrderedHashSetGrow, 2, 1)                \
  F(SetGrow, 1, 1)                           \
  F(SetShrink, 1, 1)                         \
  F(OrderedHashSetShrink, 1, 1)              \
  F(TheHole, 0, 1)                           \
  F(WeakCollectionDelete, 3, 1)              \
  F(WeakCollectionSet, 4, 1)                 \
  F(OrderedHashMapGrow, 2, 1)

#define FOR_EACH_INTRINSIC_COMPILER_GENERIC(F, I) \
  F(CompileOptimizedOSR, 0, 1)                    \
  F(CompileOptimizedOSRFromMaglev, 1, 1)          \
  F(CompileOptimizedOSRFromMaglevInlined, 2, 1)   \
  F(LogOrTraceOptimizedOSREntry, 0, 1)            \
  F(CompileLazy, 1, 1)                            \
  F(CompileBaseline, 1, 1)                        \
  F(InstallBaselineCode, 1, 1)                    \
  F(InstallSFICode, 1, 1)                         \
  F(InstantiateAsmJs, 4, 1)                       \
  F(NotifyDeoptimized, 0, 1)                      \
  F(ObserveNode, 1, 1)                            \
  F(ResolvePossiblyDirectEval, 6, 1)              \
  F(VerifyType, 1, 1)                             \
  F(CheckTurboshaftTypeOf, 2, 1)

#ifdef V8_ENABLE_LEAPTIERING

#define FOR_EACH_INTRINSIC_TIERING(F, I) \
  F(FunctionLogNextExecution, 1, 1)      \
  F(OptimizeMaglevEager, 1, 1)           \
  F(StartMaglevOptimizationJob, 1, 1)    \
  F(OptimizeTurbofanEager, 1, 1)         \
  F(StartTurbofanOptimizationJob, 1, 1)

#define FOR_EACH_INTRINSIC_COMPILER(F, I)   \
  FOR_EACH_INTRINSIC_COMPILER_GENERIC(F, I) \
  FOR_EACH_INTRINSIC_TIERING(F, I)

#else

#define FOR_EACH_INTRINSIC_TIERING(F, I)

#define FOR_EACH_INTRINSIC_COMPILER(F, I) \
  F(FunctionLogNextExecution, 1, 1)       \
  F(HealOptimizedCodeSlot, 1, 1)          \
  F(CompileOptimized, 1, 1)               \
  FOR_EACH_INTRINSIC_COMPILER_GENERIC(F, I)

#endif  // V8_ENABLE_LEAPTIERING

#define FOR_EACH_INTRINSIC_DATE(F, I) F(DateCurrentTime, 0, 1)

#define FOR_EACH_INTRINSIC_DEBUG(F, I)          \
  F(ClearStepping, 0, 1)                        \
  F(CollectGarbage, 1, 1)                       \
  F(DebugAsyncFunctionSuspended, 3, 1)          \
  F(DebugBreakAtEntry, 1, 1)                    \
  F(DebugCollectCoverage, 0, 1)                 \
  F(DebugGetLoadedScriptIds, 0, 1)              \
  F(DebugOnFunctionCall, 2, 1)                  \
  F(DebugPrepareStepInSuspendedGenerator, 0, 1) \
  F(DebugPromiseThen, 1, 1)                     \
  F(DebugToggleBlockCoverage, 1, 1)             \
  F(DebugTogglePreciseCoverage, 1, 1)           \
  F(FunctionGetInferredName, 1, 1)              \
  F(GetBreakLocations, 1, 1)                    \
  F(GetGeneratorScopeCount, 1, 1)               \
  F(GetGeneratorScopeDetails, 2, 1)             \
  F(HandleDebuggerStatement, 0, 1)              \
  F(IsBreakOnException, 1, 1)                   \
  F(LiveEditPatchScript, 2, 1)                  \
  F(ProfileCreateSnapshotDataBlob, 0, 1)        \
  F(ScheduleBreak, 0, 1)                        \
  F(ScriptLocationFromLine2, 4, 1)              \
  F(SetGeneratorScopeVariableValue, 4, 1)       \
  I(IncBlockCounter, 2, 1)

#define FOR_EACH_INTRINSIC_FORIN(F, I) \
  F(ForInEnumerate, 1, 1)              \
  F(ForInHasProperty, 2, 1)

#ifdef V8_TRACE_UNOPTIMIZED
#define FOR_EACH_INTRINSIC_TRACE_UNOPTIMIZED(F, I) \
  F(TraceUnoptimizedBytecodeEntry, 3, 1)           \
  F(TraceUnoptimizedBytecodeExit, 3, 1)
#else
#define FOR_EACH_INTRINSIC_TRACE_UNOPTIMIZED(F, I)
#endif

#ifdef V8_TRACE_FEEDBACK_UPDATES
#define FOR_EACH_INTRINSIC_TRACE_FEEDBACK(F, I) F(TraceUpdateFeedback, 3, 1)
#else
#define FOR_EACH_INTRINSIC_TRACE_FEEDBACK(F, I)
#endif

#define FOR_EACH_INTRINSIC_TRACE(F, I)       \
  FOR_EACH_INTRINSIC_TRACE_UNOPTIMIZED(F, I) \
  FOR_EACH_INTRINSIC_TRACE_FEEDBACK(F, I)

#define FOR_EACH_INTRINSIC_FUNCTION(F, I)  \
  F(Call, -1 /* >= 2 */, 1)                \
  F(FunctionGetScriptSource, 1, 1)         \
  F(FunctionGetScriptId, 1, 1)             \
  F(FunctionGetScriptSourcePosition, 1, 1) \
  F(FunctionGetSourceCode, 1, 1)           \
  F(FunctionIsAPIFunction, 1, 1)

#define FOR_EACH_INTRINSIC_GENERATOR(F, I) \
  I(AsyncFunctionAwait, 2, 1)              \
  I(AsyncFunctionEnter, 2, 1)              \
  I(AsyncFunctionReject, 2, 1)             \
  I(AsyncFunctionResolve, 2, 1)            \
  I(AsyncGeneratorAwait, 2, 1)             \
  I(AsyncGeneratorReject, 2, 1)            \
  I(AsyncGeneratorResolve, 3, 1)           \
  I(AsyncGeneratorYieldWithAwait, 2, 1)    \
  I(CreateJSGeneratorObject, 2, 1)         \
  I(GeneratorClose, 1, 1)                  \
  F(GeneratorGetFunction, 1, 1)            \
  I(GeneratorGetResumeMode, 1, 1)

#ifdef V8_INTL_SUPPORT
#define FOR_EACH_INTRINSIC_INTL(F, I) \
  F(FormatList, 2, 1)                 \
  F(FormatListToParts, 2, 1)          \
  F(StringToLowerCaseIntl, 1, 1)      \
  F(StringToLocaleLowerCase, 2, 1)    \
  F(StringToUpperCaseIntl, 1, 1)  // End of macro.
#else
#define FOR_EACH_INTRINSIC_INTL(F, I)
#endif  // V8_INTL_SUPPORT

#define FOR_EACH_THROWING_INTRINSIC_INTERNAL(F, I) \
  F(Throw, 1, 1)                                   \
  F(ThrowApplyNonFunction, 1, 1)                   \
  F(ThrowCalledNonCallable, 1, 1)                  \
  F(ThrowConstructedNonConstructable, 1, 1)        \
  F(ThrowConstructorReturnedNonObject, 0, 1)       \
  F(ThrowInvalidStringLength, 0, 1)                \
  F(ThrowInvalidTypedArrayAlignment, 2, 1)         \
  F(ThrowIteratorError, 1, 1)                      \
  F(ThrowSpreadArgError, 2, 1)                     \
  F(ThrowIteratorResultNotAnObject, 1, 1)          \
  F(ThrowNoAccess, 0, 1)                           \
  F(ThrowNotConstructor, 1, 1)                     \
  F(ThrowPatternAssignmentNonCoercible, 1, 1)      \
  F(ThrowRangeError, -1 /* >= 1 */, 1)             \
  F(ThrowReferenceError, 1, 1)                     \
  F(ThrowAccessedUninitializedVariable, 1, 1)      \
  F(ThrowStackOverflow, 0, 1)                      \
  F(ThrowSymbolAsyncIteratorInvalid, 0, 1)         \
  F(ThrowSymbolIteratorInvalid, 0, 1)              \
  F(ThrowThrowMethodMissing, 0, 1)                 \
  F(ThrowTypeError, -1 /* >= 1 */, 1)              \
  F(ThrowTypeErrorIfStrict, -1 /* >= 1 */, 1)      \
  F(ReThrow, 1, 1)                                 \
  F(ReThrowWithMessage, 2, 1)

#define FOR_EACH_INTRINSIC_INTERNAL(F, I)                  \
  FOR_EACH_THROWING_INTRINSIC_INTERNAL(F, I)               \
  F(AccessCheck, 1, 1)                                     \
  F(AllocateByteArray, 1, 1)                               \
  F(AllocateInYoungGeneration, 2, 1)                       \
  F(AllocateInOldGeneration, 2, 1)                         \
  F(AllowDynamicFunction, 1, 1)                            \
  I(CreateAsyncFromSyncIterator, 1, 1)                     \
  F(CreateListFromArrayLike, 1, 1)                         \
  F(DoubleToStringWithRadix, 2, 1)                         \
  F(FatalProcessOutOfMemoryInAllocateRaw, 0, 1)            \
  F(FatalProcessOutOfMemoryInvalidArrayLength, 0, 1)       \
  F(FatalInvalidSize, 0, 1)                                \
  F(GetAndResetRuntimeCallStats, -1 /* <= 2 */, 1)         \
  F(GetAndResetTurboProfilingData, 0, 1)                   \
  F(GetTemplateObject, 3, 1)                               \
  F(IncrementUseCounter, 1, 1)                             \
  F(BytecodeBudgetInterrupt_Ignition, 1, 1)                \
  F(BytecodeBudgetInterruptWithStackCheck_Ignition, 1, 1)  \
  F(BytecodeBudgetInterrupt_Sparkplug, 1, 1)               \
  F(BytecodeBudgetInterruptWithStackCheck_Sparkplug, 1, 1) \
  F(BytecodeBudgetInterrupt_Maglev, 1, 1)                  \
  F(BytecodeBudgetInterruptWithStackCheck_Maglev, 1, 1)    \
  F(InvalidateDependentCodeForScriptContextSlot, 1, 1)     \
  F(NewError, 2, 1)                                        \
  F(NewReferenceError, 2, 1)                               \
  F(NewTypeError, -1 /* [1, 4] */, 1)                      \
  F(OrdinaryHasInstance, 2, 1)                             \
  F(PropagateException, 0, 1)                              \
  F(ReportMessageFromMicrotask, 1, 1)                      \
  F(RunMicrotaskCallback, 2, 1)                            \
  F(PerformMicrotaskCheckpoint, 0, 1)                      \
  F(SharedValueBarrierSlow, 1, 1)                          \
  F(StackGuard, 0, 1)                                      \
  F(HandleNoHeapWritesInterrupts, 0, 1)                    \
  F(StackGuardWithGap, 1, 1)                               \
  F(TerminateExecution, 0, 1)                              \
  F(Typeof, 1, 1)                                          \
  F(UnwindAndFindExceptionHandler, 0, 1)

#define FOR_EACH_INTRINSIC_LITERALS(F, I) \
  F(CreateArrayLiteral, 4, 1)             \
  F(CreateObjectLiteral, 4, 1)            \
  F(CreateRegExpLiteral, 4, 1)

#define FOR_EACH_INTRINSIC_MODULE(F, I)    \
  F(DynamicImportCall, -1 /* [3, 4] */, 1) \
  I(GetImportMetaObject, 0, 1)             \
  F(GetModuleNamespace, 1, 1)              \
  F(GetModuleNamespaceExport, 2, 1)

#define FOR_EACH_INTRINSIC_NUMBERS(F, I) \
  F(ArrayBufferMaxByteLength, 0, 1)      \
  F(GetHoleNaNLower, 0, 1)               \
  F(GetHoleNaNUpper, 0, 1)               \
  F(IsSmi, 1, 1)                         \
  F(MaxSmi, 0, 1)                        \
  F(NumberToStringSlow, 1, 1)            \
  F(StringParseFloat, 1, 1)              \
  F(StringParseInt, 2, 1)                \
  F(StringToNumber, 1, 1)

#define FOR_EACH_INTRINSIC_OBJECT(F, I)                                \
  F(AddAsyncDisposableValue, 2, 1)                                     \
  F(AddDictionaryProperty, 3, 1)                                       \
  F(AddDisposableValue, 2, 1)                                          \
  F(AddPrivateBrand, 4, 1)                                             \
  F(AllocateHeapNumber, 0, 1)                                          \
  F(CompleteInobjectSlackTrackingForMap, 1, 1)                         \
  I(CopyDataProperties, 2, 1)                                          \
  I(CopyDataPropertiesWithExcludedPropertiesOnStack, -1 /* >= 1 */, 1) \
  I(CreateDataProperty, 3, 1)                                          \
  I(CreateIterResultObject, 2, 1)                                      \
  F(CreatePrivateAccessors, 2, 1)                                      \
  F(DefineAccessorPropertyUnchecked, 5, 1)                             \
  F(DefineKeyedOwnPropertyInLiteral, 6, 1)                             \
  F(DefineGetterPropertyUnchecked, 4, 1)                               \
  F(DefineSetterPropertyUnchecked, 4, 1)                               \
  F(DeleteProperty, 3, 1)                                              \
  F(DisposeDisposableStack, 4, 1)                                      \
  F(GetDerivedMap, 2, 1)                                               \
  F(GetFunctionName, 1, 1)                                             \
  F(GetOwnPropertyDescriptorObject, 2, 1)                              \
  F(GetOwnPropertyKeys, 2, 1)                                          \
  F(GetPrivateMember, 2, 1)                                            \
  F(GetProperty, -1 /* [2, 3] */, 1)                                   \
  F(HandleExceptionsInDisposeDisposableStack, 3, 1)                    \
  F(HasFastPackedElements, 1, 1)                                       \
  F(HasInPrototypeChain, 2, 1)                                         \
  F(HasProperty, 2, 1)                                                 \
  F(InitializeDisposableStack, 0, 1)                                   \
  F(InternalSetPrototype, 2, 1)                                        \
  F(IsJSReceiver, 1, 1)                                                \
  F(JSReceiverPreventExtensionsDontThrow, 1, 1)                        \
  F(JSReceiverPreventExtensionsThrow, 1, 1)                            \
  F(JSReceiverGetPrototypeOf, 1, 1)                                    \
  F(JSReceiverSetPrototypeOfDontThrow, 2, 1)                           \
  F(JSReceiverSetPrototypeOfThrow, 2, 1)                               \
  F(LoadPrivateGetter, 1, 1)                                           \
  F(LoadPrivateSetter, 1, 1)                                           \
  F(NewObject, 2, 1)                                                   \
  F(ObjectCreate, 2, 1)                                                \
  F(ObjectEntries, 1, 1)                                               \
  F(ObjectEntriesSkipFastPath, 1, 1)                                   \
  F(ObjectGetOwnPropertyNames, 1, 1)                                   \
  F(ObjectGetOwnPropertyNamesTryFast, 1, 1)                            \
  F(ObjectHasOwnProperty, 2, 1)                                        \
  F(HasOwnConstDataProperty, 2, 1)                                     \
  F(ObjectIsExtensible, 1, 1)                                          \
  F(ObjectKeys, 1, 1)                                                  \
  F(ObjectValues, 1, 1)                                                \
  F(ObjectValuesSkipFastPath, 1, 1)                                    \
  F(OptimizeObjectForAddingMultipleProperties, 2, 1)                   \
  F(SetDataProperties, 2, 1)                                           \
  F(SetFunctionName, 2, 1)                                             \
  F(SetKeyedProperty, 3, 1)                                            \
  F(DefineObjectOwnProperty, 3, 1)                                     \
  F(SetNamedProperty, 3, 1)                                            \
  F(SetOwnPropertyIgnoreAttributes, 4, 1)                              \
  F(ShrinkNameDictionary, 1, 1)                                        \
  F(ShrinkSwissNameDictionary, 1, 1)                                   \
  F(ToFastProperties, 1, 1)                                            \
  F(ToLength, 1, 1)                                                    \
  F(ToName, 1, 1)                                                      \
  F(ToNumber, 1, 1)                                                    \
  F(ToNumeric, 1, 1)                                                   \
  F(ToObject, 1, 1)                                                    \
  F(ToString, 1, 1)                                                    \
  F(TryMigrateInstance, 1, 1)                                          \
  F(SetPrivateMember, 3, 1)                                            \
  F(SwissTableAdd, 4, 1)                                               \
  F(SwissTableAllocate, 1, 1)                                          \
  F(SwissTableDelete, 2, 1)                                            \
  F(SwissTableDetailsAt, 2, 1)                                         \
  F(SwissTableElementsCount, 1, 1)                                     \
  F(SwissTableEquals, 2, 1)                                            \
  F(SwissTableFindEntry, 2, 1)                                         \
  F(SwissTableUpdate, 4, 1)                                            \
  F(SwissTableValueAt, 2, 1)                                           \
  F(SwissTableKeyAt, 2, 1)

#define FOR_EACH_INTRINSIC_OPERATORS(F, I) \
  F(Add, 2, 1)                             \
  F(Equal, 2, 1)                           \
  F(GreaterThan, 2, 1)                     \
  F(GreaterThanOrEqual, 2, 1)              \
  F(LessThan, 2, 1)                        \
  F(LessThanOrEqual, 2, 1)                 \
  F(NotEqual, 2, 1)                        \
  F(StrictEqual, 2, 1)                     \
  F(StrictNotEqual, 2, 1)                  \
  F(ReferenceEqual, 2, 1)

#define FOR_EACH_INTRINSIC_PROMISE(F, I) \
  F(EnqueueMicrotask, 1, 1)              \
  F(PromiseHookAfter, 1, 1)              \
  F(PromiseHookBefore, 1, 1)             \
  F(PromiseHookInit, 2, 1)               \
  F(PromiseRejectEventFromStack, 2, 1)   \
  F(PromiseRevokeReject, 1, 1)           \
  F(RejectPromise, 3, 1)                 \
  F(ResolvePromise, 2, 1)                \
  F(PromiseRejectAfterResolved, 2, 1)    \
  F(PromiseResolveAfterResolved, 2, 1)   \
  F(ConstructSuppressedError, 3, 1)      \
  F(ConstructAggregateErrorHelper, 4, 1) \
  F(ConstructInternalAggregateErrorHelper, -1 /* <= 5*/, 1)

#define FOR_EACH_INTRINSIC_PROXY(F, I) \
  F(CheckProxyGetSetTrapResult, 2, 1)  \
  F(CheckProxyHasTrapResult, 2, 1)     \
  F(CheckProxyDeleteTrapResult, 2, 1)  \
  F(GetPropertyWithReceiver, 3, 1)     \
  F(IsJSProxy, 1, 1)                   \
  F(JSProxyGetHandler, 1, 1)           \
  F(JSProxyGetTarget, 1, 1)            \
  F(SetPropertyWithReceiver, 4, 1)

#define FOR_EACH_INTRINSIC_REGEXP(F, I)             \
  F(RegExpBuildIndices, 3, 1)                       \
  F(RegExpGrowRegExpMatchInfo, 2, 1)                \
  F(RegExpExecMultiple, 3, 1)                       \
  F(RegExpInitializeAndCompile, 3, 1)               \
  F(RegExpMatchGlobalAtom, 3, 1)                    \
  F(RegExpReplaceRT, 3, 1)                          \
  F(RegExpSplit, 3, 1)                              \
  F(RegExpStringFromFlags, 1, 1)                    \
  F(StringReplaceNonGlobalRegExpWithFunction, 3, 1) \
  F(StringSplit, 3, 1)                              \
  F(RegExpExec, 4, 1)                               \
  F(RegExpExperimentalOneshotExec, 4, 1)

#define FOR_EACH_THROWING_INTRINSIC_SCOPES(F, I) \
  F(ThrowConstAssignError, 0, 1)                 \
  F(ThrowUsingAssignError, 0, 1)

#define FOR_EACH_INTRINSIC_SCOPES(F, I)            \
  FOR_EACH_THROWING_INTRINSIC_SCOPES(F, I)         \
  F(DeclareEvalFunction, 2, 1)                     \
  F(DeclareEvalVar, 1, 1)                          \
  F(DeclareGlobals, 2, 1)                          \
  F(DeclareModuleExports, 2, 1)                    \
  F(DeleteLookupSlot, 1, 1)                        \
  F(LoadLookupSlot, 1, 1)                          \
  F(LoadLookupSlotInsideTypeof, 1, 1)              \
  F(LoadLookupSlotForCall_Baseline, 2, 1)          \
                                                   \
  F(NewClosure, 2, 1)                              \
  F(NewClosure_Tenured, 2, 1)                      \
  F(NewFunctionContext, 1, 1)                      \
  F(NewRestParameter, 1, 1)                        \
  F(NewSloppyArguments, 1, 1)                      \
  F(NewStrictArguments, 1, 1)                      \
  F(PushBlockContext, 1, 1)                        \
  F(PushCatchContext, 2, 1)                        \
  F(PushWithContext, 2, 1)                         \
  F(StoreGlobalNoHoleCheckForReplLetOrConst, 2, 1) \
  F(StoreLookupSlot_Sloppy, 2, 1)                  \
  F(StoreLookupSlot_SloppyHoisting, 2, 1)          \
  F(StoreLookupSlot_Strict, 2, 1)

#define FOR_EACH_INTRINSIC_SHADOW_REALM(F, I) \
  F(ShadowRealmWrappedFunctionCreate, 2, 1)   \
  F(ShadowRealmImportValue, 1, 1)             \
  F(ShadowRealmThrow, 2, 1)

#define FOR_EACH_INTRINSIC_STRINGS(F, I)  \
  F(FlattenString, 1, 1)                  \
  F(GetSubstitution, 5, 1)                \
  F(InternalizeString, 1, 1)              \
  F(StringAdd, 2, 1)                      \
  F(StringBuilderConcat, 3, 1)            \
  F(StringCharCodeAt, 2, 1)               \
  F(StringCodePointAt, 2, 1)              \
  F(StringCompare, 2, 1)                  \
  F(StringEqual, 2, 1)                    \
  F(StringEscapeQuotes, 1, 1)             \
  F(StringGreaterThan, 2, 1)              \
  F(StringGreaterThanOrEqual, 2, 1)       \
  F(StringIsWellFormed, 1, 1)             \
  F(StringLastIndexOf, 2, 1)              \
  F(StringLessThan, 2, 1)                 \
  F(StringLessThanOrEqual, 2, 1)          \
  F(StringMaxLength, 0, 1)                \
  F(StringReplaceOneCharWithString, 3, 1) \
  F(StringSubstring, 3, 1)                \
  F(StringToArray, 2, 1)                  \
  F(StringToWellFormed, 1, 1)

#define FOR_EACH_INTRINSIC_SYMBOL(F, I)    \
  F(CreatePrivateNameSymbol, 1, 1)         \
  F(CreatePrivateBrandSymbol, 1, 1)        \
  F(CreatePrivateSymbol, -1 /* <= 1 */, 1) \
  F(SymbolDescriptiveString, 1, 1)         \
  F(SymbolIsPrivate, 1, 1)

#define FOR_EACH_INTRINSIC_TEMPORAL(F, I) \
  F(IsInvalidTemporalCalendarField, 2, 1)

#define FOR_EACH_INTRINSIC_TEST(F, I)         \
  F(Abort, 1, 1)                              \
  F(AbortCSADcheck, 1, 1)                     \
  F(AbortJS, 1, 1)                            \
  F(ActiveTierIsIgnition, 1, 1)               \
  F(ActiveTierIsSparkplug, 1, 1)              \
  F(ActiveTierIsMaglev, 1, 1)                 \
  F(ActiveTierIsTurbofan, 1, 1)               \
  F(ArrayIteratorProtector, 0, 1)             \
  F(ArraySpeciesProtector, 0, 1)              \
  F(BaselineOsr, -1, 1)                       \
  F(BenchMaglev, 2, 1)                        \
  F(BenchTurbofan, 2, 1)                      \
  F(ClearFunctionFeedback, 1, 1)              \
  F(ClearMegamorphicStubCache, 0, 1)          \
  F(CompleteInobjectSlackTracking, 1, 1)      \
  F(ConstructConsString, 2, 1)                \
  F(ConstructDouble, 2, 1)                    \
  F(ConstructInternalizedString, 1, 1)        \
  F(ConstructSlicedString, 2, 1)              \
  F(ConstructThinString, 1, 1)                \
  F(CurrentFrameIsTurbofan, 0, 1)             \
  F(DebugPrint, -1, 1)                        \
  F(DebugPrintFloat, 5, 1)                    \
  F(DebugPrintPtr, 1, 1)                      \
  F(DebugPrintWord, 5, 1)                     \
  F(DebugTrace, 0, 1)                         \
  F(DeoptimizeFunction, 1, 1)                 \
  F(DisableOptimizationFinalization, 0, 1)    \
  F(DisallowCodegenFromStrings, 1, 1)         \
  F(DisassembleFunction, 1, 1)                \
  F(EnableCodeLoggingForTesting, 0, 1)        \
  F(EnsureFeedbackVectorForFunction, 1, 1)    \
  F(FinalizeOptimization, 0, 1)               \
  F(ForceFlush, 1, 1)                         \
  F(GetAbstractModuleSource, 0, 1)            \
  F(GetCallable, 1, 1)                        \
  F(GetFeedback, 1, 1)                        \
  F(GetFunctionForCurrentFrame, 0, 1)         \
  F(GetInitializerFunction, 1, 1)             \
  F(GetOptimizationStatus, 1, 1)              \
  F(GetUndetectable, 0, 1)                    \
  F(GetWeakCollectionSize, 1, 1)              \
  F(GlobalPrint, -1, 1)                       \
  F(HasCowElements, 1, 1)                     \
  F(HasDictionaryElements, 1, 1)              \
  F(HasDoubleElements, 1, 1)                  \
  F(HasElementsInALargeObjectSpace, 1, 1)     \
  F(HasFastElements, 1, 1)                    \
  F(HasFastProperties, 1, 1)                  \
  F(HasFixedBigInt64Elements, 1, 1)           \
  F(HasFixedBigUint64Elements, 1, 1)          \
  F(HasFixedFloat16Elements, 1, 1)            \
  F(HasFixedFloat32Elements, 1, 1)            \
  F(HasFixedFloat64Elements, 1, 1)            \
  F(HasFixedInt16Elements, 1, 1)              \
  F(HasFixedInt32Elements, 1, 1)              \
  F(HasFixedInt8Elements, 1, 1)               \
  F(HasFixedUint16Elements, 1, 1)             \
  F(HasFixedUint32Elements, 1, 1)             \
  F(HasFixedUint8ClampedElements, 1, 1)       \
  F(HasFixedUint8Elements, 1, 1)              \
  F(HasHoleyElements, 1, 1)                   \
  F(HasObjectElements, 1, 1)                  \
  F(HasPackedElements, 1, 1)                  \
  F(HasSloppyArgumentsElements, 1, 1)         \
  F(HasSmiElements, 1, 1)                     \
  F(HasSmiOrObjectElements, 1, 1)             \
  F(HaveSameMap, 2, 1)                        \
  F(HeapObjectVerify, 1, 1)                   \
  F(ICsAreEnabled, 0, 1)                      \
  F(InLargeObjectSpace, 1, 1)                 \
  F(InYoungGeneration, 1, 1)                  \
  F(Is64Bit, 0, 1)                            \
  F(IsAtomicsWaitAllowed, 0, 1)               \
  F(IsBeingInterpreted, 0, 1)                 \
  F(IsConcatSpreadableProtector, 0, 1)        \
  F(IsConcurrentRecompilationSupported, 0, 1) \
  F(IsDictPropertyConstTrackingEnabled, 0, 1) \
  F(IsEfficiencyModeEnabled, 0, 1)            \
  F(IsInPlaceInternalizableString, 1, 1)      \
  F(IsInternalizedString, 1, 1)               \
  F(StringToCString, 1, 1)                    \
  F(StringUtf8Value, 1, 1)                    \
  F(IsMaglevEnabled, 0, 1)                    \
  F(IsSameHeapObject, 2, 1)                   \
  F(IsSharedString, 1, 1)                     \
  F(IsSparkplugEnabled, 0, 1)                 \
  F(IsTurbofanEnabled, 0, 1)                  \
  F(IsWasmTieringPredictable, 0, 1)           \
  F(MapIteratorProtector, 0, 1)               \
  F(NeverOptimizeFunction, 1, 1)              \
  F(NewRegExpWithBacktrackLimit, 3, 1)        \
  F(NoElementsProtector, 0, 1)                \
  F(NotifyContextDisposed, 0, 1)              \
  F(SetPriorityBestEffort, 0, 1)              \
  F(SetPriorityUserVisible, 0, 1)             \
  F(SetPriorityUserBlocking, 0, 1)            \
  F(OptimizeMaglevOnNextCall, 1, 1)           \
  F(OptimizeFunctionOnNextCall, -1, 1)        \
  F(OptimizeOsr, -1, 1)                       \
  F(PrepareFunctionForOptimization, -1, 1)    \
  F(PretenureAllocationSite, 1, 1)            \
  F(PrintWithNameForAssert, 2, 1)             \
  F(PromiseSpeciesProtector, 0, 1)            \
  F(RegExpSpeciesProtector, 0, 1)             \
  F(RegexpHasBytecode, 2, 1)                  \
  F(RegexpHasNativeCode, 2, 1)                \
  F(RegexpIsUnmodified, 1, 1)                 \
  F(RegexpTypeTag, 1, 1)                      \
  F(RunningInSimulator, 0, 1)                 \
  F(RuntimeEvaluateREPL, 1, 1)                \
  F(ScheduleGCInStackCheck, 0, 1)             \
  F(SerializeDeserializeNow, 0, 1)            \
  F(SetAllocationTimeout, -1 /* 2 || 3 */, 1) \
  F(SetBatterySaverMode, 1, 1)                \
  F(SetForceSlowPath, 1, 1)                   \
  F(SetIteratorProtector, 0, 1)               \
  F(SharedGC, 0, 1)                           \
  F(ShareObject, 1, 1)                        \
  F(SimulateNewspaceFull, 0, 1)               \
  F(StringIsFlat, 1, 1)                       \
  F(StringIteratorProtector, 0, 1)            \
  F(StringWrapperToPrimitiveProtector, 0, 1)  \
  F(SystemBreak, 0, 1)                        \
  F(TakeHeapSnapshot, -1, 1)                  \
  F(TraceEnter, 0, 1)                         \
  F(TraceExit, 1, 1)                          \
  F(TurbofanStaticAssert, 1, 1)               \
  F(TypedArraySpeciesProtector, 0, 1)         \
  F(WaitForBackgroundOptimization, 0, 1)      \
  I(DeoptimizeNow, 0, 1)                      \
  F(LeakHole, 0, 1)

#define FOR_EACH_INTRINSIC_TYPEDARRAY(F, I)    \
  F(ArrayBufferDetach, -1, 1)                  \
  F(ArrayBufferSetDetachKey, 2, 1)             \
  F(GrowableSharedArrayBufferByteLength, 1, 1) \
  F(TypedArrayCopyElements, 3, 1)              \
  F(TypedArrayGetBuffer, 1, 1)                 \
  F(TypedArraySet, 2, 1)                       \
  F(TypedArraySortFast, 1, 1)

#if V8_ENABLE_DRUMBRAKE
#define FOR_EACH_INTRINSIC_WASM_DRUMBRAKE(F, I) F(WasmRunInterpreter, 3, 1)
#else
#define FOR_EACH_INTRINSIC_WASM_DRUMBRAKE(F, I)
#endif  // V8_ENABLE_DRUMBRAKE

#define FOR_EACH_INTRINSIC_WASM(F, I)         \
  FOR_EACH_INTRINSIC_WASM_DRUMBRAKE(F, I)     \
  F(ThrowBadSuspenderError, 0, 1)             \
  F(ThrowWasmError, 1, 1)                     \
  F(TrapHandlerThrowWasmError, 0, 1)          \
  F(ThrowWasmStackOverflow, 0, 1)             \
  F(WasmI32AtomicWait, 4, 1)                  \
  F(WasmI64AtomicWait, 5, 1)                  \
  F(WasmMemoryGrow, 2, 1)                     \
  F(WasmStackGuard, 1, 1)                     \
  F(WasmThrow, 2, 1)                          \
  F(WasmReThrow, 1, 1)                        \
  F(WasmThrowJSTypeError, 0, 1)               \
  F(WasmThrowTypeError, 2, 1)                 \
  F(WasmThrowRangeError, 1, 1)                \
  F(WasmThrowDataViewTypeError, 2, 1)         \
  F(WasmThrowDataViewDetachedError, 1, 1)     \
  F(WasmRefFunc, 1, 1)                        \
  F(WasmInternalFunctionCreateExternal, 1, 1) \
  F(WasmFunctionTableGet, 3, 1)               \
  F(WasmFunctionTableSet, 4, 1)               \
  F(WasmTableInit, 6, 1)                      \
  F(WasmTableCopy, 6, 1)                      \
  F(WasmTableGrow, 3, 1)                      \
  F(WasmTableFill, 5, 1)                      \
  F(WasmJSToWasmObject, 2, 1)                 \
  F(WasmGenericJSToWasmObject, 3, 1)          \
  F(WasmGenericWasmToJSObject, 1, 1)          \
  F(WasmCompileLazy, 2, 1)
```