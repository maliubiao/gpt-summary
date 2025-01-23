Response:
My thinking process to analyze the provided C++ header file (`builtins-definitions.h`) and answer the user's request goes through these stages:

1. **Understanding the Request:** I first break down the user's request into key questions:
    * What are the functionalities of this file?
    * If the file ended in `.tq`, what would that signify?
    * How does this relate to JavaScript functionality, and can I provide examples?
    * Are there any code logic inferences possible, and can I provide examples with inputs and outputs?
    * What common programming errors are related to this?
    * Can I summarize the functionalities as part 1 of a series?

2. **Initial Scan and Keyword Recognition:** I scan the file for recognizable keywords and patterns. Immediately, I notice:
    * `Copyright 2017 the V8 project authors`: This confirms it's a V8 source file.
    * `#ifndef V8_BUILTINS_BUILTINS_DEFINITIONS_H_`, `#define V8_BUILTINS_BUILTINS_DEFINITIONS_H_`, `#endif`: This is a standard C/C++ header guard, preventing multiple inclusions.
    * `#include`:  This indicates dependencies on other V8 headers, specifically `bytecodes-builtins-list.h` and `builtin-definitions.h`. The latter is "torque-generated," which is a crucial clue.
    * `namespace v8 { namespace internal {`: This indicates the C++ namespace.
    * Macros like `IF_TSA`, `BUILTIN_LIST_BASE_TIER0`, `BUILTIN_LIST_BASE_TIERING`, `BUILTIN_LIST_BASE_TIER1`: These are heavily used to define lists of builtins.
    * Comments starting with `// CPP:`, `// TFJ:`, `// TSJ:`, `// TFS:`, `// TFC:`, `// TSC:`, `// TFH:`, `// BCH:`, `// ASM:`: These are crucial for understanding the different types of builtins defined.
    *  Keywords like `Builtin`, `Turbofan`, `Turboshaft`, `CodeStub`, `Bytecode`, `Assembly`, `Tier`, `Deoptimization`, `GC`, `Call`, `Construct`, `String`, `Array`, etc.

3. **Inferring the Core Functionality:** Based on the keywords and the structure, I can infer the primary function of this file: **defining and categorizing built-in functions within the V8 JavaScript engine.** The different prefixes (`CPP`, `TFJ`, etc.) indicate *how* these builtins are implemented (C++, Turbofan, etc.). The "Tier" concept suggests performance optimization and access efficiency.

4. **Addressing the `.tq` Extension:** The request explicitly asks about the `.tq` extension. The `#include "torque-generated/builtin-definitions.h"` line, along with the observation that many builtins don't have explicit implementation details in *this* file, strongly suggests that `.tq` files are used to *generate* some of these definitions. Torque is V8's domain-specific language for defining builtins. Therefore, if this file *were* a `.tq` file, it would contain the Torque source code that *generates* (or contributes to generating) the C++ definitions found here.

5. **Connecting to JavaScript:**  The names of many builtins are highly suggestive of JavaScript functions and concepts (e.g., `ArrayConstructor`, `StringEqual`, `CallFunction`, `Construct`). This indicates a strong relationship. I can now start thinking of JavaScript examples for some of these builtins. For instance, `ArrayConstructor` is directly related to creating new arrays in JavaScript. `StringEqual` is used behind the scenes for string comparisons (`===`). `CallFunction` and `ConstructFunction` relate to function invocation.

6. **Considering Code Logic and Examples:** While this header file *defines* the builtins, it doesn't contain the *implementation* logic. The logic resides in the C++, Torque, or assembly code referenced by these definitions. Therefore, direct "code logic inference" in the sense of tracing execution isn't possible *within this file*. However, I *can* infer the *purpose* and general behavior based on the names. For example, `StringGreaterThan` likely compares two strings lexicographically. For input/output, I'd need to consider the corresponding JavaScript operations.

7. **Identifying Common Programming Errors:**  The connection to JavaScript allows me to think about common errors related to these builtins. For example, misusing `call` or `apply` relates to the `CallFunction` builtins. Incorrectly using `new` relates to `ConstructFunction`. Type errors leading to implicit conversions relate to the `ToNumber` and other type conversion builtins.

8. **Structuring the Summary:** Finally, I organize my findings into a coherent summary, addressing each part of the user's request. I emphasize that this file is primarily a *definition* file, not an implementation file. I clearly differentiate between the C++ definitions and the underlying implementation languages (Torque, C++, Assembly).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *contains* the implementation of some simple builtins.
* **Correction:** The comments clearly indicate the implementation technology (`CPP`, `TFJ`, etc.), and most of these point to separate systems. This file is more like an index or table of contents.
* **Initial thought:** I can provide detailed C++ code logic examples.
* **Correction:** This file primarily *declares* the builtins. The logic is elsewhere. I should focus on the *purpose* and how they relate to JavaScript behavior.
* **Initial thought:**  The tiers are just an organizational thing.
* **Refinement:** The comments explicitly mention performance implications related to tier 0, indicating it's more than just organization.

By following this structured approach, combining code analysis with domain knowledge of JavaScript and V8 internals, I can generate a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下 `v8/src/builtins/builtins-definitions.h` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/builtins/builtins-definitions.h` 文件是 V8 JavaScript 引擎的核心组成部分，它定义了所有内置函数（builtins）的元数据和组织结构。  可以将其理解为一个**内置函数注册表**或者**目录**。

具体来说，它的主要功能包括：

1. **声明内置函数:**  它使用宏（例如 `CPP`, `TFJ`, `ASM` 等）来声明各种不同类型的内置函数。这些宏指示了内置函数的实现方式和链接方式，例如：
   - `CPP`:  用 C++ 实现的内置函数。
   - `TFJ`: 用 Turbofan 编译器实现的，可以像 JavaScript 函数一样调用的内置函数。
   - `ASM`: 用平台相关的汇编语言实现的内置函数。
   - 其他宏如 `TFC`, `TFS`, `TFH`, `BCH` 等，分别代表不同类型的 Turbofan builtins 或 Bytecode handlers。

2. **定义内置函数的属性:**  宏中包含的参数定义了内置函数的名称、参数数量、以及其他特定于实现方式的属性（例如，是否需要上下文，接口描述符等）。

3. **组织内置函数到不同的层级 (Tiers):**  通过 `BUILTIN_LIST_BASE_TIER0` 和 `BUILTIN_LIST_BASE_TIER1` 等宏，将内置函数组织到不同的层级。这种分层机制主要用于优化性能，`Tier 0` 的内置函数被保证靠近根寄存器，可以更高效地访问。

4. **支持实验性特性:** 通过 `#ifdef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS` 和 `IF_TSA` 宏，可以支持实验性的 TSA (Thread-Safe API) builtins。

5. **为不同的编译器和执行模型提供接口:**  该文件中的定义被 V8 的不同组件使用，包括解释器、各种优化编译器 (Turbofan, Turboshaft, Maglev) 以及运行时系统。

**关于文件扩展名 `.tq`:**

如果 `v8/src/builtins/builtins-definitions.h` 文件以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。 Torque 是 V8 专门用于定义内置函数的领域特定语言 (DSL)。 Torque 代码会被编译成 C++ 代码，而 `builtins-definitions.h` 文件（当前是 `.h` 结尾）很可能就是 Torque 编译生成的 C++ 头文件之一。

**与 JavaScript 功能的关系及举例:**

`builtins-definitions.h` 中定义的内置函数直接对应着 JavaScript 语言的核心功能和全局对象的方法。  这些内置函数是 JavaScript 代码执行的基础。

**JavaScript 示例:**

```javascript
// 例如，在 builtins-definitions.h 中可能定义了：
// TFJ(ArrayConstructor, 1)

// 这对应着 JavaScript 中的 Array 构造函数
const arr1 = new Array();
const arr2 = new Array(10);
const arr3 = new Array(1, 2, 3);

// 又例如：
// TFC(StringEqual, StringEqual)

// 这对应着 JavaScript 中的字符串相等比较 (===)
const str1 = "hello";
const str2 = "hello";
const str3 = "world";
console.log(str1 === str2); // true (底层会调用 StringEqual builtin)
console.log(str1 === str3); // false

// 再例如：
// ASM(CallFunction_ReceiverIsAny, CallTrampoline)

// 这涉及到 JavaScript 中函数的调用
function myFunction(a, b) {
  return a + b;
}
myFunction(5, 10); // 底层会使用 CallFunction 相关的 builtin 来执行
```

**代码逻辑推理及假设输入与输出 (有限，因为这是定义文件):**

这个文件本身主要是声明，不包含具体的代码逻辑。代码逻辑存在于 C++、Torque 或汇编的实现文件中。但是，我们可以根据内置函数的名称和参数数量进行一些推断。

**假设:**

假设在 `builtins-definitions.h` 中有以下定义：

```c++
TFC(StringSubstring, StringSubstring)
```

**推理:**

这表示有一个名为 `StringSubstring` 的内置函数，它可能接受一个或多个参数，用于执行字符串的子串操作，类似于 JavaScript 中的 `String.prototype.substring()` 方法。

**假设输入与输出 (基于 JavaScript 行为):**

如果 `StringSubstring` 对应 JavaScript 的 `substring`，那么：

* **输入:**  一个字符串 `"abcdefg"`, 起始索引 `2`, 结束索引 `5`
* **输出:**  子字符串 `"cde"`

**用户常见的编程错误及举例:**

由于 `builtins-definitions.h` 定义的是底层机制，直接与此文件相关的编程错误比较少见。但是，理解这些内置函数背后的原理可以帮助理解一些常见的 JavaScript 错误：

1. **类型错误导致的隐式转换:**  例如，在比较不同类型的变量时，V8 可能会调用 `ToNumber` 等类型转换的内置函数。如果用户没有预期到这种转换，可能会导致错误的结果。

   ```javascript
   console.log(5 == "5");   // true (因为 "5" 被转换为数字 5)
   console.log(5 === "5");  // false (严格相等比较，不进行类型转换)
   ```

2. **`undefined` 或 `null` 导致的错误:**  许多内置函数在处理 `undefined` 或 `null` 时会有特定的行为，例如抛出 `TypeError`。

   ```javascript
   const obj = null;
   // 尝试访问 null 的属性会抛出 TypeError
   // obj.toString(); // 可能会调用与对象操作相关的内置函数，导致错误
   ```

3. **误用 `call` 或 `apply`:**  `CallFunction` 相关的内置函数处理函数调用。错误地使用 `call` 或 `apply` 可能会导致 `this` 指向错误的对象，从而引发问题。

   ```javascript
   function sayHello() {
     console.log("Hello, " + this.name);
   }

   const person = { name: "Alice" };

   sayHello();                // this 指向全局对象 (非严格模式下)
   sayHello.call(person);     // this 指向 person 对象
   sayHello.apply(person);    // this 指向 person 对象
   ```

**总结 (第 1 部分的功能):**

作为第 1 部分，我们可以总结 `v8/src/builtins/builtins-definitions.h` 的核心功能是 **作为 V8 引擎中内置函数的定义和组织中心**。它声明了各种类型的内置函数，并将其组织到不同的层级以优化性能。这个文件是理解 V8 如何实现 JavaScript 核心功能的重要入口点，并且与 JavaScript 的语法和行为有着直接的联系。  如果以 `.tq` 结尾，它将是生成这些定义的 Torque 源代码。

### 提示词
```
这是目录为v8/src/builtins/builtins-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BUILTINS_BUILTINS_DEFINITIONS_H_
#define V8_BUILTINS_BUILTINS_DEFINITIONS_H_

#include "builtins-generated/bytecodes-builtins-list.h"
#include "src/common/globals.h"

// include generated header
#include "torque-generated/builtin-definitions.h"

namespace v8 {
namespace internal {

#ifdef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_TSA(TSA_MACRO, CSA_MACRO, ...) EXPAND(TSA_MACRO(__VA_ARGS__))
#else
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_TSA(TSA_MACRO, CSA_MACRO, ...) EXPAND(CSA_MACRO(__VA_ARGS__))
#endif

// CPP: Builtin in C++. Entered via BUILTIN_EXIT frame.
//      Args: name, formal parameter count
// TFJ: Builtin in Turbofan, with JS linkage (callable as Javascript function).
//      Args: name, formal parameter count, explicit argument names...
// TSJ: Builtin in Turboshaft, with JS linkage (callable as Javascript
//      function).
//      Args: name, formal parameter count, explicit argument names...
// TFS: Builtin in Turbofan, with CodeStub linkage.
//      Args: name, needs context, explicit argument names...
// TFC: Builtin in Turbofan, with CodeStub linkage and custom descriptor.
//      Args: name, interface descriptor
// TSC: Builtin in Turboshaft, with CodeStub linkage and custom descriptor.
//      Args: name, interface descriptor
// TFH: Handlers in Turbofan, with CodeStub linkage.
//      Args: name, interface descriptor
// BCH: Bytecode Handlers, with bytecode dispatch linkage.
//      Args: name, OperandScale, Bytecode
// ASM: Builtin in platform-dependent assembly.
//      Args: name, interface descriptor

// Builtins are additionally split into tiers, where the tier determines the
// distance of the builtins table from the root register within IsolateData.
//
//  - Tier 0 (T0) are guaranteed to be close to the root register and can thus
//    be accessed efficiently root-relative calls (so not, e.g., calls from
//    generated code when short-builtin-calls is on).
//  - T1 builtins have no distance guarantees.
//
// Note, this mechanism works only if the set of T0 builtins is kept as small
// as possible. Please, resist the temptation to add your builtin here unless
// there's a very good reason.
#define BUILTIN_LIST_BASE_TIER0(CPP, TFJ, TFC, TFS, TFH, ASM)               \
  /* Deoptimization entries. */                                             \
  ASM(DeoptimizationEntry_Eager, DeoptimizationEntry)                       \
  ASM(DeoptimizationEntry_Lazy, DeoptimizationEntry)                        \
                                                                            \
  /* GC write barrier. */                                                   \
  TFC(RecordWriteSaveFP, WriteBarrier)                                      \
  TFC(RecordWriteIgnoreFP, WriteBarrier)                                    \
  TFC(EphemeronKeyBarrierSaveFP, WriteBarrier)                              \
  TFC(EphemeronKeyBarrierIgnoreFP, WriteBarrier)                            \
                                                                            \
  /* TODO(ishell): dummy builtin added here just to keep the Tier0 table */ \
  /* size unmodified to avoid unexpected performance implications. */       \
  /* It should be removed. */                                               \
  CPP(DummyBuiltin, kDontAdaptArgumentsSentinel)

#ifdef V8_ENABLE_LEAPTIERING

/* Tiering related builtins
 *
 * These builtins are used for tiering. Some special conventions apply. They,
 * - can be passed to the JSDispatchTable::SetTieringRequest to be executed
 *   instead of the actual JSFunction's code.
 * - need to uninstall themselves using JSDispatchTable::ResetTieringRequest.
 * - need to tail call the actual JSFunction's code.
 *
 * Also, there are lifecycle considerations since the tiering requests are
 * mutually exclusive.
 *
 * */
#define BUILTIN_LIST_BASE_TIERING(TFC)            \
  TFC(FunctionLogNextExecution, JSTrampoline)     \
  TFC(StartMaglevOptimizationJob, JSTrampoline)   \
  TFC(StartTurbofanOptimizationJob, JSTrampoline) \
  TFC(OptimizeMaglevEager, JSTrampoline)          \
  TFC(OptimizeTurbofanEager, JSTrampoline)

#else

#define BUILTIN_LIST_BASE_TIERING(TFC)

#endif

#define BUILTIN_LIST_BASE_TIER1(CPP, TSJ, TFJ, TSC, TFC, TFS, TFH, ASM)        \
  /* GC write barriers */                                                      \
  TFC(IndirectPointerBarrierSaveFP, IndirectPointerWriteBarrier)               \
  TFC(IndirectPointerBarrierIgnoreFP, IndirectPointerWriteBarrier)             \
                                                                               \
  /* Adaptors for CPP builtins with various formal parameter counts. */        \
  /* We split these versions for simplicity (not all architectures have */     \
  /* enough registers for extra CEntry arguments) and speculatively for */     \
  /* performance reasons. */                                                   \
  TFC(AdaptorWithBuiltinExitFrame0, CppBuiltinAdaptor)                         \
  TFC(AdaptorWithBuiltinExitFrame1, CppBuiltinAdaptor)                         \
  TFC(AdaptorWithBuiltinExitFrame2, CppBuiltinAdaptor)                         \
  TFC(AdaptorWithBuiltinExitFrame3, CppBuiltinAdaptor)                         \
  TFC(AdaptorWithBuiltinExitFrame4, CppBuiltinAdaptor)                         \
  TFC(AdaptorWithBuiltinExitFrame5, CppBuiltinAdaptor)                         \
                                                                               \
  /* TSAN support for stores in generated code. */                             \
  IF_TSAN(TFC, TSANRelaxedStore8IgnoreFP, TSANStore)                           \
  IF_TSAN(TFC, TSANRelaxedStore8SaveFP, TSANStore)                             \
  IF_TSAN(TFC, TSANRelaxedStore16IgnoreFP, TSANStore)                          \
  IF_TSAN(TFC, TSANRelaxedStore16SaveFP, TSANStore)                            \
  IF_TSAN(TFC, TSANRelaxedStore32IgnoreFP, TSANStore)                          \
  IF_TSAN(TFC, TSANRelaxedStore32SaveFP, TSANStore)                            \
  IF_TSAN(TFC, TSANRelaxedStore64IgnoreFP, TSANStore)                          \
  IF_TSAN(TFC, TSANRelaxedStore64SaveFP, TSANStore)                            \
  IF_TSAN(TFC, TSANSeqCstStore8IgnoreFP, TSANStore)                            \
  IF_TSAN(TFC, TSANSeqCstStore8SaveFP, TSANStore)                              \
  IF_TSAN(TFC, TSANSeqCstStore16IgnoreFP, TSANStore)                           \
  IF_TSAN(TFC, TSANSeqCstStore16SaveFP, TSANStore)                             \
  IF_TSAN(TFC, TSANSeqCstStore32IgnoreFP, TSANStore)                           \
  IF_TSAN(TFC, TSANSeqCstStore32SaveFP, TSANStore)                             \
  IF_TSAN(TFC, TSANSeqCstStore64IgnoreFP, TSANStore)                           \
  IF_TSAN(TFC, TSANSeqCstStore64SaveFP, TSANStore)                             \
                                                                               \
  /* TSAN support for loads in generated code. */                              \
  IF_TSAN(TFC, TSANRelaxedLoad32IgnoreFP, TSANLoad)                            \
  IF_TSAN(TFC, TSANRelaxedLoad32SaveFP, TSANLoad)                              \
  IF_TSAN(TFC, TSANRelaxedLoad64IgnoreFP, TSANLoad)                            \
  IF_TSAN(TFC, TSANRelaxedLoad64SaveFP, TSANLoad)                              \
                                                                               \
  /* Calls */                                                                  \
  /* ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList) */              \
  ASM(CallFunction_ReceiverIsNullOrUndefined, CallTrampoline)                  \
  ASM(CallFunction_ReceiverIsNotNullOrUndefined, CallTrampoline)               \
  ASM(CallFunction_ReceiverIsAny, CallTrampoline)                              \
  /* ES6 section 9.4.1.1 [[Call]] ( thisArgument, argumentsList) */            \
  ASM(CallBoundFunction, CallTrampoline)                                       \
  /* #sec-wrapped-function-exotic-objects-call-thisargument-argumentslist */   \
  TFC(CallWrappedFunction, CallTrampoline)                                     \
  /* ES6 section 7.3.12 Call(F, V, [argumentsList]) */                         \
  ASM(Call_ReceiverIsNullOrUndefined, CallTrampoline)                          \
  ASM(Call_ReceiverIsNotNullOrUndefined, CallTrampoline)                       \
  ASM(Call_ReceiverIsAny, CallTrampoline)                                      \
  TFC(Call_ReceiverIsNullOrUndefined_Baseline_Compact,                         \
      CallTrampoline_Baseline_Compact)                                         \
  TFC(Call_ReceiverIsNullOrUndefined_Baseline, CallTrampoline_Baseline)        \
  TFC(Call_ReceiverIsNotNullOrUndefined_Baseline_Compact,                      \
      CallTrampoline_Baseline_Compact)                                         \
  TFC(Call_ReceiverIsNotNullOrUndefined_Baseline, CallTrampoline_Baseline)     \
  TFC(Call_ReceiverIsAny_Baseline_Compact, CallTrampoline_Baseline_Compact)    \
  TFC(Call_ReceiverIsAny_Baseline, CallTrampoline_Baseline)                    \
  TFC(Call_ReceiverIsNullOrUndefined_WithFeedback,                             \
      CallTrampoline_WithFeedback)                                             \
  TFC(Call_ReceiverIsNotNullOrUndefined_WithFeedback,                          \
      CallTrampoline_WithFeedback)                                             \
  TFC(Call_ReceiverIsAny_WithFeedback, CallTrampoline_WithFeedback)            \
                                                                               \
  /* ES6 section 9.5.12[[Call]] ( thisArgument, argumentsList ) */             \
  TFC(CallProxy, CallTrampoline)                                               \
  ASM(CallVarargs, CallVarargs)                                                \
  TFC(CallWithSpread, CallWithSpread)                                          \
  TFC(CallWithSpread_Baseline, CallWithSpread_Baseline)                        \
  TFC(CallWithSpread_WithFeedback, CallWithSpread_WithFeedback)                \
  TFC(CallWithArrayLike, CallWithArrayLike)                                    \
  TFC(CallWithArrayLike_WithFeedback, CallWithArrayLike_WithFeedback)          \
  ASM(CallForwardVarargs, CallForwardVarargs)                                  \
  ASM(CallFunctionForwardVarargs, CallForwardVarargs)                          \
  /* Call an API callback via a {FunctionTemplateInfo}, doing appropriate */   \
  /* access and compatible receiver checks. */                                 \
  TFC(CallFunctionTemplate_Generic, CallFunctionTemplateGeneric)               \
  TFC(CallFunctionTemplate_CheckAccess, CallFunctionTemplate)                  \
  TFC(CallFunctionTemplate_CheckCompatibleReceiver, CallFunctionTemplate)      \
  TFC(CallFunctionTemplate_CheckAccessAndCompatibleReceiver,                   \
      CallFunctionTemplate)                                                    \
                                                                               \
  /* Construct */                                                              \
  /* ES6 section 9.2.2 [[Construct]] ( argumentsList, newTarget) */            \
  ASM(ConstructFunction, JSTrampoline)                                         \
  /* ES6 section 9.4.1.2 [[Construct]] (argumentsList, newTarget) */           \
  ASM(ConstructBoundFunction, JSTrampoline)                                    \
  ASM(ConstructedNonConstructable, JSTrampoline)                               \
  /* ES6 section 7.3.13 Construct (F, [argumentsList], [newTarget]) */         \
  ASM(Construct, ConstructStub)                                                \
  ASM(ConstructVarargs, ConstructVarargs)                                      \
  TFC(ConstructWithSpread, ConstructWithSpread)                                \
  TFC(ConstructWithSpread_Baseline, ConstructWithSpread_Baseline)              \
  TFC(ConstructWithSpread_WithFeedback, ConstructWithSpread_WithFeedback)      \
  TFC(ConstructWithArrayLike, ConstructWithArrayLike)                          \
  ASM(ConstructForwardVarargs, ConstructForwardVarargs)                        \
  ASM(ConstructForwardAllArgs, ConstructForwardAllArgs)                        \
  TFC(ConstructForwardAllArgs_Baseline, ConstructForwardAllArgs_Baseline)      \
  TFC(ConstructForwardAllArgs_WithFeedback,                                    \
      ConstructForwardAllArgs_WithFeedback)                                    \
  ASM(ConstructFunctionForwardVarargs, ConstructForwardVarargs)                \
  TFC(Construct_Baseline, Construct_Baseline)                                  \
  TFC(Construct_WithFeedback, Construct_WithFeedback)                          \
  ASM(JSConstructStubGeneric, ConstructStub)                                   \
  ASM(JSBuiltinsConstructStub, ConstructStub)                                  \
  TFC(FastNewObject, FastNewObject)                                            \
  TFS(FastNewClosure, NeedsContext::kYes, kSharedFunctionInfo, kFeedbackCell)  \
  /* ES6 section 9.5.14 [[Construct]] ( argumentsList, newTarget) */           \
  TFC(ConstructProxy, JSTrampoline)                                            \
                                                                               \
  /* Apply and entries */                                                      \
  ASM(JSEntry, JSEntry)                                                        \
  ASM(JSConstructEntry, JSEntry)                                               \
  ASM(JSRunMicrotasksEntry, RunMicrotasksEntry)                                \
  /* Call a JSValue. */                                                        \
  ASM(JSEntryTrampoline, JSEntry)                                              \
  /* Construct a JSValue. */                                                   \
  ASM(JSConstructEntryTrampoline, JSEntry)                                     \
  ASM(ResumeGeneratorTrampoline, ResumeGenerator)                              \
                                                                               \
  /* String helpers */                                                         \
  IF_TSA(TSC, TFC, StringFromCodePointAt, StringAtAsString)                    \
  TFC(StringEqual, StringEqual)                                                \
  TFC(StringGreaterThan, CompareNoContext)                                     \
  TFC(StringGreaterThanOrEqual, CompareNoContext)                              \
  TFC(StringLessThan, CompareNoContext)                                        \
  TFC(StringLessThanOrEqual, CompareNoContext)                                 \
  TFC(StringCompare, CompareNoContext)                                         \
  TFC(StringSubstring, StringSubstring)                                        \
                                                                               \
  /* OrderedHashTable helpers */                                               \
  TFS(OrderedHashTableHealIndex, NeedsContext::kYes, kTable, kIndex)           \
                                                                               \
  /* Interpreter */                                                            \
  /* InterpreterEntryTrampoline dispatches to the interpreter to run a */      \
  /* JSFunction in the form of bytecodes */                                    \
  ASM(InterpreterEntryTrampoline, JSTrampoline)                                \
  ASM(InterpreterEntryTrampolineForProfiling, JSTrampoline)                    \
  ASM(InterpreterForwardAllArgsThenConstruct, ConstructForwardAllArgs)         \
  ASM(InterpreterPushArgsThenCall, InterpreterPushArgsThenCall)                \
  ASM(InterpreterPushUndefinedAndArgsThenCall, InterpreterPushArgsThenCall)    \
  ASM(InterpreterPushArgsThenCallWithFinalSpread, InterpreterPushArgsThenCall) \
  ASM(InterpreterPushArgsThenConstruct, InterpreterPushArgsThenConstruct)      \
  ASM(InterpreterPushArgsThenFastConstructFunction,                            \
      InterpreterPushArgsThenConstruct)                                        \
  ASM(InterpreterPushArgsThenConstructArrayFunction,                           \
      InterpreterPushArgsThenConstruct)                                        \
  ASM(InterpreterPushArgsThenConstructWithFinalSpread,                         \
      InterpreterPushArgsThenConstruct)                                        \
  ASM(InterpreterEnterAtBytecode, Void)                                        \
  ASM(InterpreterEnterAtNextBytecode, Void)                                    \
  ASM(InterpreterOnStackReplacement, OnStackReplacement)                       \
                                                                               \
  /* Baseline Compiler */                                                      \
  ASM(BaselineOutOfLinePrologue, BaselineOutOfLinePrologue)                    \
  ASM(BaselineOutOfLinePrologueDeopt, Void)                                    \
  ASM(BaselineOnStackReplacement, OnStackReplacement)                          \
  ASM(BaselineLeaveFrame, BaselineLeaveFrame)                                  \
  ASM(BaselineOrInterpreterEnterAtBytecode, Void)                              \
  ASM(BaselineOrInterpreterEnterAtNextBytecode, Void)                          \
  ASM(InterpreterOnStackReplacement_ToBaseline, Void)                          \
                                                                               \
  /* Maglev Compiler */                                                        \
  ASM(MaglevOnStackReplacement, OnStackReplacement)                            \
  ASM(MaglevFunctionEntryStackCheck_WithoutNewTarget, Void)                    \
  ASM(MaglevFunctionEntryStackCheck_WithNewTarget, Void)                       \
  ASM(MaglevOptimizeCodeOrTailCallOptimizedCodeSlot,                           \
      MaglevOptimizeCodeOrTailCallOptimizedCodeSlot)                           \
                                                                               \
  /* Code life-cycle */                                                        \
  TFC(CompileLazy, JSTrampoline)                                               \
  /* TODO(saelo): should this use a different descriptor? */                   \
  TFC(CompileLazyDeoptimizedCode, JSTrampoline)                                \
  TFC(InstantiateAsmJs, JSTrampoline)                                          \
  ASM(NotifyDeoptimized, Void)                                                 \
                                                                               \
  BUILTIN_LIST_BASE_TIERING(TFC)                                               \
                                                                               \
  /* Trampolines called when returning from a deoptimization that expects   */ \
  /* to continue in a JavaScript builtin to finish the functionality of a   */ \
  /* an TF-inlined version of builtin that has side-effects.                */ \
  /*                                                                        */ \
  /* The trampolines work as follows:                                       */ \
  /*   1. Trampoline restores input register values that                    */ \
  /*      the builtin expects from a BuiltinContinuationFrame.              */ \
  /*   2. Trampoline tears down BuiltinContinuationFrame.                   */ \
  /*   3. Trampoline jumps to the builtin's address.                        */ \
  /*   4. Builtin executes as if invoked by the frame above it.             */ \
  /*   5. When the builtin returns, execution resumes normally in the       */ \
  /*      calling frame, processing any return result from the JavaScript   */ \
  /*      builtin as if it had called the builtin directly.                 */ \
  /*                                                                        */ \
  /* There are two variants of the stub that differ in their handling of a  */ \
  /* value returned by the next frame deeper on the stack. For LAZY deopts, */ \
  /* the return value (e.g. rax on x64) is explicitly passed as an extra    */ \
  /* stack parameter to the JavaScript builtin by the "WithResult"          */ \
  /* trampoline variant. The plain variant is used in EAGER deopt contexts  */ \
  /* and has no such special handling. */                                      \
  ASM(ContinueToCodeStubBuiltin, ContinueToBuiltin)                            \
  ASM(ContinueToCodeStubBuiltinWithResult, ContinueToBuiltin)                  \
  ASM(ContinueToJavaScriptBuiltin, ContinueToBuiltin)                          \
  ASM(ContinueToJavaScriptBuiltinWithResult, ContinueToBuiltin)                \
                                                                               \
  /* API callback handling */                                                  \
  ASM(CallApiCallbackGeneric, CallApiCallbackGeneric)                          \
  ASM(CallApiCallbackOptimizedNoProfiling, CallApiCallbackOptimized)           \
  ASM(CallApiCallbackOptimized, CallApiCallbackOptimized)                      \
  ASM(CallApiGetter, ApiGetter)                                                \
  TFC(HandleApiCallOrConstruct, JSTrampoline)                                  \
  CPP(HandleApiConstruct, kDontAdaptArgumentsSentinel)                         \
  CPP(HandleApiCallAsFunctionDelegate, kDontAdaptArgumentsSentinel)            \
  CPP(HandleApiCallAsConstructorDelegate, kDontAdaptArgumentsSentinel)         \
                                                                               \
  /* Adapters for Turbofan into runtime */                                     \
  TFC(AllocateInYoungGeneration, Allocate)                                     \
  TFC(AllocateInOldGeneration, Allocate)                                       \
  IF_WASM(TFC, WasmAllocateInYoungGeneration, Allocate)                        \
  IF_WASM(TFC, WasmAllocateInOldGeneration, Allocate)                          \
                                                                               \
  TFC(NewHeapNumber, NewHeapNumber)                                            \
                                                                               \
  /* TurboFan support builtins */                                              \
  TFS(CopyFastSmiOrObjectElements, NeedsContext::kNo, kObject)                 \
  TFC(GrowFastDoubleElements, GrowArrayElements)                               \
  TFC(GrowFastSmiOrObjectElements, GrowArrayElements)                          \
                                                                               \
  /* Debugger */                                                               \
  TFJ(DebugBreakTrampoline, kDontAdaptArgumentsSentinel)                       \
  ASM(RestartFrameTrampoline, RestartFrameTrampoline)                          \
                                                                               \
  /* Type conversions */                                                       \
  TFC(ToNumber, TypeConversion)                                                \
  TFC(ToBigInt, TypeConversion)                                                \
  TFC(ToNumber_Baseline, TypeConversion_Baseline)                              \
  TFC(ToNumeric_Baseline, TypeConversion_Baseline)                             \
  TFC(PlainPrimitiveToNumber, TypeConversionNoContext)                         \
  TFC(ToNumberConvertBigInt, TypeConversion)                                   \
  TFC(ToBigIntConvertNumber, TypeConversion)                                   \
  TFC(Typeof, Typeof)                                                          \
  TFC(Typeof_Baseline, UnaryOp_Baseline)                                       \
  TFC(BigIntToI64, BigIntToI64)                                                \
  TFC(BigIntToI32Pair, BigIntToI32Pair)                                        \
  TFC(I64ToBigInt, I64ToBigInt)                                                \
  TFC(I32PairToBigInt, I32PairToBigInt)                                        \
                                                                               \
  /* Type conversions continuations */                                         \
  TFC(ToBooleanLazyDeoptContinuation, SingleParameterOnStack)                  \
  TFC(MathCeilContinuation, SingleParameterOnStack)                            \
  TFC(MathFloorContinuation, SingleParameterOnStack)                           \
  TFC(MathRoundContinuation, SingleParameterOnStack)                           \
                                                                               \
  /* Handlers */                                                               \
  TFH(KeyedLoadIC_PolymorphicName, LoadWithVector)                             \
  TFH(KeyedStoreIC_Megamorphic, StoreWithVector)                               \
  TFH(DefineKeyedOwnIC_Megamorphic, StoreNoFeedback)                           \
  TFH(LoadGlobalIC_NoFeedback, LoadGlobalNoFeedback)                           \
  TFH(LoadIC_FunctionPrototype, LoadWithVector)                                \
  TFH(LoadIC_StringLength, LoadWithVector)                                     \
  TFH(LoadIC_StringWrapperLength, LoadWithVector)                              \
  TFH(LoadIC_NoFeedback, LoadNoFeedback)                                       \
  TFH(StoreGlobalIC_Slow, StoreWithVector)                                     \
  TFH(StoreIC_NoFeedback, StoreNoFeedback)                                     \
  TFH(DefineNamedOwnIC_NoFeedback, StoreNoFeedback)                            \
  TFH(KeyedLoadIC_SloppyArguments, LoadWithVector)                             \
  TFH(LoadIndexedInterceptorIC, LoadWithVector)                                \
  TFH(KeyedStoreIC_SloppyArguments_InBounds, StoreWithVector)                  \
  TFH(KeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW,               \
      StoreWithVector)                                                         \
  TFH(KeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB,            \
      StoreWithVector)                                                         \
  TFH(KeyedStoreIC_SloppyArguments_NoTransitionHandleCOW, StoreWithVector)     \
  TFH(StoreFastElementIC_InBounds, StoreWithVector)                            \
  TFH(StoreFastElementIC_NoTransitionGrowAndHandleCOW, StoreWithVector)        \
  TFH(StoreFastElementIC_NoTransitionIgnoreTypedArrayOOB, StoreWithVector)     \
  TFH(StoreFastElementIC_NoTransitionHandleCOW, StoreWithVector)               \
  TFH(ElementsTransitionAndStore_InBounds, StoreTransition)                    \
  TFH(ElementsTransitionAndStore_NoTransitionGrowAndHandleCOW,                 \
      StoreTransition)                                                         \
  TFH(ElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB,              \
      StoreTransition)                                                         \
  TFH(ElementsTransitionAndStore_NoTransitionHandleCOW, StoreTransition)       \
  TFH(KeyedHasIC_PolymorphicName, LoadWithVector)                              \
  TFH(KeyedHasIC_SloppyArguments, LoadWithVector)                              \
  TFH(HasIndexedInterceptorIC, LoadWithVector)                                 \
                                                                               \
  /* Microtask helpers */                                                      \
  TFS(EnqueueMicrotask, NeedsContext::kYes, kMicrotask)                        \
  ASM(RunMicrotasksTrampoline, RunMicrotasksEntry)                             \
  TFC(RunMicrotasks, RunMicrotasks)                                            \
                                                                               \
  /* Object property helpers */                                                \
  TFS(HasProperty, NeedsContext::kYes, kObject, kKey)                          \
  TFS(DeleteProperty, NeedsContext::kYes, kObject, kKey, kLanguageMode)        \
  /* ES #sec-copydataproperties */                                             \
  TFS(CopyDataProperties, NeedsContext::kYes, kTarget, kSource)                \
  TFS(SetDataProperties, NeedsContext::kYes, kTarget, kSource)                 \
  TFC(CopyDataPropertiesWithExcludedPropertiesOnStack,                         \
      CopyDataPropertiesWithExcludedPropertiesOnStack)                         \
  TFC(CopyDataPropertiesWithExcludedProperties,                                \
      CopyDataPropertiesWithExcludedProperties)                                \
                                                                               \
  /* Abort */                                                                  \
  TFC(Abort, Abort)                                                            \
  TFC(AbortCSADcheck, Abort)                                                   \
                                                                               \
  /* Built-in functions for Javascript */                                      \
  /* Special internal builtins */                                              \
  CPP(EmptyFunction, kDontAdaptArgumentsSentinel)                              \
  CPP(EmptyFunction1, JSParameterCount(1))                                     \
  CPP(Illegal, kDontAdaptArgumentsSentinel)                                    \
  CPP(IllegalInvocationThrower, kDontAdaptArgumentsSentinel)                   \
  CPP(StrictPoisonPillThrower, JSParameterCount(0))                            \
  CPP(UnsupportedThrower, kDontAdaptArgumentsSentinel)                         \
  TFJ(ReturnReceiver, kJSArgcReceiverSlots, kReceiver)                         \
                                                                               \
  /* AbstractModuleSource */                                                   \
  CPP(AbstractModuleSourceToStringTag, JSParameterCount(0))                    \
                                                                               \
  /* Array */                                                                  \
  TFC(ArrayConstructor, JSTrampoline)                                          \
  TFC(ArrayConstructorImpl, ArrayConstructor)                                  \
  TFC(ArrayNoArgumentConstructor_PackedSmi_DontOverride,                       \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_HoleySmi_DontOverride,                        \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_PackedSmi_DisableAllocationSites,             \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_HoleySmi_DisableAllocationSites,              \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_Packed_DisableAllocationSites,                \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_Holey_DisableAllocationSites,                 \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_PackedDouble_DisableAllocationSites,          \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArrayNoArgumentConstructor_HoleyDouble_DisableAllocationSites,           \
      ArrayNoArgumentConstructor)                                              \
  TFC(ArraySingleArgumentConstructor_PackedSmi_DontOverride,                   \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_HoleySmi_DontOverride,                    \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_PackedSmi_DisableAllocationSites,         \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_HoleySmi_DisableAllocationSites,          \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_Packed_DisableAllocationSites,            \
      ArraySingleArgumentConstructor)
```