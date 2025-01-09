Response:
Let's break down the thought process for analyzing this V8 builtins definition file snippet.

**1. Understanding the Core Purpose:**

The very first lines of the provided text are crucial: `v8/src/builtins/builtins-definitions.h`. This immediately tells us this file is about *built-in* functions within the V8 JavaScript engine. The `.h` extension signifies a header file, typically used in C++ for declarations. This hints that these built-ins are implemented in C++ (or a language that can interact with C++ in V8).

**2. Recognizing the Pattern:**

Scanning the content reveals a consistent pattern of macros like `TFC`, `CPP`, `TFS`, `TFJ`, `TFH`, `ASM`, and `IF_WASM`. Each macro is followed by identifiers. This strongly suggests a declarative format, where each line defines a built-in function.

**3. Deciphering the Macros (Initial Guess and Refinement):**

* **Initial Guess:** The macros likely represent different *types* of built-in functions or different ways they are implemented. For example, `CPP` might stand for "C++ Primitives."  `TF` could be "Torque Function" (though this particular snippet doesn't use `.tq`).

* **Refinement (Based on Context):**  The comment "if v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码" confirms the existence of Torque. Since this snippet *doesn't* end in `.tq`, the macros are likely *not* Torque definitions in this instance. The presence of `CPP` further strengthens the C++ implementation idea. The other macros are harder to guess initially but context (like the arguments they take) will provide clues.

**4. Identifying Function Names:**

The second argument to each macro (or sometimes the first, depending on the macro) appears to be the name of the built-in function. Examples: `ArraySingleArgumentConstructor`, `ArrayConcat`, `ArrayPrototypeFill`, `ConsoleLog`, `DateConstructor`, `FunctionPrototypeApply`, etc. These names are very similar to standard JavaScript built-in functions and constructors.

**5. Connecting to JavaScript Functionality:**

The presence of familiar JavaScript names strongly suggests a direct link between these definitions and the JavaScript language. This leads to the idea of illustrating with JavaScript examples. For instance, seeing `ArrayPrototypePush` immediately brings the `.push()` method to mind.

**6. Analyzing Macro Arguments:**

The arguments following the function name within the macros likely provide additional information about the built-in.

* `kDontAdaptArgumentsSentinel`: This likely indicates something about how arguments are handled (or not handled) when the built-in is called.
* `NeedsContext::kYes`: Suggests the function requires access to the V8 context (e.g., for memory management, accessing global objects).
* `kElements`, `kSearchElement`, `kLength`, `kFromIndex`:  These parameter names clearly relate to array operations like `includes` and `indexOf`.
* `JSParameterCount(n)`: Explicitly defines the expected number of arguments for a built-in.
* `kJSArgcReceiverSlots`:  Likely relates to the number of arguments passed to the function, including the `this` receiver.

**7. Grouping by Category:**

The code itself is already somewhat grouped by object type (e.g., "Array", "ArrayBuffer", "AsyncFunction", "BigInt"). This natural grouping aids in understanding the file's structure and functionality.

**8. Inferring Functionality and Potential Errors:**

By recognizing the JavaScript function names and understanding the purpose of the built-ins, it becomes possible to infer their behavior and potential user errors. For example:

* `ArrayPrototypePush`:  Pushing elements onto an array. A common error is pushing onto a non-array object.
* `DateConstructor`: Creating `Date` objects. Errors could involve invalid date formats.
* `ConsoleLog`: Logging to the console. No direct errors, but misuse could lead to performance problems in tight loops.

**9. Addressing Specific Constraints:**

* **`.tq` Extension:** The prompt explicitly asks about this. It's important to acknowledge that this snippet is *not* Torque but that Torque is another way to define built-ins in V8.
* **Code Logic and I/O:** Since this is a *definition* file, not implementation code, there's no real "code logic" to trace with inputs and outputs in the traditional sense. The "inputs" are the arguments passed when the JavaScript function is called, and the "outputs" are the return values or side effects.
* **Part of a Larger Whole:**  The prompt mentions "Part 2 of 6." This reinforces the idea that this file is a component within a larger system of built-in definitions.

**10. Synthesizing the Summary:**

Finally, the gathered information needs to be synthesized into a concise summary. Key points to include:

* Purpose of the file (declarations of built-in functions).
* Implementation languages (primarily C++ in this snippet).
* Connection to JavaScript features.
* Organization by object type.
* The role of macros.
* The relationship to Torque (if applicable).

**Self-Correction/Refinement During the Process:**

* **Initial thought about `TF`:** Initially, I might have incorrectly guessed it was related to Torque. However, seeing `CPP` more frequently and the lack of `.tq` ending would lead me to revise that guess. The prompt itself clarifies the `.tq` case.
* **Over-interpreting macro arguments:** I might initially try to assign very specific technical meanings to every macro argument. However, focusing on the *types* of information they convey (e.g., argument handling, context needs, specific parameters) is more helpful at this stage.
* **Focusing too much on implementation details:**  Since this is a *definition* file, I need to avoid speculating too deeply about the low-level C++ implementation. The focus should be on the *interface* between JavaScript and the built-ins.
好的，这是对提供的V8源代码片段的功能归纳：

**功能归纳：**

这段代码是V8 JavaScript引擎中定义内置函数（built-ins）的一部分，具体来说是 `v8/src/builtins/builtins-definitions.h` 文件的摘录。 这个头文件使用一系列宏（例如 `TFC`, `CPP`, `TFS`, `TFJ`, `TFH`, `ASM`, `IF_WASM`）来声明V8引擎提供的各种内置功能。

**核心功能点：**

1. **声明内置函数:**  这个文件是声明各种内置函数的地方，这些函数是JavaScript语言的基础组成部分，例如数组操作、日期处理、控制台输出等等。
2. **定义函数签名和属性:**  通过不同的宏及其参数，定义了每个内置函数的签名（例如，需要的参数）以及可能的属性（例如，是否需要上下文 `NeedsContext::kYes`）。
3. **映射到C++或Torque实现:**  每个宏最终会映射到一个具体的C++函数 (`CPP`) 或 Torque函数 (`TFC`, `TFS`, `TFJ` 等)。虽然这段代码没有 `.tq` 结尾，但它确实包含了一些看起来像 Torque 宏的声明（`TFC`, `TFS`, `TFJ`）。  如果整个文件以 `.tq` 结尾，那么可以肯定它主要由 Torque 代码构成。
4. **组织内置函数:** 代码按照相关的功能或对象进行组织，例如 `Array`, `ArrayBuffer`, `AsyncFunction`, `BigInt`, `Console`, `Date` 等等，方便管理和查找。
5. **涵盖多种内置类型:**  代码涵盖了多种JavaScript内置对象和功能，包括：
    * **数组操作:**  构造函数、`fill`, `includes`, `indexOf`, `pop`, `push`, `shift`, `unshift`, 迭代器相关方法等。
    * **ArrayBuffer:** 构造函数、`slice`, `resize`, `transfer` 等。
    * **异步函数:**  `enter`, `reject`, `resolve`, `await` 等。
    * **BigInt:** 构造函数及相关方法。
    * **CallSite:** 用于堆栈跟踪的方法。
    * **Console:**  各种控制台输出方法 (`log`, `error`, `warn` 等)。
    * **DataView:** 构造函数。
    * **Date:** 构造函数以及各种 `get` 和 `set` 方法。
    * **DisposableStack/AsyncDisposableStack:**  用于资源管理的栈结构。
    * **Error:** 构造函数和相关方法。
    * **Function:** 构造函数、`apply`, `bind`, `call`, `toString`。
    * **Generator/Async:** 生成器和异步函数的构造和控制方法。
    * **Iterator Protocol:** 迭代器相关的辅助函数。
    * **Global object:** 全局函数，如 `decodeURI`, `encodeURI`, `eval`, `isFinite`, `isNaN`。
    * **JSON:** `parse`, `stringify` 等。
    * **ICs (Inline Caches):**  用于优化属性访问和方法调用的机制。
    * **IterableToList:** 将可迭代对象转换为列表的函数。
    * **Map:** `Map` 对象的构造函数和原型方法。
    * **Number:** `Number` 原型的方法。
    * **Binary Operators:**  带反馈收集的二元运算符。

**与JavaScript的关系及示例：**

这些定义直接对应于开发者在JavaScript中使用的内置对象和方法。

**示例 (Array):**

```javascript
// 对应于 TFC(ArraySingleArgumentConstructor_Holey_DisableAllocationSites, ArraySingleArgumentConstructor) 和 Array 的构造
const arr1 = new Array(5); // 创建一个长度为 5 的空数组

// 对应于 CPP(ArrayPush, kDontAdaptArgumentsSentinel) 和 Array.prototype.push
arr1.push(1);
arr1.push(2);
console.log(arr1); // 输出: [ <5 empty items>, 1, 2 ]

// 对应于 TFS(ArrayIncludesSmi, NeedsContext::kYes, kElements, kSearchElement, kLength, kFromIndex) 和 Array.prototype.includes
console.log(arr1.includes(1)); // 输出: true
```

**示例 (Console):**

```javascript
// 对应于 CPP(ConsoleLog, kDontAdaptArgumentsSentinel) 和 console.log
console.log("Hello, world!");

// 对应于 CPP(ConsoleWarn, kDontAdaptArgumentsSentinel) 和 console.warn
console.warn("This is a warning.");
```

**代码逻辑推理（有限，因为是定义文件）：**

虽然这是一个定义文件，不包含具体的代码实现，但可以根据函数名和参数推断其大致逻辑。

**假设输入与输出 (以 `ArrayIncludesSmi` 为例):**

* **假设输入:**
    * `elements`: 一个包含小型整数（Smi）的数组，例如 `[1, 2, 3, 4, 5]`
    * `searchElement`: 要查找的元素，例如 `3`
    * `length`: 数组的有效长度，例如 `5`
    * `fromIndex`: 开始搜索的索引，例如 `0`
* **预期输出:** `true` (因为 `3` 存在于数组中)

**假设输入与输出 (以 `ConsoleLog` 为例):**

* **假设输入:** 任意数量的参数，例如 `"Logging a message"`, `123`, `{ name: "test" }`
* **预期输出:**  这些参数会按照一定的格式输出到控制台。

**用户常见的编程错误：**

* **对非数组对象使用数组方法:** 例如，尝试在普通对象上调用 `push`。
   ```javascript
   const obj = {};
   // obj.push(1); // TypeError: obj.push is not a function
   ```
* **日期对象的使用错误:** 例如，不正确地使用 `Date` 构造函数或 `setDate` 等方法导致日期不符合预期。
   ```javascript
   const date = new Date('invalid date');
   console.log(date); // 输出: Invalid Date
   ```
* **控制台方法滥用:** 在生产环境代码中过度使用 `console.log` 等方法可能会影响性能。

**总结:**

这段代码是V8引擎的核心组成部分，它声明了大量用于实现JavaScript语言功能的内置函数。通过这些声明，V8能够将JavaScript代码高效地转换为机器码并执行。这段代码涵盖了各种内置对象和方法，为开发者提供了丰富的API来构建复杂的JavaScript应用。尽管是定义文件，我们仍然可以从中推断出函数的功能和潜在的使用场景，以及用户可能遇到的编程错误。

Prompt: 
```
这是目录为v8/src/builtins/builtins-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
                                      \
  TFC(ArraySingleArgumentConstructor_Holey_DisableAllocationSites,             \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_PackedDouble_DisableAllocationSites,      \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArraySingleArgumentConstructor_HoleyDouble_DisableAllocationSites,       \
      ArraySingleArgumentConstructor)                                          \
  TFC(ArrayNArgumentsConstructor, ArrayNArgumentsConstructor)                  \
  CPP(ArrayConcat, kDontAdaptArgumentsSentinel)                                \
  /* ES6 #sec-array.prototype.fill */                                          \
  CPP(ArrayPrototypeFill, kDontAdaptArgumentsSentinel)                         \
  /* ES7 #sec-array.prototype.includes */                                      \
  TFS(ArrayIncludesSmi, NeedsContext::kYes, kElements, kSearchElement,         \
      kLength, kFromIndex)                                                     \
  TFS(ArrayIncludesSmiOrObject, NeedsContext::kYes, kElements, kSearchElement, \
      kLength, kFromIndex)                                                     \
  TFS(ArrayIncludesPackedDoubles, NeedsContext::kYes, kElements,               \
      kSearchElement, kLength, kFromIndex)                                     \
  TFS(ArrayIncludesHoleyDoubles, NeedsContext::kYes, kElements,                \
      kSearchElement, kLength, kFromIndex)                                     \
  TFJ(ArrayIncludes, kDontAdaptArgumentsSentinel)                              \
  /* ES6 #sec-array.prototype.indexof */                                       \
  TFS(ArrayIndexOfSmi, NeedsContext::kYes, kElements, kSearchElement, kLength, \
      kFromIndex)                                                              \
  TFS(ArrayIndexOfSmiOrObject, NeedsContext::kYes, kElements, kSearchElement,  \
      kLength, kFromIndex)                                                     \
  TFS(ArrayIndexOfPackedDoubles, NeedsContext::kYes, kElements,                \
      kSearchElement, kLength, kFromIndex)                                     \
  TFS(ArrayIndexOfHoleyDoubles, NeedsContext::kYes, kElements, kSearchElement, \
      kLength, kFromIndex)                                                     \
  TFJ(ArrayIndexOf, kDontAdaptArgumentsSentinel)                               \
  /* ES6 #sec-array.prototype.pop */                                           \
  CPP(ArrayPop, kDontAdaptArgumentsSentinel)                                   \
  TFJ(ArrayPrototypePop, kDontAdaptArgumentsSentinel)                          \
  /* ES6 #sec-array.prototype.push */                                          \
  CPP(ArrayPush, kDontAdaptArgumentsSentinel)                                  \
  TFJ(ArrayPrototypePush, kDontAdaptArgumentsSentinel)                         \
  /* ES6 #sec-array.prototype.shift */                                         \
  CPP(ArrayShift, kDontAdaptArgumentsSentinel)                                 \
  /* ES6 #sec-array.prototype.unshift */                                       \
  CPP(ArrayUnshift, kDontAdaptArgumentsSentinel)                               \
  /* Support for Array.from and other array-copying idioms */                  \
  TFS(CloneFastJSArray, NeedsContext::kYes, kSource)                           \
  TFS(CloneFastJSArrayFillingHoles, NeedsContext::kYes, kSource)               \
  TFS(ExtractFastJSArray, NeedsContext::kYes, kSource, kBegin, kCount)         \
  TFS(CreateArrayFromSlowBoilerplate, NeedsContext::kYes, kFeedbackVector,     \
      kSlot, kBoilerplateDescriptor, kFlags)                                   \
  TFS(CreateObjectFromSlowBoilerplate, NeedsContext::kYes, kFeedbackVector,    \
      kSlot, kBoilerplateDescriptor, kFlags)                                   \
  TFC(CreateArrayFromSlowBoilerplateHelper, CreateFromSlowBoilerplateHelper)   \
  TFC(CreateObjectFromSlowBoilerplateHelper, CreateFromSlowBoilerplateHelper)  \
  /* ES6 #sec-array.prototype.entries */                                       \
  TFJ(ArrayPrototypeEntries, kJSArgcReceiverSlots, kReceiver)                  \
  /* ES6 #sec-array.prototype.keys */                                          \
  TFJ(ArrayPrototypeKeys, kJSArgcReceiverSlots, kReceiver)                     \
  /* ES6 #sec-array.prototype.values */                                        \
  TFJ(ArrayPrototypeValues, kJSArgcReceiverSlots, kReceiver)                   \
  /* ES6 #sec-%arrayiteratorprototype%.next */                                 \
  TFJ(ArrayIteratorPrototypeNext, kJSArgcReceiverSlots, kReceiver)             \
                                                                               \
  /* ArrayBuffer */                                                            \
  /* ES #sec-arraybuffer-constructor */                                        \
  CPP(ArrayBufferConstructor, JSParameterCount(1))                             \
  CPP(ArrayBufferConstructor_DoNotInitialize, kDontAdaptArgumentsSentinel)     \
  CPP(ArrayBufferPrototypeSlice, JSParameterCount(2))                          \
  /* https://tc39.es/proposal-resizablearraybuffer/ */                         \
  CPP(ArrayBufferPrototypeResize, JSParameterCount(1))                         \
  /* https://tc39.es/proposal-arraybuffer-transfer/ */                         \
  CPP(ArrayBufferPrototypeTransfer, kDontAdaptArgumentsSentinel)               \
  CPP(ArrayBufferPrototypeTransferToFixedLength, kDontAdaptArgumentsSentinel)  \
                                                                               \
  /* AsyncFunction */                                                          \
  TFS(AsyncFunctionEnter, NeedsContext::kYes, kClosure, kReceiver)             \
  TFS(AsyncFunctionReject, NeedsContext::kYes, kAsyncFunctionObject, kReason)  \
  TFS(AsyncFunctionResolve, NeedsContext::kYes, kAsyncFunctionObject, kValue)  \
  TFC(AsyncFunctionLazyDeoptContinuation, AsyncFunctionStackParameter)         \
  TFS(AsyncFunctionAwait, NeedsContext::kYes, kAsyncFunctionObject, kValue)    \
  TFJ(AsyncFunctionAwaitRejectClosure, kJSArgcReceiverSlots + 1, kReceiver,    \
      kSentError)                                                              \
  TFJ(AsyncFunctionAwaitResolveClosure, kJSArgcReceiverSlots + 1, kReceiver,   \
      kSentValue)                                                              \
                                                                               \
  /* BigInt */                                                                 \
  CPP(BigIntConstructor, kDontAdaptArgumentsSentinel)                          \
  CPP(BigIntAsUintN, kDontAdaptArgumentsSentinel)                              \
  CPP(BigIntAsIntN, kDontAdaptArgumentsSentinel)                               \
  CPP(BigIntPrototypeToLocaleString, kDontAdaptArgumentsSentinel)              \
  CPP(BigIntPrototypeToString, kDontAdaptArgumentsSentinel)                    \
  CPP(BigIntPrototypeValueOf, kDontAdaptArgumentsSentinel)                     \
                                                                               \
  /* CallSite */                                                               \
  CPP(CallSitePrototypeGetColumnNumber, JSParameterCount(0))                   \
  CPP(CallSitePrototypeGetEnclosingColumnNumber, JSParameterCount(0))          \
  CPP(CallSitePrototypeGetEnclosingLineNumber, JSParameterCount(0))            \
  CPP(CallSitePrototypeGetEvalOrigin, JSParameterCount(0))                     \
  CPP(CallSitePrototypeGetFileName, JSParameterCount(0))                       \
  CPP(CallSitePrototypeGetFunction, JSParameterCount(0))                       \
  CPP(CallSitePrototypeGetFunctionName, JSParameterCount(0))                   \
  CPP(CallSitePrototypeGetLineNumber, JSParameterCount(0))                     \
  CPP(CallSitePrototypeGetMethodName, JSParameterCount(0))                     \
  CPP(CallSitePrototypeGetPosition, JSParameterCount(0))                       \
  CPP(CallSitePrototypeGetPromiseIndex, JSParameterCount(0))                   \
  CPP(CallSitePrototypeGetScriptHash, JSParameterCount(0))                     \
  CPP(CallSitePrototypeGetScriptNameOrSourceURL, JSParameterCount(0))          \
  CPP(CallSitePrototypeGetThis, JSParameterCount(0))                           \
  CPP(CallSitePrototypeGetTypeName, JSParameterCount(0))                       \
  CPP(CallSitePrototypeIsAsync, JSParameterCount(0))                           \
  CPP(CallSitePrototypeIsConstructor, JSParameterCount(0))                     \
  CPP(CallSitePrototypeIsEval, JSParameterCount(0))                            \
  CPP(CallSitePrototypeIsNative, JSParameterCount(0))                          \
  CPP(CallSitePrototypeIsPromiseAll, JSParameterCount(0))                      \
  CPP(CallSitePrototypeIsToplevel, JSParameterCount(0))                        \
  CPP(CallSitePrototypeToString, JSParameterCount(0))                          \
                                                                               \
  /* Console */                                                                \
  CPP(ConsoleDebug, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleError, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleInfo, kDontAdaptArgumentsSentinel)                                \
  CPP(ConsoleLog, kDontAdaptArgumentsSentinel)                                 \
  CPP(ConsoleWarn, kDontAdaptArgumentsSentinel)                                \
  CPP(ConsoleDir, kDontAdaptArgumentsSentinel)                                 \
  CPP(ConsoleDirXml, kDontAdaptArgumentsSentinel)                              \
  CPP(ConsoleTable, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleTrace, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleGroup, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleGroupCollapsed, kDontAdaptArgumentsSentinel)                      \
  CPP(ConsoleGroupEnd, kDontAdaptArgumentsSentinel)                            \
  CPP(ConsoleClear, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleCount, kDontAdaptArgumentsSentinel)                               \
  CPP(ConsoleCountReset, kDontAdaptArgumentsSentinel)                          \
  CPP(ConsoleAssert, kDontAdaptArgumentsSentinel)                              \
  CPP(ConsoleProfile, kDontAdaptArgumentsSentinel)                             \
  CPP(ConsoleProfileEnd, kDontAdaptArgumentsSentinel)                          \
  CPP(ConsoleTime, kDontAdaptArgumentsSentinel)                                \
  CPP(ConsoleTimeLog, kDontAdaptArgumentsSentinel)                             \
  CPP(ConsoleTimeEnd, kDontAdaptArgumentsSentinel)                             \
  CPP(ConsoleTimeStamp, kDontAdaptArgumentsSentinel)                           \
  CPP(ConsoleContext, kDontAdaptArgumentsSentinel)                             \
                                                                               \
  /* DataView */                                                               \
  /* ES #sec-dataview-constructor */                                           \
  CPP(DataViewConstructor, kDontAdaptArgumentsSentinel)                        \
                                                                               \
  /* Date */                                                                   \
  /* ES #sec-date-constructor */                                               \
  CPP(DateConstructor, kDontAdaptArgumentsSentinel)                            \
  /* ES6 #sec-date.prototype.getdate */                                        \
  TFJ(DatePrototypeGetDate, kJSArgcReceiverSlots, kReceiver)                   \
  /* ES6 #sec-date.prototype.getday */                                         \
  TFJ(DatePrototypeGetDay, kJSArgcReceiverSlots, kReceiver)                    \
  /* ES6 #sec-date.prototype.getfullyear */                                    \
  TFJ(DatePrototypeGetFullYear, kJSArgcReceiverSlots, kReceiver)               \
  /* ES6 #sec-date.prototype.gethours */                                       \
  TFJ(DatePrototypeGetHours, kJSArgcReceiverSlots, kReceiver)                  \
  /* ES6 #sec-date.prototype.getmilliseconds */                                \
  TFJ(DatePrototypeGetMilliseconds, kJSArgcReceiverSlots, kReceiver)           \
  /* ES6 #sec-date.prototype.getminutes */                                     \
  TFJ(DatePrototypeGetMinutes, kJSArgcReceiverSlots, kReceiver)                \
  /* ES6 #sec-date.prototype.getmonth */                                       \
  TFJ(DatePrototypeGetMonth, kJSArgcReceiverSlots, kReceiver)                  \
  /* ES6 #sec-date.prototype.getseconds */                                     \
  TFJ(DatePrototypeGetSeconds, kJSArgcReceiverSlots, kReceiver)                \
  /* ES6 #sec-date.prototype.gettime */                                        \
  TFJ(DatePrototypeGetTime, kJSArgcReceiverSlots, kReceiver)                   \
  /* ES6 #sec-date.prototype.gettimezoneoffset */                              \
  TFJ(DatePrototypeGetTimezoneOffset, kJSArgcReceiverSlots, kReceiver)         \
  /* ES6 #sec-date.prototype.getutcdate */                                     \
  TFJ(DatePrototypeGetUTCDate, kJSArgcReceiverSlots, kReceiver)                \
  /* ES6 #sec-date.prototype.getutcday */                                      \
  TFJ(DatePrototypeGetUTCDay, kJSArgcReceiverSlots, kReceiver)                 \
  /* ES6 #sec-date.prototype.getutcfullyear */                                 \
  TFJ(DatePrototypeGetUTCFullYear, kJSArgcReceiverSlots, kReceiver)            \
  /* ES6 #sec-date.prototype.getutchours */                                    \
  TFJ(DatePrototypeGetUTCHours, kJSArgcReceiverSlots, kReceiver)               \
  /* ES6 #sec-date.prototype.getutcmilliseconds */                             \
  TFJ(DatePrototypeGetUTCMilliseconds, kJSArgcReceiverSlots, kReceiver)        \
  /* ES6 #sec-date.prototype.getutcminutes */                                  \
  TFJ(DatePrototypeGetUTCMinutes, kJSArgcReceiverSlots, kReceiver)             \
  /* ES6 #sec-date.prototype.getutcmonth */                                    \
  TFJ(DatePrototypeGetUTCMonth, kJSArgcReceiverSlots, kReceiver)               \
  /* ES6 #sec-date.prototype.getutcseconds */                                  \
  TFJ(DatePrototypeGetUTCSeconds, kJSArgcReceiverSlots, kReceiver)             \
  /* ES6 #sec-date.prototype.valueof */                                        \
  TFJ(DatePrototypeValueOf, kJSArgcReceiverSlots, kReceiver)                   \
  /* ES6 #sec-date.prototype-@@toprimitive */                                  \
  TFJ(DatePrototypeToPrimitive, kJSArgcReceiverSlots + 1, kReceiver, kHint)    \
  CPP(DatePrototypeGetYear, JSParameterCount(0))                               \
  CPP(DatePrototypeSetYear, kDontAdaptArgumentsSentinel)                       \
  CPP(DateNow, kDontAdaptArgumentsSentinel)                                    \
  CPP(DateParse, kDontAdaptArgumentsSentinel)                                  \
  CPP(DatePrototypeSetDate, kDontAdaptArgumentsSentinel)                       \
  CPP(DatePrototypeSetFullYear, kDontAdaptArgumentsSentinel)                   \
  CPP(DatePrototypeSetHours, kDontAdaptArgumentsSentinel)                      \
  CPP(DatePrototypeSetMilliseconds, kDontAdaptArgumentsSentinel)               \
  CPP(DatePrototypeSetMinutes, kDontAdaptArgumentsSentinel)                    \
  CPP(DatePrototypeSetMonth, kDontAdaptArgumentsSentinel)                      \
  CPP(DatePrototypeSetSeconds, kDontAdaptArgumentsSentinel)                    \
  CPP(DatePrototypeSetTime, kDontAdaptArgumentsSentinel)                       \
  CPP(DatePrototypeSetUTCDate, kDontAdaptArgumentsSentinel)                    \
  CPP(DatePrototypeSetUTCFullYear, kDontAdaptArgumentsSentinel)                \
  CPP(DatePrototypeSetUTCHours, kDontAdaptArgumentsSentinel)                   \
  CPP(DatePrototypeSetUTCMilliseconds, kDontAdaptArgumentsSentinel)            \
  CPP(DatePrototypeSetUTCMinutes, kDontAdaptArgumentsSentinel)                 \
  CPP(DatePrototypeSetUTCMonth, kDontAdaptArgumentsSentinel)                   \
  CPP(DatePrototypeSetUTCSeconds, kDontAdaptArgumentsSentinel)                 \
  CPP(DatePrototypeToDateString, kDontAdaptArgumentsSentinel)                  \
  CPP(DatePrototypeToISOString, kDontAdaptArgumentsSentinel)                   \
  CPP(DatePrototypeToUTCString, kDontAdaptArgumentsSentinel)                   \
  CPP(DatePrototypeToString, kDontAdaptArgumentsSentinel)                      \
  CPP(DatePrototypeToTimeString, kDontAdaptArgumentsSentinel)                  \
  CPP(DatePrototypeToJson, kDontAdaptArgumentsSentinel)                        \
  CPP(DateUTC, kDontAdaptArgumentsSentinel)                                    \
                                                                               \
  /* DisposabeStack*/                                                          \
  CPP(DisposableStackConstructor, kDontAdaptArgumentsSentinel)                 \
  CPP(DisposableStackPrototypeUse, JSParameterCount(1))                        \
  CPP(DisposableStackPrototypeDispose, JSParameterCount(0))                    \
  CPP(DisposableStackPrototypeGetDisposed, JSParameterCount(0))                \
  CPP(DisposableStackPrototypeAdopt, JSParameterCount(2))                      \
  CPP(DisposableStackPrototypeDefer, JSParameterCount(1))                      \
  CPP(DisposableStackPrototypeMove, JSParameterCount(0))                       \
                                                                               \
  /* Async DisposabeStack*/                                                    \
  CPP(AsyncDisposableStackOnFulfilled, JSParameterCount(0))                    \
  CPP(AsyncDisposableStackOnRejected, JSParameterCount(0))                     \
  CPP(AsyncDisposeFromSyncDispose, JSParameterCount(0))                        \
  CPP(AsyncDisposableStackConstructor, kDontAdaptArgumentsSentinel)            \
  CPP(AsyncDisposableStackPrototypeUse, JSParameterCount(1))                   \
  CPP(AsyncDisposableStackPrototypeDisposeAsync, JSParameterCount(0))          \
  CPP(AsyncDisposableStackPrototypeGetDisposed, JSParameterCount(0))           \
  CPP(AsyncDisposableStackPrototypeAdopt, JSParameterCount(2))                 \
  CPP(AsyncDisposableStackPrototypeDefer, JSParameterCount(1))                 \
  CPP(AsyncDisposableStackPrototypeMove, JSParameterCount(0))                  \
                                                                               \
  /* Error */                                                                  \
  CPP(ErrorConstructor, kDontAdaptArgumentsSentinel)                           \
  CPP(ErrorCaptureStackTrace, kDontAdaptArgumentsSentinel)                     \
  CPP(ErrorPrototypeToString, JSParameterCount(0))                             \
                                                                               \
  /* Function */                                                               \
  CPP(FunctionConstructor, kDontAdaptArgumentsSentinel)                        \
  ASM(FunctionPrototypeApply, JSTrampoline)                                    \
  CPP(FunctionPrototypeBind, kDontAdaptArgumentsSentinel)                      \
  IF_WASM(CPP, WebAssemblyFunctionPrototypeBind, kDontAdaptArgumentsSentinel)  \
  ASM(FunctionPrototypeCall, JSTrampoline)                                     \
  /* ES6 #sec-function.prototype.tostring */                                   \
  CPP(FunctionPrototypeToString, kDontAdaptArgumentsSentinel)                  \
                                                                               \
  /* Belongs to Objects but is a dependency of GeneratorPrototypeResume */     \
  TFS(CreateIterResultObject, NeedsContext::kYes, kValue, kDone)               \
                                                                               \
  /* Generator and Async */                                                    \
  TFS(CreateGeneratorObject, NeedsContext::kYes, kClosure, kReceiver)          \
  CPP(GeneratorFunctionConstructor, kDontAdaptArgumentsSentinel)               \
  /* ES6 #sec-generator.prototype.next */                                      \
  TFJ(GeneratorPrototypeNext, kDontAdaptArgumentsSentinel)                     \
  /* ES6 #sec-generator.prototype.return */                                    \
  TFJ(GeneratorPrototypeReturn, kDontAdaptArgumentsSentinel)                   \
  /* ES6 #sec-generator.prototype.throw */                                     \
  TFJ(GeneratorPrototypeThrow, kDontAdaptArgumentsSentinel)                    \
  CPP(AsyncFunctionConstructor, kDontAdaptArgumentsSentinel)                   \
  TFC(SuspendGeneratorBaseline, SuspendGeneratorBaseline)                      \
  TFC(ResumeGeneratorBaseline, ResumeGeneratorBaseline)                        \
                                                                               \
  /* Iterator Protocol */                                                      \
  TFC(GetIteratorWithFeedbackLazyDeoptContinuation, GetIteratorStackParameter) \
  TFC(CallIteratorWithFeedbackLazyDeoptContinuation, SingleParameterOnStack)   \
                                                                               \
  /* Global object */                                                          \
  CPP(GlobalDecodeURI, kDontAdaptArgumentsSentinel)                            \
  CPP(GlobalDecodeURIComponent, kDontAdaptArgumentsSentinel)                   \
  CPP(GlobalEncodeURI, kDontAdaptArgumentsSentinel)                            \
  CPP(GlobalEncodeURIComponent, kDontAdaptArgumentsSentinel)                   \
  CPP(GlobalEscape, kDontAdaptArgumentsSentinel)                               \
  CPP(GlobalUnescape, kDontAdaptArgumentsSentinel)                             \
  CPP(GlobalEval, kDontAdaptArgumentsSentinel)                                 \
  /* ES6 #sec-isfinite-number */                                               \
  TFJ(GlobalIsFinite, kJSArgcReceiverSlots + 1, kReceiver, kNumber)            \
  /* ES6 #sec-isnan-number */                                                  \
  TFJ(GlobalIsNaN, kJSArgcReceiverSlots + 1, kReceiver, kNumber)               \
                                                                               \
  /* JSON */                                                                   \
  CPP(JsonParse, kDontAdaptArgumentsSentinel)                                  \
  CPP(JsonStringify, JSParameterCount(3))                                      \
  CPP(JsonRawJson, JSParameterCount(1))                                        \
  CPP(JsonIsRawJson, JSParameterCount(1))                                      \
                                                                               \
  /* ICs */                                                                    \
  TFH(LoadIC, LoadWithVector)                                                  \
  TFH(LoadIC_Megamorphic, LoadWithVector)                                      \
  TFH(LoadIC_Noninlined, LoadWithVector)                                       \
  TFH(LoadICTrampoline, Load)                                                  \
  TFH(LoadICBaseline, LoadBaseline)                                            \
  TFH(LoadICTrampoline_Megamorphic, Load)                                      \
  TFH(LoadSuperIC, LoadWithReceiverAndVector)                                  \
  TFH(LoadSuperICBaseline, LoadWithReceiverBaseline)                           \
  TFH(KeyedLoadIC, KeyedLoadWithVector)                                        \
  TFH(EnumeratedKeyedLoadIC, EnumeratedKeyedLoad)                              \
  TFH(KeyedLoadIC_Megamorphic, KeyedLoadWithVector)                            \
  TFH(KeyedLoadICTrampoline, KeyedLoad)                                        \
  TFH(KeyedLoadICBaseline, KeyedLoadBaseline)                                  \
  TFH(EnumeratedKeyedLoadICBaseline, EnumeratedKeyedLoadBaseline)              \
  TFH(KeyedLoadICTrampoline_Megamorphic, KeyedLoad)                            \
  TFH(StoreGlobalIC, StoreGlobalWithVector)                                    \
  TFH(StoreGlobalICTrampoline, StoreGlobal)                                    \
  TFH(StoreGlobalICBaseline, StoreGlobalBaseline)                              \
  TFH(StoreIC, StoreWithVector)                                                \
  TFH(StoreIC_Megamorphic, StoreWithVector)                                    \
  TFH(StoreICTrampoline, Store)                                                \
  TFH(StoreICTrampoline_Megamorphic, Store)                                    \
  TFH(StoreICBaseline, StoreBaseline)                                          \
  TFH(DefineNamedOwnIC, StoreWithVector)                                       \
  TFH(DefineNamedOwnICTrampoline, Store)                                       \
  TFH(DefineNamedOwnICBaseline, StoreBaseline)                                 \
  TFH(KeyedStoreIC, StoreWithVector)                                           \
  TFH(KeyedStoreICTrampoline, Store)                                           \
  TFH(KeyedStoreICTrampoline_Megamorphic, Store)                               \
  TFH(KeyedStoreICBaseline, StoreBaseline)                                     \
  TFH(DefineKeyedOwnIC, DefineKeyedOwnWithVector)                              \
  TFH(DefineKeyedOwnICTrampoline, DefineKeyedOwn)                              \
  TFH(DefineKeyedOwnICBaseline, DefineKeyedOwnBaseline)                        \
  TFH(StoreInArrayLiteralIC, StoreWithVector)                                  \
  TFH(StoreInArrayLiteralICBaseline, StoreBaseline)                            \
  TFH(LookupContextTrampoline, LookupTrampoline)                               \
  TFH(LookupScriptContextTrampoline, LookupTrampoline)                         \
  TFH(LookupContextBaseline, LookupBaseline)                                   \
  TFH(LookupScriptContextBaseline, LookupBaseline)                             \
  TFH(LookupContextInsideTypeofTrampoline, LookupTrampoline)                   \
  TFH(LookupScriptContextInsideTypeofTrampoline, LookupTrampoline)             \
  TFH(LookupContextInsideTypeofBaseline, LookupBaseline)                       \
  TFH(LookupScriptContextInsideTypeofBaseline, LookupBaseline)                 \
  TFH(LoadGlobalIC, LoadGlobalWithVector)                                      \
  TFH(LoadGlobalICInsideTypeof, LoadGlobalWithVector)                          \
  TFH(LoadGlobalICTrampoline, LoadGlobal)                                      \
  TFH(LoadGlobalICBaseline, LoadGlobalBaseline)                                \
  TFH(LoadGlobalICInsideTypeofTrampoline, LoadGlobal)                          \
  TFH(LoadGlobalICInsideTypeofBaseline, LoadGlobalBaseline)                    \
  TFH(LookupGlobalIC, LookupWithVector)                                        \
  TFH(LookupGlobalICTrampoline, LookupTrampoline)                              \
  TFH(LookupGlobalICBaseline, LookupBaseline)                                  \
  TFH(LookupGlobalICInsideTypeof, LookupWithVector)                            \
  TFH(LookupGlobalICInsideTypeofTrampoline, LookupTrampoline)                  \
  TFH(LookupGlobalICInsideTypeofBaseline, LookupBaseline)                      \
  TFH(CloneObjectIC, CloneObjectWithVector)                                    \
  TFH(CloneObjectICBaseline, CloneObjectBaseline)                              \
  TFH(CloneObjectIC_Slow, CloneObjectWithVector)                               \
  TFH(KeyedHasIC, KeyedHasICWithVector)                                        \
  TFH(KeyedHasICBaseline, KeyedHasICBaseline)                                  \
  TFH(KeyedHasIC_Megamorphic, KeyedHasICWithVector)                            \
                                                                               \
  /* IterableToList */                                                         \
  /* ES #sec-iterabletolist */                                                 \
  TFS(IterableToList, NeedsContext::kYes, kIterable, kIteratorFn)              \
  TFS(IterableToFixedArray, NeedsContext::kYes, kIterable, kIteratorFn)        \
  TFS(IterableToListWithSymbolLookup, NeedsContext::kYes, kIterable)           \
  TFS(IterableToFixedArrayWithSymbolLookupSlow, NeedsContext::kYes, kIterable) \
  TFS(IterableToListMayPreserveHoles, NeedsContext::kYes, kIterable,           \
      kIteratorFn)                                                             \
  TFS(IterableToListConvertHoles, NeedsContext::kYes, kIterable, kIteratorFn)  \
  IF_WASM(TFS, IterableToFixedArrayForWasm, NeedsContext::kYes, kIterable,     \
          kExpectedLength)                                                     \
                                                                               \
  /* #sec-createstringlistfromiterable */                                      \
  TFS(StringListFromIterable, NeedsContext::kYes, kIterable)                   \
                                                                               \
  /* Map */                                                                    \
  TFS(FindOrderedHashMapEntry, NeedsContext::kYes, kTable, kKey)               \
  TFJ(MapConstructor, kDontAdaptArgumentsSentinel)                             \
  TFJ(MapPrototypeSet, kJSArgcReceiverSlots + 2, kReceiver, kKey, kValue)      \
  TFJ(MapPrototypeDelete, kJSArgcReceiverSlots + 1, kReceiver, kKey)           \
  TFJ(MapPrototypeGet, kJSArgcReceiverSlots + 1, kReceiver, kKey)              \
  TFJ(MapPrototypeHas, kJSArgcReceiverSlots + 1, kReceiver, kKey)              \
  CPP(MapPrototypeClear, JSParameterCount(0))                                  \
  /* ES #sec-map.prototype.entries */                                          \
  TFJ(MapPrototypeEntries, kJSArgcReceiverSlots, kReceiver)                    \
  /* ES #sec-get-map.prototype.size */                                         \
  TFJ(MapPrototypeGetSize, kJSArgcReceiverSlots, kReceiver)                    \
  /* ES #sec-map.prototype.forEach */                                          \
  TFJ(MapPrototypeForEach, kDontAdaptArgumentsSentinel)                        \
  /* ES #sec-map.prototype.keys */                                             \
  TFJ(MapPrototypeKeys, kJSArgcReceiverSlots, kReceiver)                       \
  /* ES #sec-map.prototype.values */                                           \
  TFJ(MapPrototypeValues, kJSArgcReceiverSlots, kReceiver)                     \
  /* ES #sec-%mapiteratorprototype%.next */                                    \
  TFJ(MapIteratorPrototypeNext, kJSArgcReceiverSlots, kReceiver)               \
  TFS(MapIteratorToList, NeedsContext::kYes, kSource)                          \
                                                                               \
  /* ES #sec-number-constructor */                                             \
  CPP(NumberPrototypeToExponential, kDontAdaptArgumentsSentinel)               \
  CPP(NumberPrototypeToFixed, kDontAdaptArgumentsSentinel)                     \
  CPP(NumberPrototypeToLocaleString, kDontAdaptArgumentsSentinel)              \
  CPP(NumberPrototypeToPrecision, kDontAdaptArgumentsSentinel)                 \
  TFC(SameValue, CompareNoContext)                                             \
  TFC(SameValueNumbersOnly, CompareNoContext)                                  \
                                                                               \
  /* Binary ops with feedback collection */                                    \
  TFC(Add_Baseline, BinaryOp_Baseline)                                         \
  TFC(AddSmi_Baseline, BinarySmiOp_Baseline)                                   \
  TFC(Subtract_Baseline, BinaryOp_Baseline)                                    \
  TFC(SubtractSmi_Baseline, BinarySmiOp_Baseline)                              \
  TFC(Multiply_Baseline, BinaryOp_Baseline)                                    \
  TFC(MultiplySmi_Baseline, BinarySmiOp_Baseline)                              \
  TFC(Divide_Baseline, BinaryOp_Baseline)                                      \
  TFC(DivideSmi_Baseline, BinarySmiOp_Baseline)                                \
  TFC(Modulus_Baseline, BinaryOp_Baseline)                                     \
  TF
"""


```