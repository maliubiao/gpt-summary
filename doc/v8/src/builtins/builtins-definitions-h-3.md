Response:
Let's break down the thought process for analyzing this `builtins-definitions.h` file.

1. **Understanding the Context:** The prompt clearly states this is part of the V8 JavaScript engine source code, specifically within the `builtins` directory. The filename hints at defining built-in functions. The prompt also provides crucial information: if the file ended in `.tq`, it would be Torque code. This tells us the current file is likely C++ based, given the `CPP`, `TFS`, `TFJ`, and `ASM` macros.

2. **Identifying the Core Purpose:** The file is named `builtins-definitions.h`. The most logical inference is that it *defines* the built-in functions that JavaScript code can directly access (like `Array.map`, `String.prototype.toUpperCase`, etc.).

3. **Analyzing the Structure and Macros:**  The code is a large sequence of macro invocations. Recognizing these macros is key to understanding the file's function. Let's consider the common ones:
    * `CPP`: Likely stands for "C++ Builtin." This suggests a direct mapping to a C++ function implementation. The arguments `JSParameterCount(n)` probably specify how many arguments the JavaScript-visible function takes.
    * `TFS`:  This one is less immediately obvious. Given the context of "builtins" and that other macros relate to JavaScript functions, it probably relates to a Torque Function (given the prompt's hint). The arguments `NeedsContext::kYes` and then several `k...` keywords likely represent properties of the Torque function, like whether it needs the execution context and the types of its arguments.
    * `TFJ`:  Similar to `TFS`, also likely a Torque Function, possibly with a different calling convention or purpose. The `kDontAdaptArgumentsSentinel` suggests that the arguments passed directly from JavaScript should be used without modification. The `kJSArgcReceiverSlots + 1` looks like a calculation related to the number of arguments and the `this` receiver.
    * `ASM`: Clearly indicates inline assembly code. The names often describe the functionality (e.g., `CEntry_Return1_ArgvInRegister_NoBuiltinExit`).

4. **Categorizing the Built-ins:** As I scanned the list, patterns emerged. The built-ins are grouped logically:
    * `AtomicsCondition`:  Related to shared memory and concurrency primitives.
    * `AsyncGenerator`:  Functions for handling asynchronous generators.
    * `AsyncGeneratorFunctionConstructor`:  The constructor for creating async generator functions.
    * `AsyncGenerator.prototype.*`: Methods on the prototype of async generator objects.
    * `Async-from-Sync Iterator`: Handling conversion of sync iterators to async ones.
    * `CEntry`:  Entry points for calling C++ functions from the V8 interpreter.
    * `String helpers`: Operations on strings.
    * `Miscellaneous`: General utility functions.
    * `Trace`: Debugging and logging.
    * `Weak refs`:  Weak references and finalization.
    * `Async modules`:  Support for asynchronous JavaScript modules.
    * `Temporal`: A large section dedicated to the Temporal API (for date and time).

5. **Relating to JavaScript:**  For each category, consider the equivalent JavaScript concepts. This is crucial for fulfilling the prompt's requirements.
    * `Atomics`:  Directly maps to the `Atomics` object in JavaScript.
    * `AsyncGenerator`:  Relates to `async function*` and the `yield` keyword within them.
    * `CEntry`: While not directly exposed, these are the underlying implementations of many JavaScript operations.
    * `String helpers`:  Corresponds to string methods like `+` (concatenation) and `substring`.
    * `Temporal`: A direct mapping to the JavaScript `Temporal` API.

6. **Providing JavaScript Examples:** For the categories with clear JavaScript equivalents, provide simple examples to illustrate the connection. This demonstrates the practical relevance of the definitions.

7. **Considering Code Logic and Assumptions:**  While this file *defines* the built-ins, it doesn't contain the actual *implementation* logic. Therefore, code logic reasoning is limited. However, we can infer assumptions about input and output based on the function names and parameter counts (when available). For example, `StringAdd_CheckNone` likely takes two string arguments and returns their concatenation.

8. **Identifying Potential Programming Errors:** Think about common mistakes developers make when using the JavaScript features these built-ins support. Examples include misuse of `Atomics`, incorrect handling of async operations, and errors with date/time manipulation (which the extensive `Temporal` section hints at).

9. **Synthesizing the Summary:**  Combine the key findings into a concise summary. Emphasize the role of this file in defining the interface between JavaScript and the underlying V8 engine, and how it provides the foundation for JavaScript's built-in functionalities.

10. **Addressing Specific Prompt Requirements:**  Ensure all parts of the prompt are addressed, such as mentioning the `.tq` extension and explicitly stating whether the file is Torque or not.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just lists a bunch of function names."  **Correction:**  Realize the macros and the grouping provide structure and meaning beyond just names.
* **Uncertainty about `TFS`/`TFJ`:**  Initially unsure of the exact meaning. **Correction:** Use the prompt's hint about `.tq` files to infer that these likely relate to Torque.
* **Overemphasis on implementation:**  Might initially think about the C++ implementation details. **Correction:** Focus on the *definition* and how it relates to the JavaScript interface, as the file name suggests.
* **Missing JavaScript examples:**  Might initially forget to provide concrete JavaScript examples. **Correction:**  Go back and add illustrative examples for relevant categories.

By following these steps, systematically analyzing the structure, and connecting the definitions to JavaScript concepts, a comprehensive and accurate understanding of the `builtins-definitions.h` file can be achieved.
好的，让我们来分析一下 `v8/src/builtins/builtins-definitions.h` 这个文件的功能。

**功能归纳**

这个 `.h` 文件定义了 V8 JavaScript 引擎中内置函数（built-ins）的接口。它就像一个“蓝图”，列出了所有 V8 引擎提供的可以直接在 JavaScript 代码中调用的函数。  这些定义包含了函数的名称以及一些元数据，例如：

* **函数名:**  例如 `AtomicsConditionAcquireLock`, `AsyncGeneratorResolve`, `StringAdd_CheckNone` 等。
* **参数信息:**  通过宏如 `JSParameterCount(0)` 或 `kDontAdaptArgumentsSentinel` 来指定参数的数量和处理方式。
* **上下文需求:**  通过 `NeedsContext::kYes` 表明函数执行是否需要 V8 的执行上下文。
* **函数类型:**  通过不同的宏前缀 (如 `CPP`, `TFS`, `TFJ`, `ASM`, `TFC`) 来标识内置函数的实现方式。

**关于文件扩展名 `.tq`**

你提到如果文件以 `.tq` 结尾，那么它就是 V8 Torque 源代码。由于这个文件是 `.h` 结尾，**它不是 Torque 源代码**。  `.h` 文件通常是 C 或 C++ 头文件，用于声明接口和定义。

**与 JavaScript 功能的关系及举例**

这个文件中定义的每一个条目，如果其前缀不是 `ASM` (汇编) 或纯 C++ 的 `CPP`，并且涉及到 `TF` (Torque Function)，那么它很可能直接关联到某个 JavaScript 的全局函数、对象方法或者操作符。

以下是一些 JavaScript 功能与 `builtins-definitions.h` 中定义对应的例子：

1. **`Atomics.wait()`**:  对应 `CPP(AtomicsConditionWait, kDontAdaptArgumentsSentinel)`

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);
   Atomics.store(view, 0, 0);

   // 假设另一个线程会修改 view[0] 的值
   const result = Atomics.wait(view, 0, 0, 1000); // 等待最多 1000 毫秒
   console.log(result); // 可能输出 "ok", "timed-out", 或 "not-equal"
   ```
   这个 JavaScript 示例使用了 `Atomics.wait()`, 它在 `builtins-definitions.h` 中由 `AtomicsConditionWait` 这个 C++ 内置函数来支持。

2. **Async Generators (`async function*`)**: 对应 `TFS(AsyncGeneratorResolve, NeedsContext::kYes, kGenerator, kValue, kDone)` 等。

   ```javascript
   async function* myAsyncGenerator() {
     yield 1;
     await Promise.resolve();
     yield 2;
     return 3;
   }

   const iterator = myAsyncGenerator();
   iterator.next().then(result => console.log(result)); // 输出 { value: 1, done: false }
   iterator.next().then(result => console.log(result)); // 输出 { value: 2, done: false }
   iterator.next().then(result => console.log(result)); // 输出 { value: 3, done: true }
   ```
   `AsyncGeneratorResolve`, `AsyncGeneratorReject`, `AsyncGeneratorYieldWithAwait` 等定义了异步生成器内部状态转换和操作的内置函数。

3. **字符串连接 (`+`)**: 对应 `TFS(StringAdd_CheckNone, NeedsContext::kYes, kLeft, kRight)`

   ```javascript
   const str1 = "Hello";
   const str2 = " World";
   const combined = str1 + str2;
   console.log(combined); // 输出 "Hello World"
   ```
   当 JavaScript 执行字符串相加操作时，V8 引擎会调用 `StringAdd_CheckNone` 这个内置函数来处理。

4. **`Temporal` API (日期和时间)**: 对应大量的 `CPP(Temporal...)` 定义。

   ```javascript
   const today = Temporal.Now.plainDateISO();
   console.log(today.toString()); // 输出类似 "2023-10-27" 的日期字符串

   const later = today.add({ days: 7 });
   console.log(later.toString());
   ```
   `Temporal` API 是 JavaScript 中用于处理日期和时间的新 API，其所有方法（例如 `Temporal.Now.plainDateISO()`, `plainDate.add()`）都对应着 `builtins-definitions.h` 中定义的 C++ 内置函数。

**代码逻辑推理及假设输入输出**

由于 `builtins-definitions.h` 主要定义接口，具体的代码逻辑在对应的 C++ 或 Torque 源文件中。但我们可以基于函数名进行一些推断。

**假设：**  我们关注 `TFS(StringAdd_CheckNone, NeedsContext::kYes, kLeft, kRight)`

* **假设输入:**
    * `kLeft`: 一个 JavaScript 字符串，例如 "abc"。
    * `kRight`: 另一个 JavaScript 字符串，例如 "def"。
* **可能的输出:**
    * 一个新的 JavaScript 字符串，内容为 "abcdef"。

**假设：** 我们关注 `CPP(TemporalPlainDateCompare, kDontAdaptArgumentsSentinel)`

* **假设输入:**
    * 两个 `Temporal.PlainDate` 类型的 JavaScript 对象。
* **可能的输出:**
    * 一个数字：
        *  -1: 如果第一个日期在第二个日期之前。
        *   0: 如果两个日期相等。
        *   1: 如果第一个日期在第二个日期之后。

**用户常见的编程错误举例**

了解这些内置函数可以帮助理解底层机制，从而避免一些常见的编程错误。

1. **误用 `Atomics.wait()` 导致死锁:**

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);
   Atomics.store(view, 0, 0);

   function worker1() {
     Atomics.wait(view, 0, 0); // 等待 view[0] 的值改变
     console.log("Worker 1 woke up");
   }

   function worker2() {
     Atomics.wait(view, 0, 0); // 等待 view[0] 的值改变
     console.log("Worker 2 woke up");
   }

   // 如果没有其他线程来修改 view[0]，worker1 和 worker2 将永远等待，造成死锁。
   worker1();
   worker2();
   ```
   错误在于，开发者假设会有其他线程来唤醒等待的线程，但如果没有正确的同步机制，就会导致死锁。`CPP(AtomicsConditionWait, kDontAdaptArgumentsSentinel)` 的存在提醒我们，使用原子操作需要谨慎处理并发问题。

2. **`Temporal` API 的使用错误:**

   ```javascript
   // 错误地尝试直接修改 Temporal 对象
   const today = Temporal.Now.plainDateISO();
   today.year = 2024; // 错误！Temporal 对象是不可变的
   console.log(today.toString()); // 仍然是今天的日期

   // 正确的做法是使用 with() 方法创建新的对象
   const nextYear = today.with({ year: 2024 });
   console.log(nextYear.toString());
   ```
   `Temporal` API 中的许多对象是不可变的。理解 `CPP(TemporalPlainDatePrototypeWith, kDontAdaptArgumentsSentinel)` 的作用可以帮助开发者正确使用 `with()` 等方法来创建新的 `Temporal` 对象，而不是尝试直接修改。

**总结**

`v8/src/builtins/builtins-definitions.h` 文件是 V8 引擎的核心组成部分，它定义了 JavaScript 内置函数的接口。虽然它本身不包含具体的实现逻辑，但它为理解 JavaScript 功能的底层实现提供了重要的线索。通过分析这个文件，我们可以了解 V8 引擎是如何将 JavaScript 代码映射到高效的 C++ 或 Torque 代码执行的。 文件中大量的 `Temporal` API 定义也反映了 V8 对最新 ECMAScript 标准的支持。

Prompt: 
```
这是目录为v8/src/builtins/builtins-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
unt(0))                        \
  CPP(AtomicsConditionAcquireLock, JSParameterCount(0))                        \
  CPP(AtomicsConditionIsCondition, JSParameterCount(1))                        \
  CPP(AtomicsConditionWait, kDontAdaptArgumentsSentinel)                       \
  CPP(AtomicsConditionNotify, kDontAdaptArgumentsSentinel)                     \
  CPP(AtomicsConditionWaitAsync, kDontAdaptArgumentsSentinel)                  \
                                                                               \
  /* AsyncGenerator */                                                         \
                                                                               \
  TFS(AsyncGeneratorResolve, NeedsContext::kYes, kGenerator, kValue, kDone)    \
  TFS(AsyncGeneratorReject, NeedsContext::kYes, kGenerator, kValue)            \
  TFS(AsyncGeneratorYieldWithAwait, NeedsContext::kYes, kGenerator, kValue)    \
  TFS(AsyncGeneratorReturn, NeedsContext::kYes, kGenerator, kValue)            \
  TFS(AsyncGeneratorResumeNext, NeedsContext::kYes, kGenerator)                \
                                                                               \
  /* AsyncGeneratorFunction( p1, p2, ... pn, body ) */                         \
  /* proposal-async-iteration/#sec-asyncgeneratorfunction-constructor */       \
  CPP(AsyncGeneratorFunctionConstructor, kDontAdaptArgumentsSentinel)          \
  /* AsyncGenerator.prototype.next ( value ) */                                \
  /* proposal-async-iteration/#sec-asyncgenerator-prototype-next */            \
  TFJ(AsyncGeneratorPrototypeNext, kDontAdaptArgumentsSentinel)                \
  /* AsyncGenerator.prototype.return ( value ) */                              \
  /* proposal-async-iteration/#sec-asyncgenerator-prototype-return */          \
  TFJ(AsyncGeneratorPrototypeReturn, kDontAdaptArgumentsSentinel)              \
  /* AsyncGenerator.prototype.throw ( exception ) */                           \
  /* proposal-async-iteration/#sec-asyncgenerator-prototype-throw */           \
  TFJ(AsyncGeneratorPrototypeThrow, kDontAdaptArgumentsSentinel)               \
                                                                               \
  /* Await (proposal-async-iteration/#await), with resume behaviour */         \
  /* specific to Async Generators. Internal / Not exposed to JS code. */       \
  TFS(AsyncGeneratorAwait, NeedsContext::kYes, kAsyncGeneratorObject, kValue)  \
  TFJ(AsyncGeneratorAwaitResolveClosure, kJSArgcReceiverSlots + 1, kReceiver,  \
      kValue)                                                                  \
  TFJ(AsyncGeneratorAwaitRejectClosure, kJSArgcReceiverSlots + 1, kReceiver,   \
      kValue)                                                                  \
  TFJ(AsyncGeneratorYieldWithAwaitResolveClosure, kJSArgcReceiverSlots + 1,    \
      kReceiver, kValue)                                                       \
  TFJ(AsyncGeneratorReturnClosedResolveClosure, kJSArgcReceiverSlots + 1,      \
      kReceiver, kValue)                                                       \
  TFJ(AsyncGeneratorReturnClosedRejectClosure, kJSArgcReceiverSlots + 1,       \
      kReceiver, kValue)                                                       \
  TFJ(AsyncGeneratorReturnResolveClosure, kJSArgcReceiverSlots + 1, kReceiver, \
      kValue)                                                                  \
                                                                               \
  /* Async-from-Sync Iterator */                                               \
                                                                               \
  /* %AsyncFromSyncIteratorPrototype% */                                       \
  /* See tc39.github.io/proposal-async-iteration/ */                           \
  /* #sec-%asyncfromsynciteratorprototype%-object) */                          \
  TFJ(AsyncFromSyncIteratorPrototypeNext, kDontAdaptArgumentsSentinel)         \
  /* #sec-%asyncfromsynciteratorprototype%.throw */                            \
  TFJ(AsyncFromSyncIteratorPrototypeThrow, kDontAdaptArgumentsSentinel)        \
  /* #sec-%asyncfromsynciteratorprototype%.return */                           \
  TFJ(AsyncFromSyncIteratorPrototypeReturn, kDontAdaptArgumentsSentinel)       \
  /* #sec-asyncfromsynciteratorcontinuation */                                 \
  TFJ(AsyncFromSyncIteratorCloseSyncAndRethrow, kJSArgcReceiverSlots + 1,      \
      kReceiver, kError)                                                       \
  /* #sec-async-iterator-value-unwrap-functions */                             \
  TFJ(AsyncIteratorValueUnwrap, kJSArgcReceiverSlots + 1, kReceiver, kValue)   \
                                                                               \
  /* CEntry */                                                                 \
  ASM(CEntry_Return1_ArgvInRegister_NoBuiltinExit, InterpreterCEntry1)         \
  ASM(CEntry_Return1_ArgvOnStack_BuiltinExit, CEntry1ArgvOnStack)              \
  ASM(CEntry_Return1_ArgvOnStack_NoBuiltinExit, CEntryDummy)                   \
  ASM(CEntry_Return2_ArgvInRegister_NoBuiltinExit, InterpreterCEntry2)         \
  ASM(CEntry_Return2_ArgvOnStack_BuiltinExit, CEntryDummy)                     \
  ASM(CEntry_Return2_ArgvOnStack_NoBuiltinExit, CEntryDummy)                   \
  ASM(WasmCEntry, CEntryDummy)                                                 \
  ASM(DirectCEntry, CEntryDummy)                                               \
                                                                               \
  /* String helpers */                                                         \
  TFS(StringAdd_CheckNone, NeedsContext::kYes, kLeft, kRight)                  \
  TFS(SubString, NeedsContext::kYes, kString, kFrom, kTo)                      \
                                                                               \
  /* Miscellaneous */                                                          \
  ASM(DoubleToI, Void)                                                         \
  TFC(GetProperty, GetProperty)                                                \
  TFS(GetPropertyWithReceiver, NeedsContext::kYes, kObject, kKey, kReceiver,   \
      kOnNonExistent)                                                          \
  TFS(SetProperty, NeedsContext::kYes, kReceiver, kKey, kValue)                \
  TFS(CreateDataProperty, NeedsContext::kYes, kReceiver, kKey, kValue)         \
  TFS(GetOwnPropertyDescriptor, NeedsContext::kYes, kReceiver, kKey)           \
  ASM(MemCopyUint8Uint8, CCall)                                                \
  ASM(MemMove, CCall)                                                          \
  TFC(FindNonDefaultConstructorOrConstruct,                                    \
      FindNonDefaultConstructorOrConstruct)                                    \
  TFS(OrdinaryGetOwnPropertyDescriptor, NeedsContext::kYes, kReceiver, kKey)   \
  IF_SHADOW_STACK(ASM, AdaptShadowStackForDeopt, Void)                         \
                                                                               \
  /* Trace */                                                                  \
  CPP(IsTraceCategoryEnabled, JSParameterCount(1))                             \
  CPP(Trace, JSParameterCount(5))                                              \
                                                                               \
  /* Weak refs */                                                              \
  CPP(FinalizationRegistryUnregister, kDontAdaptArgumentsSentinel)             \
                                                                               \
  /* Async modules */                                                          \
  TFJ(AsyncModuleEvaluate, kDontAdaptArgumentsSentinel)                        \
                                                                               \
  /* CallAsyncModule* are spec anonymyous functions */                         \
  CPP(CallAsyncModuleFulfilled, JSParameterCount(0))                           \
  CPP(CallAsyncModuleRejected, JSParameterCount(0))                            \
                                                                               \
  /* Temporal */                                                               \
  /* Temporal #sec-temporal.now.timezone */                                    \
  CPP(TemporalNowTimeZone, kDontAdaptArgumentsSentinel)                        \
  /* Temporal #sec-temporal.now.instant */                                     \
  CPP(TemporalNowInstant, kDontAdaptArgumentsSentinel)                         \
  /* Temporal #sec-temporal.now.plaindatetime */                               \
  CPP(TemporalNowPlainDateTime, kDontAdaptArgumentsSentinel)                   \
  /* Temporal #sec-temporal.now.plaindatetimeiso */                            \
  CPP(TemporalNowPlainDateTimeISO, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.now.zoneddatetime */                               \
  CPP(TemporalNowZonedDateTime, kDontAdaptArgumentsSentinel)                   \
  /* Temporal #sec-temporal.now.zoneddatetimeiso */                            \
  CPP(TemporalNowZonedDateTimeISO, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.now.plaindate */                                   \
  CPP(TemporalNowPlainDate, kDontAdaptArgumentsSentinel)                       \
  /* Temporal #sec-temporal.now.plaindateiso */                                \
  CPP(TemporalNowPlainDateISO, kDontAdaptArgumentsSentinel)                    \
  /* There are no Temporal.now.plainTime */                                    \
  /* See https://github.com/tc39/proposal-temporal/issues/1540 */              \
  /* Temporal #sec-temporal.now.plaintimeiso */                                \
  CPP(TemporalNowPlainTimeISO, kDontAdaptArgumentsSentinel)                    \
                                                                               \
  /* Temporal.PlaneDate */                                                     \
  /* Temporal #sec-temporal.plaindate */                                       \
  CPP(TemporalPlainDateConstructor, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-temporal.plaindate.from */                                  \
  CPP(TemporalPlainDateFrom, kDontAdaptArgumentsSentinel)                      \
  /* Temporal #sec-temporal.plaindate.compare */                               \
  CPP(TemporalPlainDateCompare, kDontAdaptArgumentsSentinel)                   \
  /* Temporal #sec-get-temporal.plaindate.prototype.calendar */                \
  CPP(TemporalPlainDatePrototypeCalendar, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.plaindate.prototype.year */                    \
  CPP(TemporalPlainDatePrototypeYear, JSParameterCount(0))                     \
  /* Temporal #sec-get-temporal.plaindate.prototype.month */                   \
  CPP(TemporalPlainDatePrototypeMonth, JSParameterCount(0))                    \
  /* Temporal #sec-get-temporal.plaindate.prototype.monthcode */               \
  CPP(TemporalPlainDatePrototypeMonthCode, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.plaindate.prototype.day */                     \
  CPP(TemporalPlainDatePrototypeDay, JSParameterCount(0))                      \
  /* Temporal #sec-get-temporal.plaindate.prototype.dayofweek */               \
  CPP(TemporalPlainDatePrototypeDayOfWeek, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.plaindate.prototype.dayofyear */               \
  CPP(TemporalPlainDatePrototypeDayOfYear, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.plaindate.prototype.weekofyear */              \
  CPP(TemporalPlainDatePrototypeWeekOfYear, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plaindate.prototype.daysinweek */              \
  CPP(TemporalPlainDatePrototypeDaysInWeek, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plaindate.prototype.daysinmonth */             \
  CPP(TemporalPlainDatePrototypeDaysInMonth, JSParameterCount(0))              \
  /* Temporal #sec-get-temporal.plaindate.prototype.daysinyear */              \
  CPP(TemporalPlainDatePrototypeDaysInYear, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plaindate.prototype.monthsinyear */            \
  CPP(TemporalPlainDatePrototypeMonthsInYear, JSParameterCount(0))             \
  /* Temporal #sec-get-temporal.plaindate.prototype.inleapyear */              \
  CPP(TemporalPlainDatePrototypeInLeapYear, JSParameterCount(0))               \
  /* Temporal #sec-temporal.plaindate.prototype.toplainyearmonth */            \
  CPP(TemporalPlainDatePrototypeToPlainYearMonth, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.plaindate.prototype.toplainmonthday */             \
  CPP(TemporalPlainDatePrototypeToPlainMonthDay, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaindate.prototype.getisofields */                \
  CPP(TemporalPlainDatePrototypeGetISOFields, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plaindate.prototype.add */                         \
  CPP(TemporalPlainDatePrototypeAdd, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.plaindate.prototype.substract */                   \
  CPP(TemporalPlainDatePrototypeSubtract, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plaindate.prototype.with */                        \
  CPP(TemporalPlainDatePrototypeWith, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.plaindate.prototype.withcalendar */                \
  CPP(TemporalPlainDatePrototypeWithCalendar, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plaindate.prototype.until */                       \
  CPP(TemporalPlainDatePrototypeUntil, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.plaindate.prototype.since */                       \
  CPP(TemporalPlainDatePrototypeSince, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.plaindate.prototype.equals */                      \
  CPP(TemporalPlainDatePrototypeEquals, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plaindate.prototype.toplaindatetime */             \
  CPP(TemporalPlainDatePrototypeToPlainDateTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaindate.prototype.tozoneddatetime */             \
  CPP(TemporalPlainDatePrototypeToZonedDateTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaindate.prototype.tostring */                    \
  CPP(TemporalPlainDatePrototypeToString, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plaindate.prototype.tojson */                      \
  CPP(TemporalPlainDatePrototypeToJSON, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plaindate.prototype.tolocalestring */              \
  CPP(TemporalPlainDatePrototypeToLocaleString, kDontAdaptArgumentsSentinel)   \
  /* Temporal #sec-temporal.plaindate.prototype.valueof */                     \
  CPP(TemporalPlainDatePrototypeValueOf, kDontAdaptArgumentsSentinel)          \
                                                                               \
  /* Temporal.PlaneTime */                                                     \
  /* Temporal #sec-temporal.plaintime */                                       \
  CPP(TemporalPlainTimeConstructor, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-temporal.plaintime.from */                                  \
  CPP(TemporalPlainTimeFrom, kDontAdaptArgumentsSentinel)                      \
  /* Temporal #sec-temporal.plaintime.compare */                               \
  CPP(TemporalPlainTimeCompare, kDontAdaptArgumentsSentinel)                   \
  /* Temporal #sec-get-temporal.plaintime.prototype.calendar */                \
  CPP(TemporalPlainTimePrototypeCalendar, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.plaintime.prototype.hour */                    \
  CPP(TemporalPlainTimePrototypeHour, JSParameterCount(0))                     \
  /* Temporal #sec-get-temporal.plaintime.prototype.minute */                  \
  CPP(TemporalPlainTimePrototypeMinute, JSParameterCount(0))                   \
  /* Temporal #sec-get-temporal.plaintime.prototype.second */                  \
  CPP(TemporalPlainTimePrototypeSecond, JSParameterCount(0))                   \
  /* Temporal #sec-get-temporal.plaintime.prototype.millisecond */             \
  CPP(TemporalPlainTimePrototypeMillisecond, JSParameterCount(0))              \
  /* Temporal #sec-get-temporal.plaintime.prototype.microsecond */             \
  CPP(TemporalPlainTimePrototypeMicrosecond, JSParameterCount(0))              \
  /* Temporal #sec-get-temporal.plaintime.prototype.nanoseond */               \
  CPP(TemporalPlainTimePrototypeNanosecond, JSParameterCount(0))               \
  /* Temporal #sec-temporal.plaintime.prototype.add */                         \
  CPP(TemporalPlainTimePrototypeAdd, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.plaintime.prototype.subtract */                    \
  CPP(TemporalPlainTimePrototypeSubtract, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plaintime.prototype.with */                        \
  CPP(TemporalPlainTimePrototypeWith, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.plaintime.prototype.until */                       \
  CPP(TemporalPlainTimePrototypeUntil, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.plaintime.prototype.since */                       \
  CPP(TemporalPlainTimePrototypeSince, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.plaintime.prototype.round */                       \
  CPP(TemporalPlainTimePrototypeRound, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.plaintime.prototype.equals */                      \
  CPP(TemporalPlainTimePrototypeEquals, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plaintime.prototype.toplaindatetime */             \
  CPP(TemporalPlainTimePrototypeToPlainDateTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaintime.prototype.tozoneddatetime */             \
  CPP(TemporalPlainTimePrototypeToZonedDateTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaintime.prototype.getisofields */                \
  CPP(TemporalPlainTimePrototypeGetISOFields, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plaintime.prototype.tostring */                    \
  CPP(TemporalPlainTimePrototypeToString, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plaindtimeprototype.tojson */                      \
  CPP(TemporalPlainTimePrototypeToJSON, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plaintime.prototype.tolocalestring */              \
  CPP(TemporalPlainTimePrototypeToLocaleString, kDontAdaptArgumentsSentinel)   \
  /* Temporal #sec-temporal.plaintime.prototype.valueof */                     \
  CPP(TemporalPlainTimePrototypeValueOf, kDontAdaptArgumentsSentinel)          \
                                                                               \
  /* Temporal.PlaneDateTime */                                                 \
  /* Temporal #sec-temporal.plaindatetime */                                   \
  CPP(TemporalPlainDateTimeConstructor, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plaindatetime.from */                              \
  CPP(TemporalPlainDateTimeFrom, kDontAdaptArgumentsSentinel)                  \
  /* Temporal #sec-temporal.plaindatetime.compare */                           \
  CPP(TemporalPlainDateTimeCompare, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.calendar */            \
  CPP(TemporalPlainDateTimePrototypeCalendar, JSParameterCount(0))             \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.year */                \
  CPP(TemporalPlainDateTimePrototypeYear, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.month */               \
  CPP(TemporalPlainDateTimePrototypeMonth, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.monthcode */           \
  CPP(TemporalPlainDateTimePrototypeMonthCode, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.day */                 \
  CPP(TemporalPlainDateTimePrototypeDay, JSParameterCount(0))                  \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.hour */                \
  CPP(TemporalPlainDateTimePrototypeHour, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.minute */              \
  CPP(TemporalPlainDateTimePrototypeMinute, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.second */              \
  CPP(TemporalPlainDateTimePrototypeSecond, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.millisecond */         \
  CPP(TemporalPlainDateTimePrototypeMillisecond, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.microsecond */         \
  CPP(TemporalPlainDateTimePrototypeMicrosecond, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.nanosecond */          \
  CPP(TemporalPlainDateTimePrototypeNanosecond, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.dayofweek */           \
  CPP(TemporalPlainDateTimePrototypeDayOfWeek, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.dayofyear */           \
  CPP(TemporalPlainDateTimePrototypeDayOfYear, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.weekofyear */          \
  CPP(TemporalPlainDateTimePrototypeWeekOfYear, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.daysinweek */          \
  CPP(TemporalPlainDateTimePrototypeDaysInWeek, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.daysinmonth */         \
  CPP(TemporalPlainDateTimePrototypeDaysInMonth, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.daysinyear */          \
  CPP(TemporalPlainDateTimePrototypeDaysInYear, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.monthsinyear */        \
  CPP(TemporalPlainDateTimePrototypeMonthsInYear, JSParameterCount(0))         \
  /* Temporal #sec-get-temporal.plaindatetime.prototype.inleapyear */          \
  CPP(TemporalPlainDateTimePrototypeInLeapYear, JSParameterCount(0))           \
  /* Temporal #sec-temporal.plaindatetime.prototype.with */                    \
  CPP(TemporalPlainDateTimePrototypeWith, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plaindatetime.prototype.withplainTime */           \
  CPP(TemporalPlainDateTimePrototypeWithPlainTime,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.withplainDate */           \
  CPP(TemporalPlainDateTimePrototypeWithPlainDate,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.withcalendar */            \
  CPP(TemporalPlainDateTimePrototypeWithCalendar, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.plaindatetime.prototype.add */                     \
  CPP(TemporalPlainDateTimePrototypeAdd, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.plaindatetime.prototype.subtract */                \
  CPP(TemporalPlainDateTimePrototypeSubtract, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plaindatetime.prototype.until */                   \
  CPP(TemporalPlainDateTimePrototypeUntil, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.plaindatetime.prototype.since */                   \
  CPP(TemporalPlainDateTimePrototypeSince, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.plaindatetime.prototype.round */                   \
  CPP(TemporalPlainDateTimePrototypeRound, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.plaindatetime.prototype.equals */                  \
  CPP(TemporalPlainDateTimePrototypeEquals, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plaindatetime.prototype.tostring */                \
  CPP(TemporalPlainDateTimePrototypeToString, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plainddatetimeprototype.tojson */                  \
  CPP(TemporalPlainDateTimePrototypeToJSON, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plaindatetime.prototype.tolocalestring */          \
  CPP(TemporalPlainDateTimePrototypeToLocaleString,                            \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.valueof */                 \
  CPP(TemporalPlainDateTimePrototypeValueOf, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.plaindatetime.prototype.tozoneddatetime */         \
  CPP(TemporalPlainDateTimePrototypeToZonedDateTime,                           \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.toplaindate */             \
  CPP(TemporalPlainDateTimePrototypeToPlainDate, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaindatetime.prototype.toplainyearmonth */        \
  CPP(TemporalPlainDateTimePrototypeToPlainYearMonth,                          \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.toplainmonthday */         \
  CPP(TemporalPlainDateTimePrototypeToPlainMonthDay,                           \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plaindatetime.prototype.toplaintime */             \
  CPP(TemporalPlainDateTimePrototypeToPlainTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plaindatetime.prototype.getisofields */            \
  CPP(TemporalPlainDateTimePrototypeGetISOFields, kDontAdaptArgumentsSentinel) \
                                                                               \
  /* Temporal.ZonedDateTime */                                                 \
  /* Temporal #sec-temporal.zoneddatetime */                                   \
  CPP(TemporalZonedDateTimeConstructor, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.zoneddatetime.from */                              \
  CPP(TemporalZonedDateTimeFrom, kDontAdaptArgumentsSentinel)                  \
  /* Temporal #sec-temporal.zoneddatetime.compare */                           \
  CPP(TemporalZonedDateTimeCompare, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.calendar */            \
  CPP(TemporalZonedDateTimePrototypeCalendar, JSParameterCount(0))             \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.timezone */            \
  CPP(TemporalZonedDateTimePrototypeTimeZone, JSParameterCount(0))             \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.year */                \
  CPP(TemporalZonedDateTimePrototypeYear, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.month */               \
  CPP(TemporalZonedDateTimePrototypeMonth, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.monthcode */           \
  CPP(TemporalZonedDateTimePrototypeMonthCode, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.day */                 \
  CPP(TemporalZonedDateTimePrototypeDay, JSParameterCount(0))                  \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.hour */                \
  CPP(TemporalZonedDateTimePrototypeHour, JSParameterCount(0))                 \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.minute */              \
  CPP(TemporalZonedDateTimePrototypeMinute, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.second */              \
  CPP(TemporalZonedDateTimePrototypeSecond, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.millisecond */         \
  CPP(TemporalZonedDateTimePrototypeMillisecond, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.microsecond */         \
  CPP(TemporalZonedDateTimePrototypeMicrosecond, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.nanosecond */          \
  CPP(TemporalZonedDateTimePrototypeNanosecond, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.epochsecond */         \
  CPP(TemporalZonedDateTimePrototypeEpochSeconds, JSParameterCount(0))         \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.epochmilliseconds */   \
  CPP(TemporalZonedDateTimePrototypeEpochMilliseconds, JSParameterCount(0))    \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.epochmicroseconds */   \
  CPP(TemporalZonedDateTimePrototypeEpochMicroseconds, JSParameterCount(0))    \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.epochnanoseconds */    \
  CPP(TemporalZonedDateTimePrototypeEpochNanoseconds, JSParameterCount(0))     \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.dayofweek */           \
  CPP(TemporalZonedDateTimePrototypeDayOfWeek, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.dayofyear */           \
  CPP(TemporalZonedDateTimePrototypeDayOfYear, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.weekofyear */          \
  CPP(TemporalZonedDateTimePrototypeWeekOfYear, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.hoursinday */          \
  CPP(TemporalZonedDateTimePrototypeHoursInDay, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.daysinweek */          \
  CPP(TemporalZonedDateTimePrototypeDaysInWeek, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.daysinmonth */         \
  CPP(TemporalZonedDateTimePrototypeDaysInMonth, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.daysinyear */          \
  CPP(TemporalZonedDateTimePrototypeDaysInYear, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.monthsinyear */        \
  CPP(TemporalZonedDateTimePrototypeMonthsInYear, JSParameterCount(0))         \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.inleapyear */          \
  CPP(TemporalZonedDateTimePrototypeInLeapYear, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.offsetnanoseconds */   \
  CPP(TemporalZonedDateTimePrototypeOffsetNanoseconds, JSParameterCount(0))    \
  /* Temporal #sec-get-temporal.zoneddatetime.prototype.offset */              \
  CPP(TemporalZonedDateTimePrototypeOffset, JSParameterCount(0))               \
  /* Temporal #sec-temporal.zoneddatetime.prototype.with */                    \
  CPP(TemporalZonedDateTimePrototypeWith, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.zoneddatetime.prototype.withplaintime */           \
  CPP(TemporalZonedDateTimePrototypeWithPlainTime,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.withplaindate */           \
  CPP(TemporalZonedDateTimePrototypeWithPlainDate,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.withtimezone */            \
  CPP(TemporalZonedDateTimePrototypeWithTimeZone, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.zoneddatetime.prototype.withcalendar */            \
  CPP(Tempo
"""


```