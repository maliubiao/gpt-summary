Response:
Let's break down the thought process for analyzing the provided C++ header file snippet.

**1. Initial Understanding & Context:**

The first step is to recognize that this is a C++ header file (`.h`). The path `v8/src/runtime/runtime.h` immediately tells us it's part of the V8 JavaScript engine and deals with runtime functionalities. The comment mentioning ".tq" (Torque) is a crucial piece of information for later.

**2. Identifying the Core Structure: Macros and Function Definitions:**

Scanning the code, the dominant pattern is a series of macros like `FOR_EACH_INTRINSIC_...` and function-like macro definitions using `F(name, nargs, ressize)`. This suggests a systematic way of defining and categorizing runtime functions within V8.

* **`F(name, nargs, ressize)`:** This macro likely defines a function signature. `name` is the function's name, `nargs` is the number of arguments it takes, and `ressize` is probably the size of the return value. The `Runtime_##name` pattern strongly suggests these are C++ implementations of runtime functions.

* **`FOR_EACH_INTRINSIC_...`:** These macros are clearly iterators. They expand into a sequence of `F` macro calls, effectively listing different groups of runtime functions (e.g., `FOR_EACH_INTRINSIC_WASM`, `FOR_EACH_INTRINSIC_IC`).

**3. Deciphering the Categories (The "What"):**

By examining the names of the `FOR_EACH_INTRINSIC_...` macros, we can infer the categories of runtime functions:

* **WASM:**  Functions related to WebAssembly execution and interaction.
* **IC:**  Inline Caches, a crucial optimization technique in V8.
* **WEAKREF:**  Functions dealing with weak references and finalization registries.
* **ARRAY, ATOMICS, BIGINT, CLASSES, COLLECTIONS, COMPILER, DATE, DEBUG, FORIN, FUNCTION, GENERATOR, INTERNAL, TRACE, INTL, LITERALS, MODULE, NUMBERS, OBJECT, OPERATORS, PROMISE, PROXY, REGEXP, SCOPES, SHADOW_REALM, STRINGS, SYMBOL, TEMPORAL, TEST, TYPEDARRAY:** These correspond to various JavaScript language features and internal V8 components. This points to the runtime functions being the low-level implementations of these features.

**4. Understanding the `#define` logic:**

The `#define` directives are used to create preprocessor macros. The structure of the nested `FOR_EACH_INTRINSIC...` macros is designed for modularity. For instance, `FOR_EACH_INTRINSIC_RETURN_OBJECT_IMPL` includes many other `FOR_EACH_INTRINSIC_...` macros, suggesting that these functions return objects. Similarly, `FOR_EACH_INTRINSIC_RETURN_PAIR_IMPL` likely contains functions returning pairs of values.

**5. Connecting to JavaScript (The "Why" and Examples):**

The comments and the categories themselves strongly suggest a link to JavaScript. The runtime functions are the underlying C++ implementations that make JavaScript features work.

* **WASM Examples:**  Functions like `WasmArrayCopy` directly relate to WebAssembly's ability to manipulate arrays.
* **String Examples:** `WasmStringNewWtf8` suggests operations on strings encoded in UTF-8 within the WASM context.
* **IC Examples:** `KeyedLoadIC_Miss` and `KeyedStoreIC_Miss` are directly related to how V8 optimizes property access in JavaScript.
* **General Features:** The other categories (Array, Object, etc.) map directly to JavaScript's built-in objects and functionalities.

**6. Code Logic and Assumptions (The "How"):**

While the header file doesn't show the actual *implementation* logic, we can infer some basic assumptions:

* **Input/Output:** The `nargs` and `ressize` in the `F` macro give us hints about the number of inputs and the size of the output (likely pointers to objects).
* **Low-Level Operations:** The functions within this header file are likely involved in core operations like memory allocation (`WasmAllocateFeedbackVector`), type checking (`IsWasmCode`), and handling execution flow (`WasmDebugBreak`).

**7. Identifying Potential Programming Errors:**

By understanding the function names, we can anticipate common errors:

* **Incorrect Arguments:**  The `nargs` parameter highlights the importance of providing the correct number of arguments when calling these runtime functions (though these are typically called internally by V8).
* **Type Mismatches:**  Functions like `WasmCastToSpecialPrimitiveArray` suggest potential type errors if the input is not of the expected type.

**8. Torque and File Extensions:**

The comment about `.tq` files is important. It indicates that if `runtime.h` *were* a `.tq` file, it would contain Torque code. Torque is V8's domain-specific language for implementing runtime functions more safely and efficiently. Since this file is `.h`, it's regular C++ header code, *defining* the interface for those runtime functions.

**9. Final Summarization (The "Big Picture"):**

The final step is to synthesize the findings into a concise summary, covering the main functionalities, the link to JavaScript, and any other key observations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Are these functions directly callable from JavaScript?"  **Correction:**  While related, these are low-level C++ functions. JavaScript code typically triggers these indirectly.
* **Misinterpreting `ressize`:** Initially might think it's the size in bytes. **Refinement:** Realize it's more likely the *number* of return values (often pointers).
* **Overlooking the `.tq` comment:** Initially might focus solely on the C++ code. **Correction:** Recognize the significance of the Torque comment for understanding V8's development practices.

By following this structured approach, analyzing the code, and making connections based on the naming conventions and context, a comprehensive understanding of the `v8/src/runtime/runtime.h` file can be achieved.
这是V8源代码 `v8/src/runtime/runtime.h` 的第二部分，它延续了第一部分定义 V8 引擎的**运行时 (Runtime) 函数**的机制。这些运行时函数是用 C++ 实现的，是 V8 执行 JavaScript 代码时调用的底层操作。

**功能归纳:**

这部分 `runtime.h` 的主要功能是定义和声明了更多的 V8 运行时函数，特别是与以下方面相关的函数：

1. **WebAssembly (Wasm):**  定义了大量与 WebAssembly 模块执行、内存管理、类型转换、字符串操作、调试和性能分析相关的运行时函数。这些函数允许 JavaScript 代码与编译后的 WebAssembly 模块进行交互，并支持 V8 对 Wasm 的优化和调试。

2. **WebAssembly 测试:** 声明了一些用于 WebAssembly 内部测试的运行时函数，例如检查堆栈状态、统计 Wrapper 数量、序列化/反序列化模块等。

3. **弱引用 (Weak References):** 声明了与 JavaScript 的 `FinalizationRegistry` 和 `WeakRef` API 相关的运行时函数，用于管理对象的生命周期和执行清理操作。

4. **内联缓存 (Inline Caches - ICs):**  定义了与 V8 的内联缓存机制相关的运行时函数。这些函数在属性访问 (load/store) 和方法调用等操作中被调用，用于收集类型信息并进行优化。`_Miss` 后缀通常表示缓存未命中，需要执行较慢的路径。

5. **其他运行时函数:**  包含了各种用于支持 JavaScript 语义和 V8 内部操作的运行时函数，例如：
    * **调试 (DebugBreakOnBytecode):**  在特定字节码处触发断点。
    * **属性查找 (LoadLookupSlotForCall):**  在调用上下文中查找属性槽。
    * **对象操作 (元素转换和存储、克隆对象等):**  执行对象属性的修改和复制。

**关于 .tq 文件:**

正如注释所说，如果 `v8/src/runtime/runtime.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 自研的一种领域特定语言，用于更安全、更高效地实现运行时函数。由于该文件以 `.h` 结尾，所以它是标准的 C++ 头文件，其中声明了这些运行时函数的接口。具体的 Torque 实现可能在其他的 `.tq` 文件中。

**与 JavaScript 功能的关系及举例:**

这部分定义的运行时函数直接支撑着 JavaScript 的各种功能。以下是一些 JavaScript 功能与这里声明的运行时函数的对应关系：

* **WebAssembly 互操作:**
    ```javascript
    // 创建一个 Uint8Array 作为 WebAssembly 模块的二进制代码
    const wasmBuffer = new Uint8Array([ /* ... wasm bytecode ... */ ]);
    WebAssembly.instantiate(wasmBuffer).then(module => {
      // 调用 WebAssembly 模块导出的函数
      module.instance.exports.myFunction();
    });
    ```
    上述代码的执行过程中，V8 可能会调用例如 `WasmAllocateFeedbackVector` (用于分配反馈向量以进行优化)、`TierUpJSToWasmWrapper` (用于将 JS 调用桥接到 Wasm) 等运行时函数。

* **WeakRef 和 FinalizationRegistry:**
    ```javascript
    let target = {};
    let registry = new FinalizationRegistry(heldValue => {
      console.log("Target collected!", heldValue);
    });
    let weakRef = new WeakRef(target);
    registry.register(target, "some info");
    target = null; // 解除对 target 的强引用
    // 当垃圾回收器回收 target 时，FinalizationRegistry 的回调会被调用，
    // V8 内部会调用 JSFinalizationRegistryRegisterWeakCellWithUnregisterToken 等运行时函数。
    ```

* **对象属性访问:**
    ```javascript
    const obj = { a: 10 };
    const value = obj.a; // 属性读取
    obj.b = 20;       // 属性写入
    ```
    对于上述代码，V8 可能会在底层调用类似 `KeyedLoadIC_Miss` (如果第一次访问 `obj.a` 时缓存未命中) 或 `KeyedStoreIC_Miss` (如果第一次设置 `obj.b` 时缓存未命中) 的运行时函数。

**代码逻辑推理 (假设输入与输出):**

以 `F(WasmArrayCopy, 5, 1)` 为例：

* **假设输入:**
    * `args_length = 5` (表示传递了 5 个参数)
    * `args_object` 指向一个包含 5 个参数的数组，这些参数可能包括：
        1. 源 WebAssembly 数组
        2. 源数组的起始索引
        3. 目标 WebAssembly 数组
        4. 目标数组的起始索引
        5. 要复制的元素数量
    * `isolate` 指向当前的 V8 隔离区

* **输出:**
    * `ressize = 1`，表示该函数返回一个值（通常是一个指向结果的指针或状态码）。
    * 该函数的输出可能是一个表示复制是否成功的状态码，或者是指向目标数组的指针。

**用户常见的编程错误:**

虽然这些是底层的 C++ 运行时函数，用户通常不会直接调用，但理解它们有助于理解 JavaScript 引擎的行为，并避免导致这些运行时函数触发错误的 JavaScript 代码：

* **WebAssembly 互操作中的类型错误:**  如果 JavaScript 代码尝试将错误类型的数据传递给 WebAssembly 函数，可能会导致 V8 内部的类型检查失败，并可能触发与类型转换相关的 Wasm 运行时函数错误。 例如，将一个 JavaScript 字符串传递给一个期望整数的 WebAssembly 函数。
* **过度依赖弱引用而没有适当的清理:** 如果用户过度依赖 `WeakRef` 和 `FinalizationRegistry`，但没有考虑到对象可能在回调执行前被多次回收，可能会导致意外的行为或错误。例如，在 `FinalizationRegistry` 的回调中尝试访问已经被回收的对象。
* **对对象属性的非预期访问模式:**  V8 的内联缓存依赖于对象属性访问模式的一致性。如果代码对同一个对象的属性进行多种不同类型的访问（例如，读取不同类型的属性），可能会导致内联缓存失效，从而降低性能。虽然这不会直接抛出错误，但会影响性能。

**总结:**

这部分 `v8/src/runtime/runtime.h` 定义了大量底层的 C++ 运行时函数，这些函数是 V8 引擎执行 JavaScript 和 WebAssembly 代码的核心组成部分。它们涵盖了 WebAssembly 的各种操作、弱引用管理、内联缓存优化以及其他支持 JavaScript 语义的功能。理解这些运行时函数有助于深入理解 V8 引擎的工作原理，并能帮助开发者编写更高效、更健壮的 JavaScript 和 WebAssembly 代码。

Prompt: 
```
这是目录为v8/src/runtime/runtime.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
           \
  F(WasmAllocateFeedbackVector, 3, 1)         \
  F(WasmLiftoffDeoptFinish, 1, 1)             \
  F(TierUpJSToWasmWrapper, 1, 1)              \
  F(IsWasmExternalFunction, 1, 1)             \
  F(TierUpWasmToJSWrapper, 1, 1)              \
  F(WasmTriggerTierUp, 1, 1)                  \
  F(WasmDebugBreak, 0, 1)                     \
  F(WasmArrayCopy, 5, 1)                      \
  F(WasmArrayNewSegment, 5, 1)                \
  F(WasmArrayInitSegment, 6, 1)               \
  F(WasmAllocateSuspender, 0, 1)              \
  F(WasmCastToSpecialPrimitiveArray, 2, 1)    \
  F(WasmStringNewSegmentWtf8, 5, 1)           \
  F(WasmStringNewWtf8, 5, 1)                  \
  F(WasmStringNewWtf8Array, 4, 1)             \
  F(WasmStringNewWtf16, 4, 1)                 \
  F(WasmStringNewWtf16Array, 3, 1)            \
  F(WasmStringConst, 2, 1)                    \
  F(WasmStringMeasureUtf8, 1, 1)              \
  F(WasmStringMeasureWtf8, 1, 1)              \
  F(WasmStringEncodeWtf8, 5, 1)               \
  F(WasmStringEncodeWtf16, 6, 1)              \
  F(WasmStringEncodeWtf8Array, 4, 1)          \
  F(WasmStringToUtf8Array, 1, 1)              \
  F(WasmStringAsWtf8, 1, 1)                   \
  F(WasmStringViewWtf8Encode, 7, 1)           \
  F(WasmStringViewWtf8Slice, 3, 1)            \
  F(WasmStringFromCodePoint, 1, 1)            \
  F(WasmStringHash, 1, 1)                     \
  F(WasmSubstring, 3, 1)

#define FOR_EACH_INTRINSIC_WASM_TEST(F, I)                      \
  F(CheckIsOnCentralStack, 0, 1)                                \
  F(CountUnoptimizedWasmToJSWrapper, 1, 1)                      \
  F(DeserializeWasmModule, 2, 1)                                \
  F(DisallowWasmCodegen, 1, 1)                                  \
  F(FlushLiftoffCode, 0, 1)                                     \
  F(EstimateCurrentMemoryConsumption, 0, 1)                     \
  F(FreezeWasmLazyCompilation, 1, 1)                            \
  F(GetWasmExceptionTagId, 2, 1)                                \
  F(GetWasmExceptionValues, 1, 1)                               \
  F(GetWasmRecoveredTrapCount, 0, 1)                            \
  F(HasUnoptimizedJSToJSWrapper, 1, 1)                          \
  F(HasUnoptimizedWasmToJSWrapper, 1, 1)                        \
  F(IsAsmWasmCode, 1, 1)                                        \
  F(IsLiftoffFunction, 1, 1)                                    \
  F(IsThreadInWasm, 0, 1)                                       \
  F(IsTurboFanFunction, 1, 1)                                   \
  F(IsUncompiledWasmFunction, 1, 1)                             \
  F(IsWasmCode, 1, 1)                                           \
  F(IsWasmDebugFunction, 1, 1)                                  \
  F(IsWasmPartialOOBWriteNoop, 0, 1)                            \
  F(IsWasmTrapHandlerEnabled, 0, 1)                             \
  F(SerializeWasmModule, 1, 1)                                  \
  F(SetWasmCompileControls, 2, 1)                               \
  F(SetWasmImportedStringsEnabled, 1, 1)                        \
  F(SetWasmInstantiateControls, 0, 1)                           \
  F(WasmCompiledExportWrappersCount, 0, 1)                      \
  F(WasmDeoptsExecutedCount, 0, 1)                              \
  F(WasmDeoptsExecutedForFunction, 1, 1)                        \
  F(WasmEnterDebugging, 0, 1)                                   \
  IF_V8_WASM_RANDOM_FUZZERS(F, WasmGenerateRandomModule, -1, 1) \
  F(WasmGetNumberOfInstances, 1, 1)                             \
  F(WasmLeaveDebugging, 0, 1)                                   \
  F(WasmNumCodeSpaces, 1, 1)                                    \
  F(WasmSwitchToTheCentralStackCount, 0, 1)                     \
  F(WasmTierUpFunction, 1, 1)                                   \
  F(WasmTraceEnter, 0, 1)                                       \
  F(WasmTraceExit, 1, 1)                                        \
  F(WasmTraceMemory, 1, 1)                                      \
  F(WasmNull, 0, 1)                                             \
  F(WasmArray, 0, 1)                                            \
  F(WasmStruct, 0, 1)

#define FOR_EACH_INTRINSIC_WASM_DRUMBRAKE_TEST(F, I) \
  F(WasmTraceBeginExecution, 0, 1)                   \
  F(WasmTraceEndExecution, 0, 1)

#define FOR_EACH_INTRINSIC_WEAKREF(F, I)                             \
  F(JSFinalizationRegistryRegisterWeakCellWithUnregisterToken, 4, 1) \
  F(JSWeakRefAddToKeptObjects, 1, 1)                                 \
  F(ShrinkFinalizationRegistryUnregisterTokenMap, 1, 1)

#define FOR_EACH_INTRINSIC_RETURN_PAIR_IMPL(F, I) \
  F(DebugBreakOnBytecode, 1, 2)                   \
  F(LoadLookupSlotForCall, 1, 2)

// Most intrinsics are implemented in the runtime/ directory, but ICs are
// implemented in ic.cc for now.
#define FOR_EACH_INTRINSIC_IC(F, I)          \
  F(ElementsTransitionAndStoreIC_Miss, 6, 1) \
  F(KeyedLoadIC_Miss, 4, 1)                  \
  F(KeyedStoreIC_Miss, 5, 1)                 \
  F(DefineKeyedOwnIC_Miss, 5, 1)             \
  F(StoreInArrayLiteralIC_Miss, 5, 1)        \
  F(DefineNamedOwnIC_Slow, 3, 1)             \
  F(KeyedStoreIC_Slow, 3, 1)                 \
  F(DefineKeyedOwnIC_Slow, 3, 1)             \
  F(LoadElementWithInterceptor, 2, 1)        \
  F(LoadGlobalIC_Miss, 4, 1)                 \
  F(LoadGlobalIC_Slow, 3, 1)                 \
  F(LoadIC_Miss, 4, 1)                       \
  F(LoadNoFeedbackIC_Miss, 4, 1)             \
  F(LoadWithReceiverIC_Miss, 5, 1)           \
  F(LoadWithReceiverNoFeedbackIC_Miss, 3, 1) \
  F(LoadPropertyWithInterceptor, 5, 1)       \
  F(StoreCallbackProperty, 5, 1)             \
  F(StoreGlobalIC_Miss, 4, 1)                \
  F(StoreGlobalICNoFeedback_Miss, 2, 1)      \
  F(StoreGlobalIC_Slow, 5, 1)                \
  F(StoreIC_Miss, 5, 1)                      \
  F(DefineNamedOwnIC_Miss, 5, 1)             \
  F(StoreInArrayLiteralIC_Slow, 5, 1)        \
  F(StorePropertyWithInterceptor, 5, 1)      \
  F(CloneObjectIC_Slow, 2, 1)                \
  F(CloneObjectIC_Miss, 4, 1)                \
  F(KeyedHasIC_Miss, 4, 1)                   \
  F(HasElementWithInterceptor, 2, 1)         \
  F(ObjectAssignTryFastcase, 2, 1)

#define FOR_EACH_INTRINSIC_RETURN_OBJECT_IMPL(F, I)               \
  FOR_EACH_INTRINSIC_ARRAY(F, I)                                  \
  FOR_EACH_INTRINSIC_ATOMICS(F, I)                                \
  FOR_EACH_INTRINSIC_BIGINT(F, I)                                 \
  FOR_EACH_INTRINSIC_CLASSES(F, I)                                \
  FOR_EACH_INTRINSIC_COLLECTIONS(F, I)                            \
  FOR_EACH_INTRINSIC_COMPILER(F, I)                               \
  FOR_EACH_INTRINSIC_DATE(F, I)                                   \
  FOR_EACH_INTRINSIC_DEBUG(F, I)                                  \
  FOR_EACH_INTRINSIC_FORIN(F, I)                                  \
  FOR_EACH_INTRINSIC_FUNCTION(F, I)                               \
  FOR_EACH_INTRINSIC_GENERATOR(F, I)                              \
  FOR_EACH_INTRINSIC_IC(F, I)                                     \
  FOR_EACH_INTRINSIC_INTERNAL(F, I)                               \
  FOR_EACH_INTRINSIC_TRACE(F, I)                                  \
  FOR_EACH_INTRINSIC_INTL(F, I)                                   \
  FOR_EACH_INTRINSIC_LITERALS(F, I)                               \
  FOR_EACH_INTRINSIC_MODULE(F, I)                                 \
  FOR_EACH_INTRINSIC_NUMBERS(F, I)                                \
  FOR_EACH_INTRINSIC_OBJECT(F, I)                                 \
  FOR_EACH_INTRINSIC_OPERATORS(F, I)                              \
  FOR_EACH_INTRINSIC_PROMISE(F, I)                                \
  FOR_EACH_INTRINSIC_PROXY(F, I)                                  \
  FOR_EACH_INTRINSIC_REGEXP(F, I)                                 \
  FOR_EACH_INTRINSIC_SCOPES(F, I)                                 \
  FOR_EACH_INTRINSIC_SHADOW_REALM(F, I)                           \
  FOR_EACH_INTRINSIC_STRINGS(F, I)                                \
  FOR_EACH_INTRINSIC_SYMBOL(F, I)                                 \
  FOR_EACH_INTRINSIC_TEMPORAL(F, I)                               \
  FOR_EACH_INTRINSIC_TEST(F, I)                                   \
  FOR_EACH_INTRINSIC_TYPEDARRAY(F, I)                             \
  IF_WASM(FOR_EACH_INTRINSIC_WASM, F, I)                          \
  IF_WASM(FOR_EACH_INTRINSIC_WASM_TEST, F, I)                     \
  IF_WASM_DRUMBRAKE(FOR_EACH_INTRINSIC_WASM_DRUMBRAKE_TEST, F, I) \
  FOR_EACH_INTRINSIC_WEAKREF(F, I)

#define FOR_EACH_THROWING_INTRINSIC(F)       \
  FOR_EACH_THROWING_INTRINSIC_CLASSES(F, F)  \
  FOR_EACH_THROWING_INTRINSIC_INTERNAL(F, F) \
  FOR_EACH_THROWING_INTRINSIC_SCOPES(F, F)

// Defines the list of all intrinsics, coming in 2 flavors, either returning an
// object or a pair.
#define FOR_EACH_INTRINSIC_IMPL(F, I)       \
  FOR_EACH_INTRINSIC_RETURN_PAIR_IMPL(F, I) \
  FOR_EACH_INTRINSIC_RETURN_OBJECT_IMPL(F, I)

#define FOR_EACH_INTRINSIC_RETURN_OBJECT(F) \
  FOR_EACH_INTRINSIC_RETURN_OBJECT_IMPL(F, F)

#define FOR_EACH_INTRINSIC_RETURN_PAIR(F) \
  FOR_EACH_INTRINSIC_RETURN_PAIR_IMPL(F, F)

// The list of all intrinsics, including those that have inline versions, but
// not the inline versions themselves.
#define FOR_EACH_INTRINSIC(F) FOR_EACH_INTRINSIC_IMPL(F, F)

// The list of all inline intrinsics only.
#define FOR_EACH_INLINE_INTRINSIC(I) FOR_EACH_INTRINSIC_IMPL(NOTHING, I)

#define F(name, nargs, ressize)                                 \
  Address Runtime_##name(int args_length, Address* args_object, \
                         Isolate* isolate);
FOR_EACH_INTRINSIC_RETURN_OBJECT(F)
#undef F

//---------------------------------------------------------------------------
// Runtime provides access to all C++ runtime functions.

class Runtime : public AllStatic {
 public:
  enum FunctionId : int32_t {
#define F(name, nargs, ressize) k##name,
#define I(name, nargs, ressize) kInline##name,
    FOR_EACH_INTRINSIC(F) FOR_EACH_INLINE_INTRINSIC(I)
#undef I
#undef F
        kNumFunctions,
  };

  static constexpr int kNumInlineFunctions =
#define COUNT(...) +1
      FOR_EACH_INLINE_INTRINSIC(COUNT);
#undef COUNT

  enum IntrinsicType { RUNTIME, INLINE };

  // Intrinsic function descriptor.
  struct Function {
    FunctionId function_id;
    IntrinsicType intrinsic_type;
    // The JS name of the function.
    const char* name;

    // For RUNTIME functions, this is the C++ entry point.
    // For INLINE functions this is the C++ entry point of the fall back.
    Address entry;

    // The number of arguments expected. nargs is -1 if the function takes
    // a variable number of arguments.
    int8_t nargs;
    // Size of result.  Most functions return a single pointer, size 1.
    int8_t result_size;
  };

  static const int kNotFound = -1;

  // Checks whether the runtime function with the given {id} depends on the
  // "current context", i.e. because it does scoped lookups, or whether it's
  // fine to just pass any context within the same "native context".
  static bool NeedsExactContext(FunctionId id);

  // Checks whether the runtime function with the given {id} never returns
  // to its caller normally, i.e. whether it'll always raise an exception.
  // More specifically: The C++ implementation returns the Heap::exception
  // sentinel, always.
  static bool IsNonReturning(FunctionId id);

  // Check if a runtime function with the given {id} may trigger a heap
  // allocation.
  static bool MayAllocate(FunctionId id);

  // Check if a runtime function with the given {id} is enabled for fuzzing.
  static bool IsEnabledForFuzzing(FunctionId id);

  // Get the intrinsic function with the given name.
  static const Function* FunctionForName(const unsigned char* name, int length);

  // Get the intrinsic function with the given FunctionId.
  V8_EXPORT_PRIVATE static const Function* FunctionForId(FunctionId id);

  // Get the intrinsic function with the given function entry address.
  static const Function* FunctionForEntry(Address ref);

  // Get the runtime intrinsic function table.
  static const Function* RuntimeFunctionTable(Isolate* isolate);

  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool>
  DeleteObjectProperty(Isolate* isolate, Handle<JSReceiver> receiver,
                       Handle<Object> key, LanguageMode language_mode);

  // Perform a property store on object. If the key is a private name (i.e. this
  // is a private field assignment), this method throws if the private field
  // does not exist on object.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  SetObjectProperty(Isolate* isolate, Handle<JSAny> object, Handle<Object> key,
                    Handle<Object> value, MaybeHandle<JSAny> receiver,
                    StoreOrigin store_origin,
                    Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>());
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  SetObjectProperty(Isolate* isolate, Handle<JSAny> object, Handle<Object> key,
                    Handle<Object> value, StoreOrigin store_origin,
                    Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>());

  // Defines a property on object. If the key is a private name (i.e. this is a
  // private field definition), this method throws if the field already exists
  // on object.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  DefineObjectOwnProperty(Isolate* isolate, Handle<JSAny> object,
                          Handle<Object> key, Handle<Object> value,
                          StoreOrigin store_origin);

  // When "receiver" is not passed, it defaults to "lookup_start_object".
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  GetObjectProperty(Isolate* isolate, Handle<JSAny> lookup_start_object,
                    Handle<Object> key,
                    Handle<JSAny> receiver = Handle<JSAny>(),
                    bool* is_found = nullptr);

  // Look up for a private member with a name matching "desc" and return its
  // value. "desc" should be a #-prefixed string, in the case of private fields,
  // it should match the description of the private name symbol. Throw an error
  // if the found private member is an accessor without a getter, or there is no
  // matching private member, or there are more than one matching private member
  // (which would be ambiguous). If the found private member is an accessor with
  // a getter, the getter will be called to set the value.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  GetPrivateMember(Isolate* isolate, Handle<JSReceiver> receiver,
                   Handle<String> desc);

  // Look up for a private member with a name matching "desc" and set it to
  // "value". "desc" should be a #-prefixed string, in the case of private
  // fields, it should match the description of the private name symbol. Throw
  // an error if the found private member is a private method, or an accessor
  // without a setter, or there is no matching private member, or there are more
  // than one matching private member (which would be ambiguous).
  // If the found private member is an accessor with a setter, the setter will
  // be called to set the value.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  SetPrivateMember(Isolate* isolate, Handle<JSReceiver> receiver,
                   Handle<String> desc, Handle<Object> value);

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> HasProperty(
      Isolate* isolate, Handle<Object> object, Handle<Object> key);

  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray>
  GetInternalProperties(Isolate* isolate, Handle<Object>);

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> ThrowIteratorError(
      Isolate* isolate, Handle<Object> object);
};

class RuntimeState {
 public:
  RuntimeState(const RuntimeState&) = delete;
  RuntimeState& operator=(const RuntimeState&) = delete;
#ifndef V8_INTL_SUPPORT
  unibrow::Mapping<unibrow::ToUppercase, 128>* to_upper_mapping() {
    return &to_upper_mapping_;
  }
  unibrow::Mapping<unibrow::ToLowercase, 128>* to_lower_mapping() {
    return &to_lower_mapping_;
  }
#endif

  Runtime::Function* redirected_intrinsic_functions() {
    return redirected_intrinsic_functions_.get();
  }

  void set_redirected_intrinsic_functions(
      Runtime::Function* redirected_intrinsic_functions) {
    redirected_intrinsic_functions_.reset(redirected_intrinsic_functions);
  }

 private:
  RuntimeState() = default;
#ifndef V8_INTL_SUPPORT
  unibrow::Mapping<unibrow::ToUppercase, 128> to_upper_mapping_;
  unibrow::Mapping<unibrow::ToLowercase, 128> to_lower_mapping_;
#endif

  std::unique_ptr<Runtime::Function[]> redirected_intrinsic_functions_;

  friend class Isolate;
  friend class Runtime;
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream&, Runtime::FunctionId);

//---------------------------------------------------------------------------
// Constants used by interface to runtime functions.

using AllocateDoubleAlignFlag = base::BitField<bool, 0, 1>;

// A set of bits returned by Runtime_GetOptimizationStatus.
// These bits must be in sync with bits defined in test/mjsunit/mjsunit.js
enum class OptimizationStatus {
  kIsFunction = 1 << 0,
  kNeverOptimize = 1 << 1,
  kAlwaysOptimize = 1 << 2,
  kMaybeDeopted = 1 << 3,
  kOptimized = 1 << 4,
  kMaglevved = 1 << 5,
  kTurboFanned = 1 << 6,
  kInterpreted = 1 << 7,
  kMarkedForOptimization = 1 << 8,
  kMarkedForConcurrentOptimization = 1 << 9,
  kOptimizingConcurrently = 1 << 10,
  kIsExecuting = 1 << 11,
  kTopmostFrameIsTurboFanned = 1 << 12,
  kLiteMode = 1 << 13,
  kMarkedForDeoptimization = 1 << 14,
  kBaseline = 1 << 15,
  kTopmostFrameIsInterpreted = 1 << 16,
  kTopmostFrameIsBaseline = 1 << 17,
  kIsLazy = 1 << 18,
  kTopmostFrameIsMaglev = 1 << 19,
  kOptimizeOnNextCallOptimizesToMaglev = 1 << 20,
  kMarkedForMaglevOptimization = 1 << 21,
  kMarkedForConcurrentMaglevOptimization = 1 << 22,
};

// The number of isolates used for testing in d8.
V8_EXPORT_PRIVATE extern int g_num_isolates_for_testing;

}  // namespace internal
}  // namespace v8

#endif  // V8_RUNTIME_RUNTIME_H_

"""


```