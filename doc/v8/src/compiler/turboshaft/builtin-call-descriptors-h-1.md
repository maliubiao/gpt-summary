Response:
The user wants to understand the functionality of the provided C++ header file, `builtin-call-descriptors.h`, which seems to define descriptors for calling built-in functions within the V8 JavaScript engine's Turboshaft compiler.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name and the structure of the code (structs inheriting from `Descriptor`) strongly suggest that this file defines interfaces for calling built-in functions. Each struct likely represents a specific built-in.

2. **Analyze the `Descriptor` structure:**  Observe the common members in each struct:
    * `kFunction`:  This links the descriptor to a specific `Builtin` enum value, indicating which built-in function is being described.
    * `arguments_t`:  Defines the types of the arguments expected by the built-in. `V<T>` probably represents a value of type `T` within the Turboshaft representation.
    * `results_t`: Defines the return type(s) of the built-in.
    * `kNeedsFrameState`, `kNeedsContext`:  Flags indicating if the built-in requires frame state or context information.
    * `kProperties`: Flags related to the behavior of the built-in, like whether it can deoptimize or throw exceptions.
    * `kEffects`:  Describes the side effects of calling the built-in, such as memory access or allocation.

3. **Recognize the WebAssembly context:** The presence of numerous built-ins prefixed with "Wasm" clearly indicates a strong connection to WebAssembly support within V8.

4. **Infer individual built-in functionalities:**  Based on the names of the structs (e.g., `WasmStringToUtf8Array`, `WasmTableSet`, `WasmStringEqual`), try to deduce what each built-in does.

5. **Address the `.tq` question:** The prompt asks about a `.tq` extension. Since this file is `.h`, it's not a Torque file. Explain the role of Torque in V8, which is related to defining built-ins but is a different mechanism.

6. **Connect to JavaScript (if applicable):**  For built-ins that have clear parallels in JavaScript, provide illustrative examples. Focus on the *WebAssembly* related functionalities and how they interact with JavaScript's WebAssembly API.

7. **Handle code logic and assumptions:**  Since these are *descriptors*, they don't contain executable code logic. They *describe* the interface. Emphasize this distinction. For input/output, focus on the *types* of arguments and results defined in the descriptors.

8. **Address common programming errors:**  Since these are low-level built-ins, the "common errors" are more about *misusing* the WebAssembly API in JavaScript or encountering WebAssembly runtime errors.

9. **Summarize the functionality:** Condense the observations into a concise summary.

10. **Review and refine:**  Ensure the language is clear, accurate, and directly addresses all parts of the prompt. For example, make sure to explicitly state that this is *not* Torque code and to clarify the distinction.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Perhaps these are the *implementations* of the built-ins.
* **Correction:**  The `Descriptor` structure and lack of actual code point towards them being *interfaces* or *metadata* about the built-ins, not the implementations themselves. The `Builtin::k...` member reinforces this.
* **Initial thought:** Focus only on the direct JavaScript equivalents of the functions.
* **Refinement:**  Emphasize the *WebAssembly* context, as most of the built-ins are WASM-specific. The JavaScript examples should demonstrate how these WASM functionalities might be used via the JavaScript WebAssembly API.
* **Initial thought:**  Provide very detailed explanations of each `OpEffects` flag.
* **Refinement:** Keep the explanations of `OpEffects` concise, as the focus should be on the high-level functionality of the built-ins. A brief explanation of the categories is sufficient.
这是对V8源代码文件 `v8/src/compiler/turboshaft/builtin-call-descriptors.h` 的功能归纳，基于提供的第二部分代码。

**功能归纳:**

总的来说，`v8/src/compiler/turboshaft/builtin-call-descriptors.h` 文件定义了一系列结构体，这些结构体充当了 Turboshaft 编译器中调用特定 V8 built-in 函数的描述符。  每个结构体都代表一个特定的 built-in 函数，并详细说明了调用该函数所需的参数类型、返回结果类型、以及该调用的属性和副作用。

**具体功能点:**

1. **定义 Built-in 函数的接口:**  每个结构体都关联一个 `Builtin::k...` 枚举值，唯一标识一个 V8 built-in 函数。这为 Turboshaft 编译器提供了一种类型安全的方式来引用和调用这些 built-in 函数。

2. **描述参数和返回值类型:**  `arguments_t` 和 `results_t` 成员分别使用 `std::tuple` 和模板 `V<>` 来指定 built-in 函数的参数和返回值类型。这有助于 Turboshaft 进行类型检查和代码生成。例如，`WasmStringToUtf8Array` 期望一个 `V<String>` 类型的参数并返回一个 `V<WasmArray>` 类型的返回值。

3. **指定调用属性:** `kNeedsFrameState` 和 `kNeedsContext` 标志表明调用 built-in 函数是否需要当前的帧状态或上下文信息。`kProperties` 成员则定义了该调用的其他属性，例如是否可能触发 deoptimization 或抛出异常。

4. **描述副作用 (Effects):** `kEffects` 成员使用 `OpEffects` 类型来详细描述调用 built-in 函数可能产生的副作用，例如读取内存、写入堆内存、分配内存、改变控制流等。  这对于编译器的优化和正确性分析至关重要。例如，`WasmStringEncodeWtf16Array` 的副作用包括 `CanReadMemory()`, `CanWriteHeapMemory()` 和 `CanLeaveCurrentFunction()`。

5. **涵盖 WebAssembly 特性:**  从结构体的命名可以看出，该文件主要关注与 WebAssembly 相关 built-in 函数的描述，例如字符串处理 (`WasmStringToUtf8Array`, `WasmStringEncodeWtf16Array`)、内存操作 (`WasmAllocateFixedArray`)、表操作 (`WasmTableSet`, `WasmTableInit`)、原子操作 (`WasmI32AtomicWait`) 和异常处理 (`WasmThrow`).

6. **定义异常相关的 Built-in:** 文件中还定义了一些与抛出异常相关的 built-in 函数的描述符，例如 `ThrowDataViewDetachedError`, `ThrowDataViewOutOfBounds` 等。这些 built-in 函数在特定错误条件下被调用。

**关于 .tq 文件和 JavaScript 关系:**

* 提供的代码是 C++ 头文件 (`.h`)，不是 Torque 文件 (`.tq`)。
* 如果 `builtin-call-descriptors.h` 以 `.tq` 结尾，那么它将是使用 V8 的 Torque 语言编写的。Torque 是一种用于定义 V8 built-in 函数的领域特定语言。Torque 文件会生成 C++ 代码。

**JavaScript 示例 (与 WebAssembly 功能相关):**

虽然这个头文件本身是 C++ 代码，但它描述的 built-in 函数是 V8 执行 JavaScript 和 WebAssembly 代码的基础。以下是一些与文件中描述的 built-in 函数相关的 JavaScript WebAssembly API 用例：

```javascript
// 对应 WasmStringToUtf8Array：将 WebAssembly 字符串转换为 UTF-8 数组
const wasmString = "你好，世界"; // 假设这是从 WebAssembly 实例获取的字符串
const encoder = new TextEncoder();
const utf8Array = encoder.encode(wasmString);
console.log(utf8Array);

// 对应 WasmStringEncodeWtf16Array：将 JavaScript 字符串编码为 WTF-16 数组 (通常在 WebAssembly 内部使用)
const jsString = "你好，世界";
const buffer = new ArrayBuffer(jsString.length * 2); // 假设分配了足够的空间
const view = new Uint16Array(buffer);
for (let i = 0; i < jsString.length; i++) {
  view[i] = jsString.charCodeAt(i);
}
console.log(view);

// 对应 WasmTableSet：设置 WebAssembly Table 中的元素
const table = new WebAssembly.Table({ initial: 1, element: 'anyfunc' });
const instance = new WebAssembly.Instance(module, { table });
table.set(0, instance.exports.someFunction);

// 对应 WasmThrow：在 WebAssembly 中抛出异常
// (在 JavaScript 中通常会捕获 WebAssembly 的异常)
try {
  // 调用一个可能抛出异常的 WebAssembly 函数
} catch (e) {
  console.error("WebAssembly exception caught:", e);
}

// 对应 WasmI32AtomicWait：执行 WebAssembly 的原子等待操作
const sab = new SharedArrayBuffer(4);
const int32Array = new Int32Array(sab);
Atomics.wait(int32Array, 0, 0, 1000); // 等待 int32Array[0] 的值变为非 0，超时时间 1000ms
```

**代码逻辑推理 (由于是描述符，没有具体的代码逻辑):**

这个文件定义的是接口，而不是具体的代码实现。我们只能推断出以下逻辑关系：

* **假设输入 (针对 `WasmStringMeasureUtf8`):** 一个 JavaScript 字符串对象 (`V<String>`).
* **预期输出:**  该字符串的 UTF-8 编码的字节数 (`V<Word32>`).

* **假设输入 (针对 `WasmTableSet`):**  一个 WebAssembly 表的指针 (`V<WordPtr>`)，一个索引 (`V<Word32>`)，以及要设置的对象 (`V<Object>`).
* **预期输出:**  一个表示操作结果的对象 (`V<Object>`).

**用户常见的编程错误 (与 WebAssembly 相关):**

由于这个文件描述的是底层的 built-in 函数，直接与这些函数交互的错误通常发生在编写和使用 WebAssembly 代码时：

1. **类型不匹配:**  在 JavaScript 中调用 WebAssembly 函数时，传递的参数类型与 WebAssembly 函数期望的类型不符。例如，尝试将一个 JavaScript 字符串直接传递给一个期望数字的 WebAssembly 函数。

2. **内存越界访问:** 在 WebAssembly 中尝试访问超出线性内存边界的地址。这可能导致 `WasmThrow` built-in 函数被调用，抛出异常。

3. **表操作错误:**  尝试访问或设置 WebAssembly 表中超出范围的索引。例如，使用 `table.set()` 设置超出 `initial` 或 `maximum` 大小的索引。

4. **原子操作使用不当:**  错误地使用原子操作，例如在没有共享内存的情况下使用 `Atomics.wait` 或 `Atomics.notify`。

5. **字符串编码错误:**  在 JavaScript 和 WebAssembly 之间传递字符串时，编码方式不一致可能导致乱码或错误。例如，假设 WebAssembly 期望 UTF-8 编码，但 JavaScript 传递的是 UTF-16 编码的字符串。

**总结:**

`v8/src/compiler/turboshaft/builtin-call-descriptors.h` 的第二部分主要定义了 Turboshaft 编译器在处理 WebAssembly 代码时需要调用的各种 built-in 函数的描述符。这些描述符详细说明了每个 built-in 函数的参数、返回值、属性和副作用，为编译器的优化和代码生成提供了必要的元信息。 它也包含了一些与 JavaScript 异常处理相关的 built-in 函数描述符。 这个文件是 V8 内部实现细节的一部分，开发者通常不需要直接修改或理解其内容，但了解其功能有助于理解 V8 如何执行 JavaScript 和 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/builtin-call-descriptors.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/builtin-call-descriptors.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
();
  };

  struct WasmStringToUtf8Array : public Descriptor<WasmStringToUtf8Array> {
    static constexpr auto kFunction = Builtin::kWasmStringToUtf8Array;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<WasmArray>>;
    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocate();
  };

  struct WasmStringEncodeWtf16Array
      : public Descriptor<WasmStringEncodeWtf16Array> {
    static constexpr auto kFunction = Builtin::kWasmStringEncodeWtf16Array;
    using arguments_t = std::tuple<V<String>, V<WasmArray>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory()
                                              .CanWriteHeapMemory()
                                              .CanLeaveCurrentFunction();
  };

  struct WasmFloat64ToString : public Descriptor<WasmFloat64ToString> {
    static constexpr auto kFunction = Builtin::kWasmFloat64ToString;
    using arguments_t = std::tuple<V<Float64>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanAllocateWithoutIdentity();
  };

  struct WasmIntToString : public Descriptor<WasmIntToString> {
    static constexpr auto kFunction = Builtin::kWasmIntToString;
    using arguments_t = std::tuple<V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoDeopt;
    static constexpr OpEffects kEffects =
        base_effects.CanAllocateWithoutIdentity();
  };

  struct WasmStringToDouble : public Descriptor<WasmStringToDouble> {
    static constexpr auto kFunction = Builtin::kWasmStringToDouble;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Float64>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmAllocateFixedArray : public Descriptor<WasmAllocateFixedArray> {
    static constexpr auto kFunction = Builtin::kWasmAllocateFixedArray;
    using arguments_t = std::tuple<V<WordPtr>>;
    using results_t = std::tuple<V<FixedArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanAllocate();
  };

  struct WasmThrow : public Descriptor<WasmThrow> {
    static constexpr auto kFunction = Builtin::kWasmThrow;
    using arguments_t = std::tuple<V<Object>, V<FixedArray>>;
    using results_t = std::tuple<OpIndex>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadHeapMemory().CanChangeControlFlow();
  };

  struct WasmI32AtomicWait : public Descriptor<WasmI32AtomicWait> {
    static constexpr auto kFunction = Builtin::kWasmI32AtomicWait;
    using arguments_t = std::tuple<V<Word32>, V<WordPtr>, V<Word32>, V<BigInt>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct WasmI64AtomicWait : public Descriptor<WasmI64AtomicWait> {
    static constexpr auto kFunction = Builtin::kWasmI64AtomicWait;
    using arguments_t = std::tuple<V<Word32>, V<WordPtr>, V<BigInt>, V<BigInt>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

  struct WasmFunctionTableGet : public Descriptor<WasmFunctionTableGet> {
    static constexpr auto kFunction = Builtin::kWasmFunctionTableGet;
    using arguments_t = std::tuple<V<WordPtr>, V<WordPtr>, V<Word32>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanAllocate();
  };

  struct WasmTableSetFuncRef : public Descriptor<WasmTableSetFuncRef> {
    static constexpr auto kFunction = Builtin::kWasmTableSetFuncRef;
    using arguments_t =
        std::tuple<V<WordPtr>, V<Word32>, V<WordPtr>, V<WasmFuncRef>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanWriteMemory();
  };

  struct WasmTableSet : public Descriptor<WasmTableSet> {
    static constexpr auto kFunction = Builtin::kWasmTableSet;
    using arguments_t =
        std::tuple<V<WordPtr>, V<Word32>, V<WordPtr>, V<Object>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanWriteMemory();
  };

  struct WasmTableInit : public Descriptor<WasmTableInit> {
    static constexpr auto kFunction = Builtin::kWasmTableInit;
    using arguments_t =
        std::tuple<V<WordPtr>, V<Word32>, V<Word32>, V<Smi>, V<Smi>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanWriteMemory();
  };

  struct WasmTableCopy : public Descriptor<WasmTableCopy> {
    static constexpr auto kFunction = Builtin::kWasmTableCopy;
    using arguments_t =
        std::tuple<V<WordPtr>, V<WordPtr>, V<WordPtr>, V<Smi>, V<Smi>, V<Smi>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory();
  };

  struct WasmTableGrow : public Descriptor<WasmTableGrow> {
    static constexpr auto kFunction = Builtin::kWasmTableGrow;
    using arguments_t = std::tuple<V<Smi>, V<WordPtr>, V<Word32>, V<Object>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanAllocate();
  };

  struct WasmTableFill : public Descriptor<WasmTableFill> {
    static constexpr auto kFunction = Builtin::kWasmTableFill;
    using arguments_t =
        std::tuple<V<WordPtr>, V<WordPtr>, V<Word32>, V<Smi>, V<Object>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanWriteMemory();
  };

  struct WasmArrayNewSegment : public Descriptor<WasmArrayNewSegment> {
    static constexpr auto kFunction = Builtin::kWasmArrayNewSegment;
    using arguments_t =
        std::tuple<V<Word32>, V<Word32>, V<Word32>, V<Smi>, V<Smi>, V<Map>>;
    using results_t = std::tuple<V<WasmArray>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadHeapMemory().CanAllocate();
  };

  struct WasmArrayInitSegment : public Descriptor<WasmArrayInitSegment> {
    static constexpr auto kFunction = Builtin::kWasmArrayInitSegment;
    using arguments_t = std::tuple<V<Word32>, V<Word32>, V<Word32>, V<Smi>,
                                   V<Smi>, V<Smi>, V<HeapObject>>;
    using results_t = std::tuple<V<Object>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanWriteHeapMemory().CanReadHeapMemory();
  };

  struct WasmStringNewWtf8 : public Descriptor<WasmStringNewWtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringNewWtf8;
    using arguments_t = std::tuple<V<WordPtr>, V<Word32>, V<Word32>, V<Smi>>;
    using results_t = std::tuple<V<WasmStringRefNullable>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory()
                                              .CanAllocateWithoutIdentity()
                                              .CanLeaveCurrentFunction();
  };

  struct WasmStringNewWtf16 : public Descriptor<WasmStringNewWtf16> {
    static constexpr auto kFunction = Builtin::kWasmStringNewWtf16;
    using arguments_t = std::tuple<V<Word32>, V<WordPtr>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects = base_effects.CanReadHeapMemory()
                                              .CanAllocateWithoutIdentity()
                                              .CanLeaveCurrentFunction();
  };

  struct WasmStringFromDataSegment
      : public Descriptor<WasmStringFromDataSegment> {
    static constexpr auto kFunction = Builtin::kWasmStringFromDataSegment;
    using arguments_t =
        std::tuple<V<Word32>, V<Word32>, V<Word32>, V<Smi>, V<Smi>, V<Smi>>;
    using results_t = std::tuple<V<WasmStringRefNullable>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoDeopt;
    // No "CanReadMemory" because data segments are immutable.
    static constexpr OpEffects kEffects =
        base_effects.CanAllocateWithoutIdentity().RequiredWhenUnused();
  };

  struct WasmStringConst : public Descriptor<WasmStringConst> {
    static constexpr auto kFunction = Builtin::kWasmStringConst;
    using arguments_t = std::tuple<V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadHeapMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringMeasureUtf8 : public Descriptor<WasmStringMeasureUtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringMeasureUtf8;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringMeasureWtf8 : public Descriptor<WasmStringMeasureWtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringMeasureWtf8;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringEncodeWtf8 : public Descriptor<WasmStringEncodeWtf8> {
    static constexpr auto kFunction = Builtin::kWasmStringEncodeWtf8;
    using arguments_t = std::tuple<V<WordPtr>, V<Word32>, V<Word32>, V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory();
  };

  struct WasmStringEncodeWtf16 : public Descriptor<WasmStringEncodeWtf16> {
    static constexpr auto kFunction = Builtin::kWasmStringEncodeWtf16;
    using arguments_t = std::tuple<V<String>, V<WordPtr>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanLeaveCurrentFunction();
  };

  struct WasmStringEqual : public Descriptor<WasmStringEqual> {
    static constexpr auto kFunction = Builtin::kWasmStringEqual;
    using arguments_t = std::tuple<V<String>, V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringIsUSVSequence : public Descriptor<WasmStringIsUSVSequence> {
    static constexpr auto kFunction = Builtin::kWasmStringIsUSVSequence;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringViewWtf8Advance
      : public Descriptor<WasmStringViewWtf8Advance> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf8Advance;
    using arguments_t = std::tuple<V<ByteArray>, V<Word32>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringViewWtf8Encode
      : public Descriptor<WasmStringViewWtf8Encode> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf8Encode;
    using arguments_t = std::tuple<V<WordPtr>, V<Word32>, V<Word32>,
                                   V<ByteArray>, V<Smi>, V<Smi>>;
    using results_t = std::tuple<V<Word32>, V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory().CanLeaveCurrentFunction();
  };

  struct WasmStringViewWtf16Encode
      : public Descriptor<WasmStringViewWtf16Encode> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf16Encode;
    using arguments_t =
        std::tuple<V<WordPtr>, V<Word32>, V<Word32>, V<String>, V<Smi>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties =
        Operator::kNoDeopt | Operator::kNoThrow;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteMemory();
  };

  struct WasmStringViewWtf16GetCodeUnit
      : public Descriptor<WasmStringViewWtf16GetCodeUnit> {
    static constexpr auto kFunction = Builtin::kWasmStringViewWtf16GetCodeUnit;
    using arguments_t = std::tuple<V<String>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringCodePointAt : public Descriptor<WasmStringCodePointAt> {
    static constexpr auto kFunction = Builtin::kWasmStringCodePointAt;
    using arguments_t = std::tuple<V<String>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct WasmStringAsIter : public Descriptor<WasmStringAsIter> {
    static constexpr auto kFunction = Builtin::kWasmStringAsIter;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<WasmStringViewIter>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanAllocate();
  };

  struct WasmStringViewIterNext : public Descriptor<WasmStringViewIterNext> {
    static constexpr auto kFunction = Builtin::kWasmStringViewIterNext;
    using arguments_t = std::tuple<V<WasmStringViewIter>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteHeapMemory();
  };

  struct WasmStringViewIterAdvance
      : public Descriptor<WasmStringViewIterAdvance> {
    static constexpr auto kFunction = Builtin::kWasmStringViewIterAdvance;
    using arguments_t = std::tuple<V<WasmStringViewIter>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteHeapMemory();
  };

  struct WasmStringViewIterRewind
      : public Descriptor<WasmStringViewIterRewind> {
    static constexpr auto kFunction = Builtin::kWasmStringViewIterRewind;
    using arguments_t = std::tuple<V<WasmStringViewIter>, V<Word32>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanWriteHeapMemory();
  };

  struct WasmStringViewIterSlice : public Descriptor<WasmStringViewIterSlice> {
    static constexpr auto kFunction = Builtin::kWasmStringViewIterSlice;
    using arguments_t = std::tuple<V<WasmStringViewIter>, V<Word32>>;
    using results_t = std::tuple<V<String>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects =
        base_effects.CanReadMemory().CanAllocateWithoutIdentity();
  };

  struct WasmStringHash : public Descriptor<WasmStringHash> {
    static constexpr auto kFunction = Builtin::kWasmStringHash;
    using arguments_t = std::tuple<V<String>>;
    using results_t = std::tuple<V<Word32>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kEliminatable;
    static constexpr OpEffects kEffects = base_effects.CanReadMemory();
  };

  struct ThrowDataViewDetachedError
      : public Descriptor<ThrowDataViewDetachedError> {
    static constexpr auto kFunction = Builtin::kThrowDataViewDetachedError;
    using arguments_t = std::tuple<>;
    using results_t = std::tuple<OpIndex>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct ThrowDataViewOutOfBounds
      : public Descriptor<ThrowDataViewOutOfBounds> {
    static constexpr auto kFunction = Builtin::kThrowDataViewOutOfBounds;
    using arguments_t = std::tuple<>;
    using results_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct ThrowDataViewTypeError : public Descriptor<ThrowDataViewTypeError> {
    static constexpr auto kFunction = Builtin::kThrowDataViewTypeError;
    using arguments_t = std::tuple<V<JSDataView>>;
    using results_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects =
        base_effects.CanReadHeapMemory().CanChangeControlFlow();
  };

  struct ThrowIndexOfCalledOnNull
      : public Descriptor<ThrowIndexOfCalledOnNull> {
    static constexpr auto kFunction = Builtin::kThrowIndexOfCalledOnNull;
    using arguments_t = std::tuple<>;
    using results_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoWrite;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct ThrowToLowerCaseCalledOnNull
      : public Descriptor<ThrowToLowerCaseCalledOnNull> {
    static constexpr auto kFunction = Builtin::kThrowToLowerCaseCalledOnNull;
    using arguments_t = std::tuple<>;
    using results_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoWrite;
    static constexpr OpEffects kEffects = base_effects.CanChangeControlFlow();
  };

  struct WasmFastApiCallTypeCheckAndUpdateIC
      : public Descriptor<WasmFastApiCallTypeCheckAndUpdateIC> {
    static constexpr auto kFunction =
        Builtin::kWasmFastApiCallTypeCheckAndUpdateIC;
    using arguments_t = std::tuple<V<Object>, V<Object>>;
    using results_t = std::tuple<V<Smi>>;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = true;
    static constexpr Operator::Properties kProperties = Operator::kNoWrite;
    static constexpr OpEffects kEffects =
        base_effects.CanLeaveCurrentFunction();
  };

  struct WasmPropagateException : public Descriptor<WasmPropagateException> {
    static constexpr auto kFunction = Builtin::kWasmPropagateException;
    using arguments_t = std::tuple<>;
    using results_t = Never;

    static constexpr bool kNeedsFrameState = false;
    static constexpr bool kNeedsContext = false;
    static constexpr Operator::Properties kProperties = Operator::kNoProperties;
    static constexpr OpEffects kEffects = base_effects.CanCallAnything();
  };

#endif  // V8_ENABLE_WEBASSEMBLY
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_BUILTIN_CALL_DESCRIPTORS_H_
```