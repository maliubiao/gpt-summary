Response:
Let's break down the thought process for analyzing this Torque code snippet.

**1. Initial Scan and High-Level Understanding:**

* **File Extension:**  The `.tq` extension immediately flags this as a Torque file within the V8 codebase. This means it's dealing with low-level built-in functions and potentially interacting with V8's internal representations of JavaScript objects.
* **Namespace:** The `namespace wasm` clearly indicates these functions are related to WebAssembly support within V8.
* **`builtin` keyword:**  This is a strong indicator that these are implementations of functions directly callable from WebAssembly or used internally by V8's WebAssembly machinery. They are not regular JavaScript functions.
* **`tail` keyword:** This suggests these functions often terminate by calling another function. This is an optimization technique for function calls.
* **`ThrowWasmTrap...` functions:**  These immediately stand out as error handling mechanisms within the WebAssembly context. They signal different kinds of runtime errors in WebAssembly.

**2. Grouping and Categorization (Mental or Written):**

As I read through, I started to mentally group the functions based on their apparent purpose:

* **Traps/Errors:**  `ThrowWasmTrap...` functions. Obvious error handling.
* **Memory Access:**  `dAccess`, `GetRefAt`, `LoadPointerFromRootRegister`. These seem to deal with raw memory access and potentially accessing V8's internal data structures.
* **Thread Management:** `ModifyThreadInWasmFlag`. Hints at managing the state of a thread executing WebAssembly.
* **String Creation (from Wasm):** `WasmStringNewWtf8`, `WasmStringNewWtf8Array`, `WasmStringNewWtf16`, `WasmStringNewWtf16Array`, `WasmStringFromDataSegment`, `WasmStringConst`, `WasmStringFromCodePoint`. A significant portion is dedicated to creating V8 strings from WebAssembly memory.
* **String Manipulation/Conversion (Wasm -> JS):** `WasmStringAsWtf16`, `WasmStringMeasureUtf8`, `WasmStringMeasureWtf8`, `WasmStringEncodeWtf8`, `WasmStringEncodeWtf8Array`, `WasmStringToUtf8Array`, `WasmStringEncodeWtf16`, `WasmStringEncodeWtf16Array`, `WasmStringConcat`, `WasmStringEqual`, `WasmStringIsUSVSequence`, `WasmStringAsWtf8`. These seem to convert and manipulate strings between WebAssembly and JavaScript representations.
* **String Views/Iteration:** `WasmStringViewWtf8Advance`, `WasmStringViewWtf8Encode`, `WasmStringViewWtf8Slice`, `WasmStringViewWtf16GetCodeUnit`, `WasmStringViewWtf16Encode`, `WasmStringViewWtf16Slice`, `WasmStringAsIter`, `WasmStringCodePointAt`, `WasmStringViewIterNext`, `WasmStringViewIterAdvance`, `WasmStringViewIterRewind`, `WasmStringViewIterSlice`. Functions for working with "views" of strings, likely for efficient access without full copying.
* **String Conversion (Other Types):** `WasmIntToString`, `WasmStringToDouble`. Converting between numbers and strings.
* **String Hashing:** `WasmStringHash`.
* **Type Conversion (Wasm -> JS):** `WasmAnyConvertExtern`.
* **Fast API Calls:** `WasmFastApiCallTypeCheckAndUpdateIC`. Optimizations for calling JavaScript functions from WebAssembly.
* **Utility/Helpers (Macros, Structs):** `GetRefAt`, `TwoByteToOneByteIterator`, `StringFromTwoByteSlice`, `IsWtf8CodepointStart`, `AlignWtf8PositionForward`, `AlignWtf8PositionBackward`, `NewPositionAndBytesWritten`, `IsLeadSurrogate`, `IsTrailSurrogate`, `CombineSurrogatePair`. These are lower-level building blocks or helper functions.
* **Error Throwing (Generic JS Errors):** `ThrowToLowerCaseCalledOnNull`, `ThrowIndexOfCalledOnNull`, `ThrowDataViewTypeError`, `ThrowDataViewDetachedError`, `ThrowDataViewOutOfBounds`. These are for throwing standard JavaScript errors in WebAssembly contexts.

**3. Analyzing Key Functions/Macros in Detail:**

I picked out some representative functions and macros to understand their mechanics:

* **`ThrowWasmTrap...`:**  Simple, just calls a generic `WasmTrap` with a specific error message template.
* **`GetRefAt`:**  Clearly for getting a raw memory reference to a specific type at an offset. This is very low-level.
* **`ModifyThreadInWasmFlag`:**  Shows interaction with V8's internal thread state.
* **`WasmStringNewWtf8` and `WasmStringNewWtf16`:**  Demonstrate how WebAssembly provides raw memory and length to construct V8 strings. The `runtime::` prefix indicates calls to V8's runtime functions.
* **`StringFromTwoByteSlice`:** This is interesting due to the optimization considerations. It highlights the trade-offs in creating efficient string representations (one-byte vs. two-byte).
* **`WasmStringViewWtf8Advance` and related:** Shows how UTF-8 string views are handled, including aligning to codepoint boundaries.
* **`WasmStringCodePointAt`:**  Demonstrates handling of surrogate pairs for Unicode.
* **`WasmIntToString`:**  Illustrates different paths for converting integers to strings based on radix and whether the integer fits in a Smi.
* **`WasmFastApiCallTypeCheckAndUpdateIC`:**  Shows how V8 optimizes calls from WebAssembly to JavaScript by caching type information.

**4. Connecting to JavaScript and Examples:**

Once I understood the core functions, I could start thinking about how these relate to JavaScript:

* **Traps:** Directly map to WebAssembly runtime errors that would be thrown as JavaScript exceptions if they occurred in a WebAssembly module.
* **String Creation:**  Relates to how JavaScript engines handle strings passed from WebAssembly.
* **String Manipulation:** Mirrors JavaScript string methods like `substring`, `charAt`, `indexOf`, etc.
* **Type Conversion:**  Corresponds to JavaScript's implicit and explicit type conversions.
* **Fast API Calls:**  Demonstrates the underlying mechanics that make calling JavaScript functions from WebAssembly efficient.

**5. Identifying Potential Errors:**

Based on the function names and logic, I could infer common programming errors:

* **Out-of-bounds access:**  `ThrowWasmTrap...OutOfBounds` functions are a clear sign of this.
* **Division by zero:** `ThrowWasmTrapDivByZero`.
* **Type mismatches:** `ThrowWasmTrapFuncSigMismatch`, `ThrowWasmTrapIllegalCast`.
* **Null dereferences:** `ThrowWasmTrapNullDereference`.
* **Invalid string operations:** Trying to access characters beyond string bounds.
* **Incorrect data view usage:**  Errors related to `DataView`.

**6. Structuring the Output:**

Finally, I organized the information into the requested categories:

* **Functionality Listing:**  A comprehensive list of what the code does.
* **Torque Source:**  Confirmation of the file type.
* **JavaScript Relationship:**  Explaining how the code connects to JavaScript features and providing illustrative examples.
* **Code Logic Reasoning:** Choosing a representative function (like `WasmStringCodePointAt`) and walking through potential inputs and outputs.
* **Common Programming Errors:** Listing errors and providing simple JavaScript examples that could lead to the corresponding WebAssembly traps.
* **Overall Functionality Summary:** A concise summary of the code's purpose.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on individual functions. I realized it was important to group them by their broader purpose to understand the overall picture.
* I made sure to connect the low-level Torque code to higher-level JavaScript concepts to make the explanation more accessible.
* I refined the examples to be clear and directly related to the WebAssembly traps.

By following this structured approach, I could systematically analyze the Torque code and generate a comprehensive explanation.
好的，这是对 `v8/src/builtins/wasm.tq` 代码的功能进行归纳的第二部分，结合第一部分的信息，我们可以更全面地了解它的作用。

**整体功能归纳 (结合第一部分和第二部分):**

`v8/src/builtins/wasm.tq` 是 V8 引擎中专门为 WebAssembly (Wasm) 提供内置函数实现的 Torque 源代码文件。它定义了 Wasm 执行过程中需要的一些底层操作和辅助函数，主要涉及以下几个方面：

1. **Wasm 陷阱 (Traps) 处理:** 定义了各种 Wasm 运行时可能发生的错误（陷阱），例如除零错误、内存访问越界、函数签名不匹配等等。这些内置函数负责抛出相应的 Wasm 陷阱，最终会被转换为 JavaScript 的异常。

2. **内存访问:** 提供了直接操作内存的宏，例如 `GetRefAt`，允许在 Wasm 执行环境中进行底层的内存读写操作。

3. **线程状态管理:** 包含修改 Wasm 线程状态的宏，例如 `ModifyThreadInWasmFlag`，用于标记当前线程是否正在执行 Wasm 代码。

4. **字符串处理:**  这是该文件的一个核心功能，提供了多种用于在 Wasm 和 JavaScript 之间创建、操作和转换字符串的内置函数：
    * **创建 Wasm 字符串:**  从 Wasm 线性内存或数组中创建 V8 的字符串对象 (`WasmStringNewWtf8`, `WasmStringNewWtf16` 等)。
    * **测量 Wasm 字符串:** 获取 Wasm 字符串的 UTF-8 或 WTF-8 编码长度 (`WasmStringMeasureUtf8`, `WasmStringMeasureWtf8`).
    * **编码 Wasm 字符串:** 将 V8 字符串编码到 Wasm 线性内存或数组中 (`WasmStringEncodeWtf8`, `WasmStringEncodeWtf16` 等)。
    * **Wasm 字符串转换为字节数组:**  将 V8 字符串转换为 WTF-8 编码的字节数组 (`WasmStringAsWtf8`, `WasmStringToUtf8Array`).
    * **Wasm 字符串连接:** 连接两个 Wasm 字符串 (`WasmStringConcat`).
    * **Wasm 字符串比较:** 比较两个 Wasm 字符串是否相等 (`WasmStringEqual`).
    * **Wasm 字符串切片:**  创建 Wasm 字符串的子串 (`WasmStringViewWtf8Slice`, `WasmStringViewWtf16Slice`).
    * **Wasm 字符串迭代:**  提供遍历 Wasm 字符串中代码点的功能 (`WasmStringAsIter`, `WasmStringCodePointAt`, `WasmStringViewIterNext` 等)。
    * **其他 Wasm 字符串操作:**  例如判断字符串是否为 USV 序列 (`WasmStringIsUSVSequence`)，获取字符串的哈希值 (`WasmStringHash`)。

5. **类型转换:** 提供了在 Wasm 和 JavaScript 类型之间进行转换的内置函数，例如将整数转换为字符串 (`WasmIntToString`)，将字符串转换为浮点数 (`WasmStringToDouble`)，以及将 JavaScript 对象转换为 Wasm 的 externref (`WasmAnyConvertExtern`).

6. **快速 API 调用优化:**  包含用于优化从 Wasm 调用 JavaScript 函数的内置函数，例如 `WasmFastApiCallTypeCheckAndUpdateIC`，用于进行类型检查和更新内联缓存 (Inline Cache)。

7. **DataView 相关错误处理:** 提供了抛出与 JavaScript `DataView` 对象相关的类型错误和越界错误的内置函数 (`ThrowDataViewTypeError`, `ThrowDataViewDetachedError`, `ThrowDataViewOutOfBounds`).

**基于第二部分的代码功能分析：**

第二部分的代码主要集中在 **字符串处理** 和一些 **辅助功能** 上：

* **Wasm 陷阱 (Traps):**  定义了更多用于抛出特定 Wasm 运行时错误的内置函数，例如 `ThrowWasmTrapDivByZero` (除零错误), `ThrowWasmTrapNullDereference` (空指针解引用) 等。这些函数都使用了 `tail WasmTrap(...)`，表明它们最终会调用一个通用的 `WasmTrap` 函数。

* **内存访问宏:** `GetRefAt` 宏提供了一种获取指定内存地址的类型化引用的方式。

* **线程状态管理宏:** `ModifyThreadInWasmFlag` 宏用于修改一个全局标志，表明当前线程是否在执行 Wasm 代码。这在 V8 的内部管理中可能用于调度或其他优化。

* **Wasm 字符串创建:**  提供了从 Wasm 线性内存中创建 V8 字符串的内置函数，如 `WasmStringNewWtf8` (UTF-8 编码) 和 `WasmStringNewWtf16` (UTF-16 编码)。

* **Wasm 字符串数组创建:** 提供了从 Wasm 数组中创建 V8 字符串的内置函数，如 `WasmStringNewWtf8Array` 和 `WasmStringNewWtf16Array`。这些函数会进行边界检查，以防止越界访问。

* **Wasm 字符串从数据段创建:** `WasmStringFromDataSegment` 用于从 Wasm 模块的数据段中创建字符串常量。

* **Wasm 字符串转换:** `WasmStringAsWtf16` 用于确保字符串可以被 `StringPrepareForGetCodeunit` 操作处理 (可能涉及字符串的扁平化)。

* **Wasm 字符串常量:** `WasmStringConst` 用于获取 Wasm 模块中定义的字符串常量。

* **Wasm 字符串测量和编码:** 提供了测量字符串 UTF-8 编码长度 (`WasmStringMeasureUtf8`, `WasmStringMeasureWtf8`) 和将字符串编码到内存中的功能 (`WasmStringEncodeWtf8`, `WasmStringEncodeWtf16` 等)。

* **Wasm 字符串转字节数组:** `WasmStringToUtf8Array` 用于将 V8 字符串转换为 UTF-8 编码的 Wasm 数组。

* **错误处理 (JavaScript 风格):**  定义了一些用于在 Wasm 上下文中抛出 JavaScript 风格的类型错误的内置函数，例如 `ThrowToLowerCaseCalledOnNull` 和 `ThrowIndexOfCalledOnNull`，模拟 JavaScript 内置方法在 `null` 或 `undefined` 上调用的行为。

* **DataView 错误处理:**  提供了用于抛出 `DataView` 相关类型错误和越界错误的内置函数。

* **Wasm 字符串连接和比较:**  提供了连接两个 Wasm 字符串 (`WasmStringConcat`) 和比较两个 Wasm 字符串是否相等 (`WasmStringEqual`) 的内置函数。

* **Wasm 字符串是否为 USV 序列:** `WasmStringIsUSVSequence` 用于判断一个字符串是否只包含 Basic Multilingual Plane (BMP) 中的字符。

* **Wasm 字符串转字节数组 (WTF-8):** `WasmStringAsWtf8` 用于将 V8 字符串转换为 WTF-8 编码的字节数组。

* **Wasm 字符串视图 (String Views):**  提供了一系列用于操作字符串视图的内置函数，允许在不复制整个字符串的情况下进行访问和操作，例如 `WasmStringViewWtf8Advance` (移动视图的偏移量), `WasmStringViewWtf8Encode` (将视图内容编码到内存), `WasmStringViewWtf8Slice` (创建视图的切片), `WasmStringViewWtf16GetCodeUnit` (获取指定偏移量的代码单元), `WasmStringViewWtf16Encode` (编码 WTF-16 字符串视图), `WasmStringViewWtf16Slice` (创建 WTF-16 字符串视图的切片)。

* **Wasm 字符串迭代器:** 提供了用于迭代字符串中代码点的功能 (`WasmStringAsIter`, `WasmStringCodePointAt`, `WasmStringViewIterNext`, `WasmStringViewIterAdvance`, `WasmStringViewIterRewind`, `WasmStringViewIterSlice`)。这允许更方便地处理包含 Unicode 代理对的字符串。

* **类型转换 (数字与字符串):** 提供了将整数转换为字符串 (`WasmIntToString`) 和将字符串转换为浮点数 (`WasmStringToDouble`) 的内置函数。

* **Wasm 字符串从代码点创建:** `WasmStringFromCodePoint` 用于从一个 Unicode 代码点创建一个字符串。

* **Wasm 字符串哈希:** `WasmStringHash` 用于计算 Wasm 字符串的哈希值。

* **Wasm 类型转换 (Any -> Externref):** `WasmAnyConvertExtern` 用于将 JavaScript 的任意值转换为 Wasm 的 `externref` 类型。

* **快速 API 调用优化:** `WasmFastApiCallTypeCheckAndUpdateIC` 用于在从 Wasm 调用 JavaScript 函数时进行类型检查并更新内联缓存，提高调用性能。

**JavaScript 示例:**

与这些内置函数相关的 JavaScript 功能主要体现在 WebAssembly 的字符串操作和错误处理方面。

* **Wasm 陷阱：** 当 Wasm 代码执行过程中发生错误时，会抛出相应的陷阱，这些陷阱最终会被转换为 JavaScript 的 `WebAssembly.RuntimeError` 异常。

```javascript
const wasmCode = `
  (module
    (func (export "divide") (param $a i32) (param $b i32) (result i32)
      (i32.div $a $b)
    )
  )
`;
const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule);

try {
  wasmInstance.exports.divide(10, 0); // 触发除零错误
} catch (e) {
  console.error(e); // 输出 WebAssembly.RuntimeError: integer division by zero
}
```

* **Wasm 字符串操作：**  WebAssembly 的 [Stringref proposal](https://github.com/WebAssembly/stringref) 允许 Wasm 代码直接操作字符串。这些 Torque 内置函数就是为支持这些操作而设计的。虽然 JavaScript 无法直接调用这些内置函数，但当你从 Wasm 模块获取或传递字符串时，V8 内部会使用这些函数进行处理。

```javascript
// 假设有一个 Wasm 模块导出了一个返回字符串的函数
// (这需要 Stringref proposal 的支持)
// 并且这个 Wasm 模块内部使用了 WasmStringNewWtf8 等函数创建字符串

// const wasmModule = ...;
// const wasmInstance = new WebAssembly.Instance(wasmModule);
// const wasmString = wasmInstance.exports.getString();
// console.log(wasmString); // 输出从 Wasm 获取的字符串
```

* **类型转换：** 当 Wasm 代码需要与 JavaScript 交互时，例如调用 JavaScript 函数并将数字或字符串作为参数传递，或者从 JavaScript 函数接收返回值时，会涉及到类型转换。`WasmIntToString` 和 `WasmStringToDouble` 等函数就用于这些场景。

```javascript
const wasmCode = `
  (module
    (import "env" "log" (func $log (param i32)))
    (func (export "callLog") (param $val i32)
      (call $log $val)
    )
  )
`;
const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule, {
  env: {
    log: (val) => {
      console.log("From Wasm:", val); // JavaScript 接收到来自 Wasm 的整数
    },
  },
});

wasmInstance.exports.callLog(123);
```

**代码逻辑推理与假设输入输出:**

以 `WasmStringCodePointAt` 为例：

**假设输入:**
* `string`: 一个 V8 字符串对象，例如 "你好" (UTF-16 编码为 `0x4F60 0x597D`)
* `offset`:  一个表示字符串索引的无符号整数。

**可能的输出:**

* 如果 `offset` 在字符串范围内：返回指定索引处的 Unicode 代码点。
    * 输入: `string` = "你好", `offset` = 0
    * 输出: `22909` (你好 的 '你' 的 Unicode 代码点)
    * 输入: `string` = "你好", `offset` = 1
    * 输出: `23435` (你好 的 '好' 的 Unicode 代码点)
* 如果 `offset` 超出字符串范围：抛出一个 `WebAssembly.RuntimeError`，因为该内置函数内部会调用 `ThrowWasmTrapStringOffsetOutOfBounds()`。

**用户常见的编程错误:**

* **字符串操作越界:**  在 Wasm 中尝试访问字符串的非法索引。这会触发 `ThrowWasmTrapStringOffsetOutOfBounds`。

```javascript
// 假设 Wasm 代码尝试访问字符串超出其长度的索引
// 这会导致 JavaScript 抛出 WebAssembly.RuntimeError

const wasmCode = `
  (module
    (import "env" "getStringLength" (func $getStringLength (param i32) (result i32)))
    (import "env" "getCharAt" (func $getCharAt (param i32) (param i32) (result i32)))
    (func (export "accessString") (param $ptr i32)
      (local $len i32)
      (local $char i32)
      (set_local $len (call $getStringLength $ptr))
      (set_local $char (call $getCharAt $ptr (i32.sub $len (i32.const 1)))) ;; Accessing the last character (valid)
      (drop $char)
      (set_local $char (call $getCharAt $ptr $len)) ;; Accessing out of bounds (error!)
      (drop $char)
    )
  )
`;
// ... 编译和实例化 Wasm 代码 ...
// 假设 ptr 指向一个长度为 5 的字符串
// wasmInstance.exports.accessString(ptr); // 这将导致一个 WebAssembly.RuntimeError
```

* **DataView 操作错误:**  使用 `DataView` 对象时，可能会发生以下错误，对应于 `wasm.tq` 中定义的错误处理函数：
    * **类型错误 (`ThrowDataViewTypeError`):**  尝试在非 `ArrayBuffer` 或 `SharedArrayBuffer` 上创建 `DataView`，或者在已分离的缓冲区上操作。
    * **分离的缓冲区错误 (`ThrowDataViewDetachedError`):**  尝试在已分离的 `ArrayBuffer` 或 `SharedArrayBuffer` 上进行操作。
    * **越界错误 (`ThrowDataViewOutOfBounds`):**  尝试访问 `DataView` 范围之外的内存。

```javascript
const buffer = new ArrayBuffer(10);
const dataView = new DataView(buffer);

try {
  dataView.getInt32(8); // 正确访问
  dataView.getInt32(9); // 错误：超出 DataView 的范围，会抛出 RangeError
} catch (e) {
  console.error(e); // 输出 RangeError: Offset is outside the bounds of the DataView
}

// 分离 ArrayBuffer
buffer.transfer();
try {
  dataView.getInt32(0); // 错误：尝试在已分离的缓冲区上操作，可能在 Wasm 中触发错误
} catch (e) {
  console.error(e); // 可能输出错误，取决于具体的 Wasm 代码行为
}
```

**总结:**

`v8/src/builtins/wasm.tq` 的第二部分以及整体内容都专注于为 V8 引擎的 WebAssembly 支持提供底层的、高性能的内置函数。这些函数涵盖了 Wasm 执行过程中的关键操作，特别是字符串处理、内存访问、类型转换和错误处理。它们是连接 Wasm 代码和 V8 引擎内部机制的桥梁，确保 Wasm 代码能够安全、高效地运行，并与 JavaScript 环境进行互操作。

### 提示词
```
这是目录为v8/src/builtins/wasm.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/wasm.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
dAccess(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapUnalignedAccess));
}

builtin ThrowWasmTrapDivByZero(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDivByZero));
}

builtin ThrowWasmTrapDivUnrepresentable(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDivUnrepresentable));
}

builtin ThrowWasmTrapRemByZero(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapRemByZero));
}

builtin ThrowWasmTrapFloatUnrepresentable(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapFloatUnrepresentable));
}

builtin ThrowWasmTrapFuncSigMismatch(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapFuncSigMismatch));
}

builtin ThrowWasmTrapDataSegmentOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapDataSegmentOutOfBounds));
}

builtin ThrowWasmTrapElementSegmentOutOfBounds(): JSAny {
  tail WasmTrap(
      SmiConstant(MessageTemplate::kWasmTrapElementSegmentOutOfBounds));
}

builtin ThrowWasmTrapTableOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapTableOutOfBounds));
}

builtin ThrowWasmTrapRethrowNull(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapRethrowNull));
}

builtin ThrowWasmTrapNullDereference(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapNullDereference));
}

builtin ThrowWasmTrapIllegalCast(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapIllegalCast));
}

builtin ThrowWasmTrapArrayOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapArrayOutOfBounds));
}

builtin ThrowWasmTrapArrayTooLarge(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapArrayTooLarge));
}

builtin ThrowWasmTrapStringOffsetOutOfBounds(): JSAny {
  tail WasmTrap(SmiConstant(MessageTemplate::kWasmTrapStringOffsetOutOfBounds));
}

macro GetRefAt<T: type, From: type>(base: From, offset: intptr): &T {
  return torque_internal::unsafe::NewOffHeapReference<T>(
      %RawDownCast<RawPtr<T>>(base + offset));
}

extern macro LoadPointerFromRootRegister(intptr): RawPtr;

const kThreadInWasmFlagAddressOffset: constexpr intptr
    generates 'Isolate::thread_in_wasm_flag_address_offset()';

const kActiveSuspenderOffset: constexpr intptr
    generates 'IsolateData::root_slot_offset(RootIndex::kActiveSuspender)';

macro ModifyThreadInWasmFlag(newValue: int32): void {
  const threadInWasmFlagAddress =
      LoadPointerFromRootRegister(kThreadInWasmFlagAddressOffset);
  const threadInWasmFlagRef = GetRefAt<int32>(threadInWasmFlagAddress, 0);
  *threadInWasmFlagRef = newValue;
}

builtin WasmStringNewWtf8(
    offset: uintptr, size: uint32, memory: uint32, utf8Variant: Smi): String
    |WasmNull {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringNewWtf8(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), utf8Variant, UintPtrToNumberRounding(offset),
      WasmUint32ToNumber(size));
}
builtin WasmStringNewWtf8Array(
    start: uint32, end: uint32, array: WasmArray, utf8Variant: Smi): String
    |WasmNull {
  // This can be called from Wasm and from "JS String Builtins".
  const context = LoadContextFromWasmOrJsFrame();
  try {
    if (array.length < end) goto OffsetOutOfRange;
    if (end < start) goto OffsetOutOfRange;
    tail runtime::WasmStringNewWtf8Array(
        context, utf8Variant, array, SmiFromUint32(start), SmiFromUint32(end));
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(context, SmiConstant(error));
  }
}
builtin WasmStringNewWtf16(memory: uint32, offset: uintptr, size: uint32):
    String {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringNewWtf16(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), UintPtrToNumberRounding(offset),
      WasmUint32ToNumber(size));
}

struct TwoByteToOneByteIterator {
  macro Next(): char8 labels NoMore {
    if (this.start == this.end) goto NoMore;
    const raw: char16 = *torque_internal::unsafe::NewReference<char16>(
        this.object, this.start);
    const result: char8 = %RawDownCast<char8>(raw & 0xFF);
    this.start += 2;
    return result;
  }

  object: HeapObject|TaggedZeroPattern;
  start: intptr;
  end: intptr;
}

macro StringFromTwoByteSlice(length: uint32, slice: ConstSlice<char16>):
    String {
  // Ideas for additional future improvements:
  // (1) We could add a fast path for very short strings, e.g. <= 8 chars,
  //     and just allocate two-byte strings for them. That would save time
  //     here, and would only waste a couple of bytes at most. A concern is
  //     that such strings couldn't take one-byte fast paths later on, e.g.
  //     in toLower/toUpper case conversions.
  // (2) We could load more than one array element at a time, e.g. using
  //     intptr-wide loads, or possibly even wider SIMD instructions. We'd
  //     have to make sure that non-aligned start offsets are handled,
  //     and the implementation would become more platform-specific.
  // (3) We could shift the problem around by allocating two-byte strings
  //     here and checking whether they're one-byte-compatible later, e.g.
  //     when promoting them from new to old space. Drawback: rewriting
  //     strings to different maps isn't great for optimized code that's
  //     based on collected type feedback, or that wants to elide duplicate
  //     map checks within the function.
  // (4) We could allocate space for a two-byte string, then optimistically
  //     start writing one-byte characters into it, and then either restart
  //     in two-byte mode if needed, or return the over-allocated bytes to
  //     the allocator in the end.
  // (5) We could standardize a `string.new_ascii_array` instruction, which
  //     could safely produce one-byte strings without checking characters.
  //     See https://github.com/WebAssembly/stringref/issues/53.

  try {
    // To reduce the amount of branching, check 8 code units at a time. The
    // tradeoff for choosing 8 is that we want to check for early termination
    // of the loop often (to avoid unnecessary work) but not too often
    // (because each check has a cost).
    let i: intptr = 0;
    const intptrLength = slice.length;
    const eightElementLoopEnd = intptrLength - 8;
    while (i <= eightElementLoopEnd) {
      const bits = Convert<uint32>(*slice.UncheckedAtIndex(i)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 1)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 2)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 3)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 4)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 5)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 6)) |
          Convert<uint32>(*slice.UncheckedAtIndex(i + 7));
      if (bits > 0xFF) goto TwoByte;
      i += 8;
    }
    let bits: uint32 = 0;
    while (i < intptrLength) {
      bits |= Convert<uint32>(*slice.UncheckedAtIndex(i));
      i += 1;
    }
    if (bits > 0xFF) goto TwoByte;
  } label TwoByte {
    return AllocateSeqTwoByteString(length, slice.Iterator());
  }

  const end = slice.offset + torque_internal::TimesSizeOf<char16>(slice.length);
  return AllocateNonEmptySeqOneByteString(length, TwoByteToOneByteIterator{
    object: slice.object,
    start: slice.offset,
    end: end
  });
}

builtin WasmStringNewWtf16Array(array: WasmArray, start: uint32, end: uint32):
    String {
  try {
    if (array.length < end) goto OffsetOutOfRange;
    if (end < start) goto OffsetOutOfRange;
    const length: uint32 = end - start;
    if (length == 0) return kEmptyString;
    if (length == 1) {
      const offset = kWasmArrayHeaderSize +
          torque_internal::TimesSizeOf<char16>(Convert<intptr>(start));
      const code: char16 = *torque_internal::unsafe::NewReference<char16>(
          array, offset);
      // This makes sure we check the SingleCharacterStringTable.
      return StringFromSingleCharCode(code);
    }
    // Calling into the runtime has overhead, but once we're there it's faster,
    // so it pays off for long strings. The threshold has been determined
    // experimentally.
    if (length >= 32) goto Runtime;
    const intptrLength = Convert<intptr>(length);
    const arrayContent = torque_internal::unsafe::NewConstSlice<char16>(
        array, kWasmArrayHeaderSize, Convert<intptr>(array.length));
    const substring =
        Subslice(arrayContent, Convert<intptr>(start), intptrLength)
        otherwise goto OffsetOutOfRange;

    return StringFromTwoByteSlice(length, substring);
  } label OffsetOutOfRange deferred {
    // This can be called from Wasm and from "JS String Builtins".
    const context = LoadContextFromWasmOrJsFrame();
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(context, SmiConstant(error));
  } label Runtime deferred {
    const context = LoadContextFromWasmOrJsFrame();
    tail runtime::WasmStringNewWtf16Array(
        context, array, SmiFromUint32(start), SmiFromUint32(end));
  }
}

// For imports based string constants.
// Always returns a String or WasmNull if it didn't trap; typed "JSAny" to
// satisfy Torque's type checker for tail calls.
builtin WasmStringFromDataSegment(
    segmentLength: uint32, arrayStart: uint32, arrayEnd: uint32,
    segmentIndex: Smi, segmentOffset: Smi, variant: Smi): JSAny|WasmNull {
  const trustedData = LoadInstanceDataFromFrame();
  try {
    const segmentOffsetU: uint32 = Unsigned(SmiToInt32(segmentOffset));
    if (segmentLength > Convert<uint32>(kSmiMax) - segmentOffsetU) {
      goto SegmentOOB;
    }
    if (arrayStart > segmentLength) goto ArrayOutOfBounds;
    if (arrayEnd < arrayStart) goto ArrayOutOfBounds;
    const arrayLength = arrayEnd - arrayStart;
    if (arrayLength > segmentLength - arrayStart) goto ArrayOutOfBounds;
    const smiOffset = Convert<PositiveSmi>(segmentOffsetU + arrayStart)
        otherwise SegmentOOB;
    const smiLength = Convert<PositiveSmi>(arrayLength) otherwise SegmentOOB;
    tail runtime::WasmStringNewSegmentWtf8(
        LoadContextFromInstanceData(trustedData), trustedData, segmentIndex,
        smiOffset, smiLength, variant);
  } label SegmentOOB deferred {
    tail ThrowWasmTrapElementSegmentOutOfBounds();
  } label ArrayOutOfBounds deferred {
    tail ThrowWasmTrapArrayOutOfBounds();
  }
}

// Contract: input is any string, output is a string that the TF operator
// "StringPrepareForGetCodeunit" can handle.
builtin WasmStringAsWtf16(str: String): String {
  const cons = Cast<ConsString>(str) otherwise return str;
  return Flatten(cons);
}

builtin WasmStringConst(index: uint32): String {
  const trustedData = LoadInstanceDataFromFrame();
  tail runtime::WasmStringConst(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(index));
}
builtin WasmStringMeasureUtf8(string: String): int32 {
  const result = runtime::WasmStringMeasureUtf8(LoadContextFromFrame(), string);
  return NumberToInt32(result);
}
builtin WasmStringMeasureWtf8(string: String): int32 {
  const result = runtime::WasmStringMeasureWtf8(LoadContextFromFrame(), string);
  return NumberToInt32(result);
}
builtin WasmStringEncodeWtf8(
    offset: uintptr, memory: uint32, utf8Variant: uint32,
    string: String): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const result = runtime::WasmStringEncodeWtf8(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), SmiFromUint32(utf8Variant), string,
      UintPtrToNumberRounding(offset));
  return NumberToUint32(result);
}
builtin WasmStringEncodeWtf8Array(
    string: String, array: WasmArray, start: uint32, utf8Variant: Smi): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const result = runtime::WasmStringEncodeWtf8Array(
      LoadContextFromInstanceData(trustedData), utf8Variant, string, array,
      WasmUint32ToNumber(start));
  return NumberToUint32(result);
}
builtin WasmStringToUtf8Array(string: String): WasmArray {
  return runtime::WasmStringToUtf8Array(LoadContextFromFrame(), string);
}
builtin WasmStringEncodeWtf16(string: String, offset: uintptr, memory: uint32):
    uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  runtime::WasmStringEncodeWtf16(
      LoadContextFromInstanceData(trustedData), trustedData,
      SmiFromUint32(memory), string, UintPtrToNumberRounding(offset),
      SmiConstant(0), SmiFromInt32(string.length));
  return Unsigned(string.length);
}
builtin WasmStringEncodeWtf16Array(
    string: String, array: WasmArray, start: uint32): uint32 {
  try {
    if (start > array.length) goto OffsetOutOfRange;
    if (array.length - start < Unsigned(string.length)) goto OffsetOutOfRange;

    const byteOffset: intptr = kWasmArrayHeaderSize +
        torque_internal::TimesSizeOf<char16>(Convert<intptr>(start));
    const arrayContent = torque_internal::unsafe::NewMutableSlice<char16>(
        array, byteOffset, string.length_intptr);
    try {
      StringToSlice(string) otherwise OneByte, TwoByte;
    } label OneByte(slice: ConstSlice<char8>) {
      let fromIt = slice.Iterator();
      let toIt = arrayContent.Iterator();
      while (true) {
        let toRef = toIt.NextReference() otherwise break;
        *toRef = %RawDownCast<char16>(Convert<uint16>(fromIt.NextNotEmpty()));
      }
    } label TwoByte(slice: ConstSlice<char16>) {
      let fromIt = slice.Iterator();
      let toIt = arrayContent.Iterator();
      while (true) {
        let toRef = toIt.NextReference() otherwise break;
        *toRef = fromIt.NextNotEmpty();
      }
    }
    return Unsigned(string.length);
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapArrayOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromWasmOrJsFrame(), SmiConstant(error));
  }
}

builtin ThrowToLowerCaseCalledOnNull(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kCalledOnNullOrUndefined;
  const name = StringConstant('String.prototype.toLowerCase');
  runtime::WasmThrowTypeError(context, SmiConstant(error), name);
}

builtin ThrowIndexOfCalledOnNull(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kCalledOnNullOrUndefined;
  const name = StringConstant('String.prototype.indexOf');
  runtime::WasmThrowTypeError(context, SmiConstant(error), name);
}

builtin ThrowDataViewTypeError(value: JSAny): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kIncompatibleMethodReceiver;
  runtime::WasmThrowDataViewTypeError(context, SmiConstant(error), value);
}

builtin ThrowDataViewDetachedError(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kDetachedOperation;
  runtime::WasmThrowDataViewDetachedError(context, SmiConstant(error));
}

builtin ThrowDataViewOutOfBounds(): JSAny {
  const context = LoadContextFromFrame();
  const error = MessageTemplate::kInvalidDataViewAccessorOffset;
  runtime::WasmThrowRangeError(context, SmiConstant(error));
}

builtin WasmStringConcat(a: String, b: String): String {
  const context = LoadContextFromFrame();
  tail StringAdd_CheckNone(a, b);
}

extern builtin StringEqual(NoContext, String, String, intptr): Boolean;

builtin WasmStringEqual(a: String, b: String): int32 {
  if (TaggedEqual(a, b)) return 1;
  if (a.length != b.length) return 0;
  if (StringEqual(kNoContext, a, b, a.length_intptr) == True) {
    return 1;
  }
  return 0;
}

builtin WasmStringIsUSVSequence(str: String): int32 {
  if (IsOneByteStringMap(str.map)) return 1;
  const length = runtime::WasmStringMeasureUtf8(LoadContextFromFrame(), str);
  if (NumberToInt32(length) < 0) return 0;
  return 1;
}

builtin WasmStringAsWtf8(str: String): ByteArray {
  tail runtime::WasmStringAsWtf8(LoadContextFromFrame(), str);
}

macro IsWtf8CodepointStart(view: ByteArray, pos: uint32): bool {
  // We're already at the start of a codepoint if the current byte
  // doesn't start with 0b10xxxxxx.
  return (view.values[Convert<uintptr>(pos)] & 0xc0) != 0x80;
}
macro AlignWtf8PositionForward(view: ByteArray, pos: uint32): uint32 {
  const length = Unsigned(SmiToInt32(view.length));
  if (pos >= length) return length;

  if (IsWtf8CodepointStart(view, pos)) return pos;

  // Otherwise `pos` is part of a multibyte codepoint, and is not the
  // leading byte.  The next codepoint will start at pos + 1, pos + 2,
  // or pos + 3.
  if (pos + 1 == length) return length;
  if (IsWtf8CodepointStart(view, pos + 1)) return pos + 1;

  if (pos + 2 == length) return length;
  if (IsWtf8CodepointStart(view, pos + 2)) return pos + 2;

  return pos + 3;
}
macro AlignWtf8PositionBackward(view: ByteArray, pos: uint32): uint32 {
  // Return the highest offset that starts a codepoint which is not
  // greater than pos.  Preconditions: pos in [0, view.length), view
  // contains well-formed WTF-8.
  if (IsWtf8CodepointStart(view, pos)) return pos;
  if (IsWtf8CodepointStart(view, pos - 1)) return pos - 1;
  if (IsWtf8CodepointStart(view, pos - 2)) return pos - 2;
  return pos - 3;
}
builtin WasmStringViewWtf8Advance(view: ByteArray, pos: uint32, bytes: uint32):
    uint32 {
  const clampedPos = AlignWtf8PositionForward(view, pos);
  if (bytes == 0) return clampedPos;
  const length = Unsigned(SmiToInt32(view.length));
  if (bytes >= length - clampedPos) return length;
  return AlignWtf8PositionBackward(view, clampedPos + bytes);
}
struct NewPositionAndBytesWritten {
  newPosition: uint32;
  bytesWritten: uint32;
}
builtin WasmStringViewWtf8Encode(
    addr: uintptr, pos: uint32, bytes: uint32, view: ByteArray, memory: Smi,
    utf8Variant: Smi): NewPositionAndBytesWritten {
  const start = WasmStringViewWtf8Advance(view, pos, 0);
  const end = WasmStringViewWtf8Advance(view, start, bytes);
  const trustedData = LoadInstanceDataFromFrame();
  const context = LoadContextFromInstanceData(trustedData);

  // Always call out to run-time, to catch invalid addr.
  runtime::WasmStringViewWtf8Encode(
      context, trustedData, utf8Variant, view, UintPtrToNumberRounding(addr),
      WasmUint32ToNumber(start), WasmUint32ToNumber(end), memory);

  return NewPositionAndBytesWritten{
    newPosition: end,
    bytesWritten: end - start
  };
}
builtin WasmStringViewWtf8Slice(view: ByteArray, start: uint32, end: uint32):
    String {
  const start = WasmStringViewWtf8Advance(view, start, 0);
  const end = WasmStringViewWtf8Advance(view, end, 0);

  if (end <= start) return kEmptyString;

  tail runtime::WasmStringViewWtf8Slice(
      LoadContextFromFrame(), view, WasmUint32ToNumber(start),
      WasmUint32ToNumber(end));
}
transitioning builtin WasmStringViewWtf16GetCodeUnit(
    string: String, offset: uint32): uint32 {
  try {
    if (Unsigned(string.length) <= offset) goto OffsetOutOfRange;
    const code: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
    return Convert<uint32>(code);
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapStringOffsetOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromFrame(), SmiConstant(error));
  }
}
builtin WasmStringViewWtf16Encode(
    offset: uintptr, start: uint32, length: uint32, string: String,
    memory: Smi): uint32 {
  const trustedData = LoadInstanceDataFromFrame();
  const clampedStart =
      start < Unsigned(string.length) ? start : Unsigned(string.length);
  const maxLength = Unsigned(string.length) - clampedStart;
  const clampedLength = length < maxLength ? length : maxLength;
  runtime::WasmStringEncodeWtf16(
      LoadContextFromInstanceData(trustedData), trustedData, memory, string,
      UintPtrToNumberRounding(offset), SmiFromUint32(clampedStart),
      SmiFromUint32(clampedLength));
  return clampedLength;
}
transitioning builtin WasmStringViewWtf16Slice(
    string: String, start: uint32, end: uint32): String {
  const length = Unsigned(string.length);
  if (start >= length) return kEmptyString;
  if (end <= start) return kEmptyString;

  // On a high level, the intended logic is:
  // (1) If start == 0 && end == string.length, return string.
  // (2) If clampedLength == 1, use a cached single-character string.
  // (3) If clampedLength < SlicedString::kMinLength, make a copy.
  // (4) If clampedLength < string.length / 2, make a copy.
  // (5) Else, create a slice.
  // The reason for having case (4) is that case (5) has the risk of keeping
  // huge parent strings alive unnecessarily, and Wasm currently doesn't have a
  // way to control that behavior, so we have to be careful.
  // The reason for having case (5) is that case (4) would lead to quadratic
  // overall behavior if code repeatedly chops off a few characters of a long
  // string, which we want to avoid.
  // The string::SubString implementation can handle cases (1), (2), (3),
  // and (5). The inline code here handles case (4), and doesn't mind if it
  // also catches some of case (3).
  const clampedEnd = end <= length ? end : length;
  const clampedLength = clampedEnd - start;
  if (clampedLength > 1 && clampedLength < length / 2) {
    try {
      // Calling into the runtime has overhead, but once we're there it's
      // faster, so it pays off for long strings.
      if (clampedLength > 32) goto Runtime;
      StringToSlice(string) otherwise OneByte, TwoByte;
    } label OneByte(slice: ConstSlice<char8>) {
      let subslice = Subslice(
          slice, Convert<intptr>(start), Convert<intptr>(clampedLength))
          otherwise unreachable;
      return AllocateNonEmptySeqOneByteString(
          clampedLength, subslice.Iterator());
    } label TwoByte(slice: ConstSlice<char16>) {
      let subslice = Subslice(
          slice, Convert<intptr>(start), Convert<intptr>(clampedLength))
          otherwise unreachable;
      return StringFromTwoByteSlice(clampedLength, subslice);
    } label Runtime deferred {
      const context = LoadContextFromWasmOrJsFrame();
      tail runtime::WasmSubstring(
          context, string, SmiFromUint32(start), SmiFromUint32(clampedLength));
    }
  }
  return string::SubString(
      string, Convert<uintptr>(start), Convert<uintptr>(clampedEnd));
}
builtin WasmStringAsIter(string: String): WasmStringViewIter {
  return new WasmStringViewIter{string: string, offset: 0, optional_padding: 0};
}
macro IsLeadSurrogate(code: char16): bool {
  return (code & 0xfc00) == 0xd800;
}
macro IsTrailSurrogate(code: char16): bool {
  return (code & 0xfc00) == 0xdc00;
}
macro CombineSurrogatePair(lead: char16, trail: char16): int32 {
  const lead32 = Convert<uint32>(lead);
  const trail32 = Convert<uint32>(trail);
  // Surrogate pairs encode codepoints in the range
  // [0x010000, 0x10FFFF].  Each surrogate has 10 bits of information in
  // the low bits.  We can combine them together with a shift-and-add,
  // then add a bias of 0x010000 - 0xD800<<10 - 0xDC00 = 0xFCA02400.
  const surrogateBias: uint32 = 0xFCA02400;
  return Signed((lead32 << 10) + trail32 + surrogateBias);
}

builtin WasmStringCodePointAt(string: String, offset: uint32): uint32 {
  try {
    if (Unsigned(string.length) <= offset) goto OffsetOutOfRange;
    const lead: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
    if (!IsLeadSurrogate(lead)) return Convert<uint32>(lead);
    const trailOffset = offset + 1;
    if (Unsigned(string.length) <= trailOffset) return Convert<uint32>(lead);
    const trail: char16 =
        StringCharCodeAt(string, Convert<uintptr>(trailOffset));
    if (!IsTrailSurrogate(trail)) return Convert<uint32>(lead);
    return Unsigned(CombineSurrogatePair(lead, trail));
  } label OffsetOutOfRange deferred {
    const error = MessageTemplate::kWasmTrapStringOffsetOutOfBounds;
    runtime::ThrowWasmError(LoadContextFromFrame(), SmiConstant(error));
  }
}

builtin WasmStringViewIterNext(view: WasmStringViewIter): int32 {
  const string = view.string;
  const offset = view.offset;
  if (offset >= Unsigned(string.length)) return -1;
  const code: char16 = StringCharCodeAt(string, Convert<uintptr>(offset));
  try {
    if (IsLeadSurrogate(code) && offset + 1 < Unsigned(string.length)) {
      goto CheckForSurrogatePair;
    }
  } label CheckForSurrogatePair deferred {
    const code2: char16 =
        StringCharCodeAt(string, Convert<uintptr>(offset + 1));
    if (IsTrailSurrogate(code2)) {
      view.offset = offset + 2;
      return CombineSurrogatePair(code, code2);
    }
  }
  view.offset = offset + 1;
  return Signed(Convert<uint32>(code));
}
builtin WasmStringViewIterAdvance(
    view: WasmStringViewIter, codepoints: uint32): uint32 {
  const string = view.string;
  let offset = view.offset;
  let advanced: uint32 = 0;
  while (advanced < codepoints) {
    if (offset == Unsigned(string.length)) break;
    advanced = advanced + 1;
    if (offset + 1 < Unsigned(string.length) &&
        IsLeadSurrogate(StringCharCodeAt(string, Convert<uintptr>(offset))) &&
        IsTrailSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset + 1)))) {
      offset = offset + 2;
    } else {
      offset = offset + 1;
    }
  }
  view.offset = offset;
  return advanced;
}
builtin WasmStringViewIterRewind(view: WasmStringViewIter, codepoints: uint32):
    uint32 {
  const string = view.string;
  let offset = view.offset;
  let rewound: uint32 = 0;
  if (string.length == 0) return 0;
  while (rewound < codepoints) {
    if (offset == 0) break;
    rewound = rewound + 1;
    if (offset >= 2 &&
        IsTrailSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset - 1))) &&
        IsLeadSurrogate(
            StringCharCodeAt(string, Convert<uintptr>(offset - 2)))) {
      offset = offset - 2;
    } else {
      offset = offset - 1;
    }
  }
  view.offset = offset;
  return rewound;
}
builtin WasmStringViewIterSlice(view: WasmStringViewIter, codepoints: uint32):
    String {
  const string = view.string;
  const start = view.offset;
  let end = view.offset;
  let advanced: uint32 = 0;
  while (advanced < codepoints) {
    if (end == Unsigned(string.length)) break;
    advanced = advanced + 1;
    if (end + 1 < Unsigned(string.length) &&
        IsLeadSurrogate(StringCharCodeAt(string, Convert<uintptr>(end))) &&
        IsTrailSurrogate(StringCharCodeAt(string, Convert<uintptr>(end + 1)))) {
      end = end + 2;
    } else {
      end = end + 1;
    }
  }
  return (start == end) ?
      kEmptyString :
      string::SubString(string, Convert<uintptr>(start), Convert<uintptr>(end));
}

builtin WasmIntToString(x: int32, radix: int32): String {
  if (radix == 10) {
    const smi = SmiFromInt32(x);
    const untagged = SmiToInt32(smi);
    if (x == untagged) {
      // Queries and populates the NumberToStringCache, but needs tagged
      // inputs, so only call this for Smis.
      return NumberToString(smi);
    }
    return number::IntToDecimalString(x);
  }

  // Pretend that Number.prototype.toString was called.
  if (radix < 2 || radix > 36) {
    runtime::ThrowRangeError(
        LoadContextFromInstanceData(LoadInstanceDataFromFrame()),
        SmiConstant(MessageTemplate::kToRadixFormatRange));
  }
  return number::IntToString(x, Unsigned(radix));
}

builtin WasmStringToDouble(s: String): float64 {
  const hash: NameHash = s.raw_hash_field;
  if (IsIntegerIndex(hash) &&
      hash.array_index_length < kMaxCachedArrayIndexLength) {
    const arrayIndex: int32 = Signed(hash.array_index_value);
    return Convert<float64>(arrayIndex);
  }
  return StringToFloat64(Flatten(s));
}

builtin WasmStringFromCodePoint(codePoint: uint32): String {
  tail runtime::WasmStringFromCodePoint(
      LoadContextFromFrame(), WasmUint32ToNumber(codePoint));
}

builtin WasmStringHash(string: String): int32 {
  const result = runtime::WasmStringHash(kNoContext, string);
  return SmiToInt32(result);
}

builtin WasmAnyConvertExtern(externObject: JSAny): JSAny {
  const trustedData = LoadInstanceDataFromFrame();
  const context = LoadContextFromInstanceData(trustedData);

  tail runtime::WasmJSToWasmObject(
      context, externObject, SmiConstant(kAnyType));
}

extern macro CallOrConstructBuiltinsAssembler::GetCompatibleReceiver(
    JSReceiver, HeapObject, Context): JSReceiver;

builtin WasmFastApiCallTypeCheckAndUpdateIC(
    implicit context: Context)(data: WasmFastApiCallData,
    receiver: JSAny): Smi {
  try {
    const rec = Cast<JSReceiver>(receiver) otherwise goto IllegalCast;
    ModifyThreadInWasmFlag(0);
    // We don't care about the actual compatible receiver; we just rely
    // on this helper throwing an exception when there isn't one.
    GetCompatibleReceiver(rec, data.signature, context);
    ModifyThreadInWasmFlag(1);
    data.cached_map = StrongToWeak(rec.map);
    return 1;
  } label IllegalCast {
    const error = MessageTemplate::kIllegalInvocation;
    runtime::WasmThrowTypeError(context, SmiConstant(error), Convert<Smi>(0));
  }
}
}  // namespace wasm
```