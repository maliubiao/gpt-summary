Response: Let's break down the thought process for analyzing this Torque code.

**1. Initial Understanding of the Context:**

The first line `// This file defines the builtins that are used as the non-optimized versions of the "JS String Builtins", i.e. from Liftoff code, and for exported functions.` is crucial. It immediately tells us:

* **Target Audience:** This code is for WebAssembly (Wasm).
* **Purpose:** It provides implementations of string operations for Wasm that are *not* the highly optimized versions. Think of them as fallback or initial implementations.
* **Triggering Contexts:** Liftoff (a Wasm tier in V8) and exported Wasm functions will use these.

**2. Identifying Key Building Blocks:**

Scanning the code, I notice repeating patterns and keywords:

* **`transitioning javascript builtin WebAssembly...`:** This is the defining structure for each function. It indicates these are built-in functions exposed to JavaScript (and therefore, indirectly, Wasm).
* **`Trap(context, MessageTemplate::kWasmTrap...)`:** This suggests error handling specific to Wasm, indicating a potential runtime error.
* **`Cast<String>(...) otherwise goto IllegalCast;`:**  Type checking is happening. The code expects string inputs, and if it doesn't get them, it jumps to the `IllegalCast` label, which then calls `Trap`.
* **`WasmCastToSpecialPrimitiveArray(...)`:**  This function name suggests interaction with typed arrays, specifically for representing string data. The `SmiConstant(8)` and `SmiConstant(16)` hint at UTF-8 and UTF-16 encodings.
* **`wasm::WasmStringNew...`, `wasm::WasmStringEncode...`, `wasm::WasmStringMeasure...`, `wasm::WasmStringView...`, `wasm::StringEqual`:**  These clearly point to internal V8 functions within the `wasm` namespace that handle the underlying Wasm string implementation.
* **`NumberToUint32(ToNumber_Inline(...))`:** Input arguments (like start and end indices) are being converted to numbers and then to unsigned 32-bit integers.
* **`StringFromSingleCharCode(...)`:**  This is a standard JavaScript string operation.
* **`StringAdd_CheckNone(...)`, `StringCompare(...)`:** More standard JavaScript string operations.

**3. Grouping Functionalities:**

Based on the function names and the operations they perform, I can categorize them:

* **Type Conversion/Checking:** `WebAssemblyStringCast`, `WebAssemblyStringTest`
* **String Creation from Arrays:** `WebAssemblyStringFromWtf16Array`, `WebAssemblyStringFromUtf8Array`
* **String Encoding to Arrays:** `WebAssemblyStringIntoUtf8Array`, `WebAssemblyStringToUtf8Array`, `WebAssemblyStringToWtf16Array`
* **Character/Code Point Access:** `WebAssemblyStringFromCharCode`, `WebAssemblyStringFromCodePoint`, `WebAssemblyStringCodePointAt`, `WebAssemblyStringCharCodeAt`
* **String Properties:** `WebAssemblyStringLength`, `WebAssemblyStringMeasureUtf8`
* **String Manipulation:** `WebAssemblyStringConcat`, `WebAssemblyStringSubstring`
* **String Comparison:** `WebAssemblyStringEquals`, `WebAssemblyStringCompare`

**4. Connecting to JavaScript:**

For each category, I think about the corresponding JavaScript features:

* **Type Conversion/Checking:**  `typeof`, explicit type conversions (though Wasm has stricter typing).
* **String Creation from Arrays:** `String.fromCharCode.apply(null, array)`, `TextDecoder`.
* **String Encoding to Arrays:** `TextEncoder`.
* **Character/Code Point Access:** `String.fromCharCode`, `String.fromCodePoint`, `charCodeAt`, `codePointAt`.
* **String Properties:** `length`.
* **String Manipulation:** `+` operator, `concat`, `slice`, `substring`.
* **String Comparison:** `===`, `==`, `<`, `>`, `localeCompare`.

**5. Constructing Examples and Scenarios:**

For each function, I try to create a simple JavaScript example demonstrating its equivalent or related functionality. I also consider:

* **Input Types:** What kind of data does the Wasm function expect? (Arrays, numbers, strings).
* **Output Types:** What does it return? (Strings, numbers).
* **Error Cases:** What could go wrong? (Incorrect types, out-of-bounds indices). This directly relates to the `Trap` calls.

**6. Inferring Logic and Assumptions:**

* **Array Handling:**  The code assumes the input arrays are of the correct type (Uint8Array or Uint16Array) due to the `WasmCastToSpecialPrimitiveArray` calls with `SmiConstant(8)` and `SmiConstant(16)`.
* **Index Handling:**  Indices are converted to `Uint32`, implying they should be non-negative integers. The code checks for out-of-bounds access in some cases.
* **Encoding:**  The use of "WTF-8" suggests a specific encoding used internally by V8 for Wasm strings, and the code handles conversions between UTF-8 and UTF-16.

**7. Addressing Common Errors:**

I think about what mistakes a programmer might make when interacting with these kinds of string operations:

* **Incorrect Types:** Passing a number when a string is expected, or vice-versa.
* **Out-of-Bounds Access:**  Providing invalid start or end indices for substrings or character access.
* **Encoding Mismatches:**  Trying to interpret a UTF-8 encoded array as UTF-16, or vice-versa, outside of the provided conversion functions.

**8. Iterative Refinement:**

After the initial pass, I reread the code and my analysis, looking for inconsistencies or areas where I can be more precise. For example, initially, I might just say "converts to UTF-8 array."  Then I'd refine it to mention "lossy UTF-8" based on the `kLossyUtf8` constant. I also make sure the JavaScript examples accurately reflect the Wasm function's purpose.

By following this process, I can systematically analyze the Torque code and generate a comprehensive explanation of its functionality, its relation to JavaScript, and potential error scenarios.
这个V8 Torque源代码文件 `v8/src/builtins/wasm-strings.tq` 定义了一系列用于 WebAssembly (Wasm) 中字符串操作的内置函数。这些内置函数是未经过优化的版本，主要用于 Liftoff 代码（V8 的一个快速但非优化的 Wasm 执行器）和导出的 Wasm 函数。

**功能归纳:**

该文件定义了一组 JavaScript 内置函数，这些函数在 WebAssembly 的上下文中用于处理字符串。这些函数涵盖了字符串的创建、类型转换、检查、编码、解码、长度获取、字符访问、连接、截取、比较等基本操作。

更具体地说，这些函数提供了以下功能：

* **类型转换和检查:**
    * `WebAssemblyStringCast`: 将一个 JavaScript 值强制转换为字符串类型，如果转换失败则触发 Wasm 陷阱 (trap)。
    * `WebAssemblyStringTest`: 检查一个 JavaScript 值是否为字符串，返回 1 (true) 或 0 (false)。
* **从数组创建字符串:**
    * `WebAssemblyStringFromWtf16Array`: 从一个 WTF-16 编码的 WebAssembly 数组创建字符串。
    * `WebAssemblyStringFromUtf8Array`: 从一个 UTF-8 编码的 WebAssembly 数组创建字符串。
* **将字符串编码到数组:**
    * `WebAssemblyStringIntoUtf8Array`: 将一个 JavaScript 字符串编码到预先分配的 UTF-8 编码的 WebAssembly 数组中。
    * `WebAssemblyStringToUtf8Array`: 将一个 JavaScript 字符串编码为一个新的 UTF-8 编码的 WebAssembly 数组。
    * `WebAssemblyStringToWtf16Array`: 将一个 JavaScript 字符串编码到预先分配的 WTF-16 编码的 WebAssembly 数组中。
* **字符操作:**
    * `WebAssemblyStringFromCharCode`: 从一个 Unicode 码点创建一个单字符字符串（限制在 0xFFFF 范围内）。
    * `WebAssemblyStringFromCodePoint`: 从一个 Unicode 码点创建一个字符串（可以处理超出 0xFFFF 的码点）。
    * `WebAssemblyStringCodePointAt`: 返回字符串中指定索引处的 Unicode 码点。
    * `WebAssemblyStringCharCodeAt`: 返回字符串中指定索引处的 UTF-16 代码单元。
* **字符串属性:**
    * `WebAssemblyStringLength`: 返回字符串的长度。
    * `WebAssemblyStringMeasureUtf8`: 测量字符串的 UTF-8 编码长度。
* **字符串操作:**
    * `WebAssemblyStringConcat`: 连接两个字符串。
    * `WebAssemblyStringSubstring`: 返回字符串的子串。
* **字符串比较:**
    * `WebAssemblyStringEquals`: 比较两个字符串是否相等。
    * `WebAssemblyStringCompare`: 比较两个字符串的大小。

**与 JavaScript 功能的关系 (带示例):**

这些 WebAssembly 内置函数在功能上与 JavaScript 的 `String` 对象提供的许多方法相似。以下是一些对应关系和示例：

* **`WebAssemblyStringCast(arg)` 类似于 JavaScript 的显式类型转换 `String(arg)` 或在某些上下文中的隐式转换。**
   ```javascript
   // JavaScript
   const num = 123;
   const str1 = String(num); // 显式转换
   const str2 = "" + num;    // 隐式转换
   console.log(typeof str1); // "string"
   console.log(typeof str2); // "string"

   // 假设在 Wasm 中调用了 WebAssemblyStringCast(123)
   // 它会尝试将 123 转换为字符串。
   ```

* **`WebAssemblyStringTest(arg)` 类似于 JavaScript 的 `typeof arg === 'string'`。**
   ```javascript
   // JavaScript
   const str = "hello";
   const num = 123;
   console.log(typeof str === 'string'); // true
   console.log(typeof num === 'string'); // false

   // 假设在 Wasm 中调用了 WebAssemblyStringTest("hello")，返回 1
   // 假设在 Wasm 中调用了 WebAssemblyStringTest(123)，返回 0
   ```

* **`WebAssemblyStringFromWtf16Array(array, start, end)` 和 `WebAssemblyStringFromUtf8Array(array, start, end)` 类似于使用 `TextDecoder` (对于 UTF-8) 或直接操作 `String.fromCharCode` (对于 UTF-16 代码单元)。**
   ```javascript
   // JavaScript (UTF-8)
   const utf8Array = new Uint8Array([104, 101, 108, 108, 111]);
   const decoder = new TextDecoder();
   const strFromUtf8 = decoder.decode(utf8Array);
   console.log(strFromUtf8); // "hello"

   // JavaScript (UTF-16 假设数组包含 UTF-16 代码单元)
   const utf16Array = [104, 101, 108, 108, 111];
   const strFromUtf16 = String.fromCharCode(...utf16Array);
   console.log(strFromUtf16); // "hello"

   // 在 Wasm 中，你可以提供一个 Wasm 的 ArrayBufferView 和起始/结束索引。
   ```

* **`WebAssemblyStringIntoUtf8Array(string, array, start)` 和 `WebAssemblyStringToUtf8Array(string)` 类似于使用 `TextEncoder`。**
   ```javascript
   // JavaScript
   const str = "你好";
   const encoder = new TextEncoder();
   const encodedArray = encoder.encode(str);
   console.log(encodedArray); // Uint8Array [ 228, 189, 160, 229, 165, 189 ]

   // WebAssemblyStringToUtf8Array 会返回一个新的 Uint8Array
   // WebAssemblyStringIntoUtf8Array 会将编码写入已有的 Uint8Array
   ```

* **`WebAssemblyStringFromCharCode(code)` 对应于 `String.fromCharCode(code)`。**
   ```javascript
   // JavaScript
   const char = String.fromCharCode(65);
   console.log(char); // "A"

   // 假设在 Wasm 中调用 WebAssemblyStringFromCharCode(65) 将返回 "A"
   ```

* **`WebAssemblyStringFromCodePoint(code)` 对应于 `String.fromCodePoint(code)`。**
   ```javascript
   // JavaScript
   const emoji = String.fromCodePoint(0x1F600);
   console.log(emoji); // "😀"

   // 假设在 Wasm 中调用 WebAssemblyStringFromCodePoint(0x1F600) 将返回 "😀"
   ```

* **`WebAssemblyStringCodePointAt(string, index)` 对应于 `string.codePointAt(index)`。**
   ```javascript
   // JavaScript
   const str = "😀abc";
   console.log(str.codePointAt(0)); // 128512 (0x1F600)
   console.log(str.codePointAt(1)); // 97 (a)

   // 假设在 Wasm 中调用 WebAssemblyStringCodePointAt("😀abc", 0) 将返回 128512
   ```

* **`WebAssemblyStringCharCodeAt(string, index)` 对应于 `string.charCodeAt(index)`。**
   ```javascript
   // JavaScript
   const str = "abc";
   console.log(str.charCodeAt(0)); // 97 (a)

   // 假设在 Wasm 中调用 WebAssemblyStringCharCodeAt("abc", 0) 将返回 97
   ```

* **`WebAssemblyStringLength(string)` 对应于 `string.length`。**
   ```javascript
   // JavaScript
   const str = "hello";
   console.log(str.length); // 5

   // 假设在 Wasm 中调用 WebAssemblyStringLength("hello") 将返回 5
   ```

* **`WebAssemblyStringConcat(first, second)` 对应于字符串的 `+` 运算符或 `string.concat(otherString)`。**
   ```javascript
   // JavaScript
   const str1 = "hello";
   const str2 = "world";
   const combined = str1 + " " + str2;
   console.log(combined); // "hello world"

   // 假设在 Wasm 中调用 WebAssemblyStringConcat("hello", "world") 将返回 "helloworld"
   ```

* **`WebAssemblyStringSubstring(string, start, end)` 对应于 `string.substring(start, end)` 或 `string.slice(start, end)`。**
   ```javascript
   // JavaScript
   const str = "hello";
   const sub = str.substring(1, 4);
   console.log(sub); // "ell"

   // 假设在 Wasm 中调用 WebAssemblyStringSubstring("hello", 1, 4) 将返回 "ell"
   ```

* **`WebAssemblyStringEquals(a, b)` 对应于 `a === b` (严格相等) 用于字符串比较。**
   ```javascript
   // JavaScript
   const str1 = "hello";
   const str2 = "hello";
   const str3 = new String("hello");
   console.log(str1 === str2); // true
   console.log(str1 === str3); // false (因为类型不同)

   // 假设在 Wasm 中调用 WebAssemblyStringEquals("hello", "hello") 将返回 1
   ```

* **`WebAssemblyStringCompare(first, second)` 对应于 `string1.localeCompare(string2)`，返回一个表示比较结果的数字（负数、零或正数）。**
   ```javascript
   // JavaScript
   const str1 = "apple";
   const str2 = "banana";
   console.log(str1.localeCompare(str2)); // -1 (apple 在 banana 之前)

   // 假设在 Wasm 中调用 WebAssemblyStringCompare("apple", "banana") 将返回一个负数
   ```

**代码逻辑推理 (假设输入与输出):**

**示例 1: `WebAssemblyStringFromUtf8Array`**

* **假设输入:**
    * `arrayArg`: 一个表示 `[104, 101, 108, 108, 111]` 的 `Uint8Array` 的 JavaScript 值。
    * `startArg`: JavaScript 值 `0`。
    * `endArg`: JavaScript 值 `5`。
* **代码逻辑:**
    1. `WasmCastToSpecialPrimitiveArray` 将 `arrayArg` 转换为 WebAssembly 的特殊原始数组类型，并验证其元素大小为 8 位。
    2. `NumberToUint32` 将 `startArg` 和 `endArg` 转换为无符号 32 位整数，分别为 `0` 和 `5`。
    3. `wasm::WasmStringNewWtf8Array`  使用提供的数组、起始和结束索引创建一个新的 Wasm 字符串。
* **预期输出:** 一个表示字符串 "hello" 的 WebAssembly 字符串对象。

**示例 2: `WebAssemblyStringLength`**

* **假设输入:**
    * `stringArg`: 一个表示字符串 "world" 的 JavaScript 值。
* **代码逻辑:**
    1. `Cast<String>` 将 `stringArg` 强制转换为字符串类型。
    2. 返回字符串对象的 `length_smi` 属性，该属性存储了字符串的长度。
* **预期输出:**  一个表示数字 `5` 的 `Smi` (Small Integer) 对象。

**用户常见的编程错误:**

1. **类型错误:**  向需要字符串的函数传递非字符串的值，例如数字或对象。这会导致 `Cast<String>` 失败，并触发 `Trap`，抛出 `kWasmTrapIllegalCast` 错误。
   ```javascript
   // JavaScript
   const wasmModule = // ... 加载的 WebAssembly 模块
   const wasmInstance = // ... 创建的 WebAssembly 实例

   // 错误示例：传递数字给需要字符串的 Wasm 函数
   try {
       wasmInstance.exports.stringLength(123);
   } catch (error) {
       console.error("错误:", error); // 可能包含 "illegal cast" 的信息
   }
   ```

2. **索引越界:**  在使用 `WebAssemblyStringCharCodeAt`、`WebAssemblyStringCodePointAt` 或 `WebAssemblyStringSubstring` 等函数时，提供超出字符串长度范围的索引。这会导致跳转到 `OOB` 标签，并触发 `Trap`，抛出 `kWasmTrapStringOffsetOutOfBounds` 错误。
   ```javascript
   // JavaScript
   const wasmModule = // ... 加载的 WebAssembly 模块
   const wasmInstance = // ... 创建的 WebAssembly 实例
   const myString = wasmInstance.exports.createString("hello");

   // 错误示例：索引越界
   try {
       wasmInstance.exports.charCodeAt(myString, 10);
   } catch (error) {
       console.error("错误:", error); // 可能包含 "string offset out of bounds" 的信息
   }
   ```

3. **编码不匹配:**  当使用 `WebAssemblyStringFromUtf8Array` 或 `WebAssemblyStringFromWtf16Array` 时，如果提供的数组的编码格式与函数期望的不符，会导致创建出错误的字符串。虽然这里没有明确的错误捕获，但在后续使用该字符串时可能会出现问题。
   ```javascript
   // JavaScript
   const wasmModule = // ... 加载的 WebAssembly 模块
   const wasmInstance = // ... 创建的 WebAssembly 实例
   const utf8Data = new Uint8Array([65, 66, 67]); // "ABC" 的 UTF-8 编码
   const wtf16Data = new Uint16Array([65, 66, 67]); // "ABC" 的 WTF-16 编码

   // 错误示例：将 UTF-8 数据当作 WTF-16 处理
   const wrongString = wasmInstance.exports.createStringFromWtf16Array(wtf16Data.buffer, 0, wtf16Data.length);
   // wrongString 的内容将不是 "ABC"，因为字节被错误地解释为 UTF-16 代码单元。
   ```

4. **假设字符串总是 ASCII:**  在处理来自 WebAssembly 的字符串时，可能错误地假设它们总是 ASCII 编码。实际上，WebAssembly 字符串可以包含各种 Unicode 字符，因此需要使用能正确处理多字节字符的函数 (例如 `WebAssemblyStringCodePointAt`)。

理解这些内置函数的功能和潜在的错误情况对于在 WebAssembly 中正确处理字符串至关重要。它们为 Wasm 提供了与 JavaScript 类似的字符串操作能力，但需要在类型和边界检查方面更加谨慎。

Prompt: 
```
这是目录为v8/src/builtins/wasm-strings.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file defines the builtins that are used as the non-optimized versions
// of the "JS String Builtins", i.e. from Liftoff code, and for exported
// functions.

macro Trap(context: Context, error: constexpr MessageTemplate): never {
  runtime::ThrowWasmError(context, SmiConstant(error));
}

transitioning javascript builtin WebAssemblyStringCast(
    js-implicit context: Context)(arg: JSAny): String {
  try {
    return Cast<String>(arg) otherwise goto IllegalCast;
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringTest(
    js-implicit context: Context)(arg: JSAny): Smi {
  return Is<String>(arg) ? SmiConstant(1) : SmiConstant(0);
}

extern runtime WasmCastToSpecialPrimitiveArray(Context, Object, Smi): WasmArray;

transitioning javascript builtin WebAssemblyStringFromWtf16Array(
    js-implicit context: Context)(arrayArg: JSAny, startArg: JSAny,
    endArg: JSAny): JSAny {
  const array =
      WasmCastToSpecialPrimitiveArray(context, arrayArg, SmiConstant(16));
  const start = NumberToUint32(ToNumber_Inline(startArg));
  const end = NumberToUint32(ToNumber_Inline(endArg));
  return wasm::WasmStringNewWtf16Array(array, start, end);
}

const kLossyUtf8:
    constexpr int31 generates 'unibrow::Utf8Variant::kLossyUtf8';

transitioning javascript builtin WebAssemblyStringFromUtf8Array(
    js-implicit context: Context)(arrayArg: JSAny, startArg: JSAny,
    endArg: JSAny): JSAny {
  const array =
      WasmCastToSpecialPrimitiveArray(context, arrayArg, SmiConstant(8));
  const start = NumberToUint32(ToNumber_Inline(startArg));
  const end = NumberToUint32(ToNumber_Inline(endArg));
  const result =
      wasm::WasmStringNewWtf8Array(start, end, array, SmiConstant(kLossyUtf8));
  dcheck(Is<String>(result));
  return %RawDownCast<String>(result);
}

transitioning javascript builtin WebAssemblyStringIntoUtf8Array(
    js-implicit context: Context)(stringArg: JSAny, arrayArg: JSAny,
    startArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    const array =
        WasmCastToSpecialPrimitiveArray(context, arrayArg, SmiConstant(8));
    const start = NumberToUint32(ToNumber_Inline(startArg));
    return runtime::WasmStringEncodeWtf8Array(
        context, SmiConstant(kLossyUtf8), string, array,
        ChangeUint32ToTagged(start));
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringToUtf8Array(
    js-implicit context: Context)(stringArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    return runtime::WasmStringToUtf8Array(context, string);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringToWtf16Array(
    js-implicit context: Context)(stringArg: JSAny, arrayArg: JSAny,
    startArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    const array =
        WasmCastToSpecialPrimitiveArray(context, arrayArg, SmiConstant(16));
    const start = NumberToUint32(ToNumber_Inline(startArg));
    const written = wasm::WasmStringEncodeWtf16Array(string, array, start);
    return Convert<Smi>(written);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringFromCharCode(
    js-implicit context: Context)(codeArg: JSAny): JSAny {
  const code = NumberToUint32(ToNumber_Inline(codeArg));
  return StringFromSingleCharCode(%RawDownCast<char16>(code & 0xFFFF));
}

transitioning javascript builtin WebAssemblyStringFromCodePoint(
    js-implicit context: Context)(codeArg: JSAny): JSAny {
  const code = ToNumber_Inline(codeArg);
  const codeUint = NumberToUint32(code);
  if (codeUint <= 0xFFFF) {
    return StringFromSingleCharCode(%RawDownCast<char16>(codeUint));
  }
  return runtime::WasmStringFromCodePoint(context, code);
}

transitioning javascript builtin WebAssemblyStringCodePointAt(
    js-implicit context: Context)(stringArg: JSAny, indexArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    const index = NumberToUint32(ToNumber_Inline(indexArg));
    if (index >= Unsigned(string.length)) goto OOB;
    const code: int32 = string::LoadSurrogatePairAt(
        string, string.length_intptr, Signed(Convert<uintptr>(index)),
        UnicodeEncoding::UTF32);
    return Convert<Smi>(code);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  } label OOB deferred {
    Trap(context, MessageTemplate::kWasmTrapStringOffsetOutOfBounds);
  }
}

transitioning javascript builtin WebAssemblyStringCharCodeAt(
    js-implicit context: Context)(stringArg: JSAny, indexArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    const index = NumberToUint32(ToNumber_Inline(indexArg));
    if (index >= Unsigned(string.length)) goto OOB;
    const code: char16 = StringCharCodeAt(string, Convert<uintptr>(index));
    return SmiTag(code);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  } label OOB deferred {
    Trap(context, MessageTemplate::kWasmTrapStringOffsetOutOfBounds);
  }
}

transitioning javascript builtin WebAssemblyStringLength(
    js-implicit context: Context)(stringArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    return string.length_smi;
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringMeasureUtf8(
    js-implicit context: Context)(stringArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    // WTF-8 length equals Lossy-UTF-8 length.
    return runtime::WasmStringMeasureWtf8(context, string);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringConcat(
    js-implicit context: Context)(firstArg: JSAny, secondArg: JSAny): JSAny {
  try {
    const first = Cast<String>(firstArg) otherwise goto IllegalCast;
    const second = Cast<String>(secondArg) otherwise goto IllegalCast;
    return StringAdd_CheckNone(first, second);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringSubstring(
    js-implicit context: Context)(stringArg: JSAny, startArg: JSAny,
    endArg: JSAny): JSAny {
  try {
    const string = Cast<String>(stringArg) otherwise goto IllegalCast;
    const start = NumberToUint32(ToNumber_Inline(startArg));
    const end = NumberToUint32(ToNumber_Inline(endArg));
    return wasm::WasmStringViewWtf16Slice(string, start, end);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringEquals(
    js-implicit context: Context)(a: JSAny, b: JSAny): JSAny {
  try {
    if (a == Null) {
      typeswitch (b) {
        case (Null): {
          return SmiConstant(1);
        }
        case (String): {
          return SmiConstant(0);
        }
        case (JSAny): {
          goto IllegalCast;
        }
      }
    }
    const left = Cast<String>(a) otherwise goto IllegalCast;
    if (b == Null) return SmiConstant(0);
    const right = Cast<String>(b) otherwise goto IllegalCast;
    if (TaggedEqual(a, b)) return SmiConstant(1);
    if (left.length != right.length) return SmiConstant(0);
    if (wasm::StringEqual(kNoContext, left, right, left.length_intptr) ==
        True) {
      return SmiConstant(1);
    }
    return SmiConstant(0);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

transitioning javascript builtin WebAssemblyStringCompare(
    js-implicit context: Context)(firstArg: JSAny, secondArg: JSAny): JSAny {
  try {
    const first = Cast<String>(firstArg) otherwise goto IllegalCast;
    const second = Cast<String>(secondArg) otherwise goto IllegalCast;
    return StringCompare(first, second);
  } label IllegalCast deferred {
    Trap(context, MessageTemplate::kWasmTrapIllegalCast);
  }
}

"""

```