Response: The user wants a summary of the C++ code provided, specifically focusing on its functionality and its relationship to JavaScript. Since this is part 5 of 6, the summary should also consider its role within the larger context of the file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code snippet primarily deals with functions within the `WasmGraphBuilder` class related to string manipulation. Keywords like `StringEncodeWtf8`, `StringToUtf8Array`, `StringConcat`, `StringEqual`, `StringViewWtf8Advance`, etc., clearly indicate this focus.

2. **Categorize the String Operations:**  The operations can be grouped into several categories:
    * **Encoding/Decoding:** Converting between different string representations (UTF-8, WTF-8, WTF-16, arrays).
    * **Basic Operations:** Concatenation, equality comparison.
    * **View/Iteration:**  Creating and manipulating views of strings, iterating through code points.
    * **Character/Code Point Access:**  Getting code units and code points at specific offsets.
    * **Conversion:** Converting from character codes and code points to strings.
    * **Hashing:** Calculating string hashes.

3. **Connect to JavaScript:**  Consider how these string operations relate to JavaScript's string functionality. Many of the C++ functions have direct parallels in JavaScript:
    * Encoding/Decoding: `TextEncoder`, `TextDecoder` APIs.
    * Basic Operations: String concatenation (`+`), equality (`===`).
    * View/Iteration: String iterators, `slice` method.
    * Character/Code Point Access: `charCodeAt`, `codePointAt`.
    * Conversion: `String.fromCharCode`, `String.fromCodePoint`.
    * Hashing: While JavaScript doesn't have a direct built-in for string hashing accessible to the user, the internal mechanism is relevant.

4. **Illustrate with JavaScript Examples:** Provide concise JavaScript code snippets to demonstrate the connection. Focus on the most direct equivalents.

5. **Consider the "Part 5 of 6" Context:** Recognize that this snippet likely represents a section of the `wasm-compiler.cc` file dedicated to handling string-related WebAssembly instructions. The previous and subsequent parts likely cover other aspects of WebAssembly compilation.

6. **Structure the Summary:** Organize the findings logically:
    * Start with a general overview of the section's purpose.
    * Detail the specific string manipulation capabilities.
    * Explain the relationship to JavaScript, providing examples.
    * Acknowledge the "part 5 of 6" context and speculate about the file's overall structure.

7. **Refine the Language:** Use clear and concise language, avoiding overly technical jargon where possible. Ensure the JavaScript examples are accurate and easy to understand. Use formatting (like bullet points and code blocks) to improve readability.

**(Self-Correction during the thought process):**

* **Initial thought:** Focus only on direct JavaScript method equivalents.
* **Correction:** Broaden the scope to include related JavaScript APIs and concepts, even if not a perfect one-to-one mapping (e.g., `TextEncoder`/`TextDecoder`).
* **Initial thought:**  Just list the C++ functions.
* **Correction:** Group the functions by functionality to provide a more thematic understanding.
* **Initial thought:** Assume the user understands internal compiler details.
* **Correction:** Explain the concepts in a way that's accessible to someone with a good understanding of JavaScript and a basic idea of compilation.

By following these steps, the generated answer effectively summarizes the provided C++ code snippet and its relationship to JavaScript within the context of WebAssembly compilation.
这段C++代码是 `v8/src/compiler/wasm-compiler.cc` 文件的第五部分，主要负责 **在 WebAssembly 图构建阶段处理 WebAssembly 字符串相关的操作**。它定义了 `WasmGraphBuilder` 类中与创建和操作 WebAssembly 字符串相关的节点的方法。

**功能归纳:**

这部分代码主要提供了以下功能：

1. **字符串的创建和转换:**
   - `StringNew`: 创建一个新的 WebAssembly 字符串。
   - `StringConst`: 创建一个常量 WebAssembly 字符串。
   - `StringFromCodePoint`, `StringFromCharCode`: 从 Unicode 代码点或字符编码创建字符串。
   - `StringToString`:  看起来像是将一个字符串转换为字符串（可能用于类型转换或确保字符串类型）。
   - `StringAsWtf8`, `StringAsWtf16`, `StringToUtf8Array`, `StringEncodeWtf8`, `StringEncodeWtf8Array`, `StringEncodeWtf16`, `StringEncodeWtf16Array`:  在不同的字符串编码（UTF-8, WTF-8, WTF-16）之间进行转换，以及与内存中的数组进行编码和解码。

2. **字符串的基本操作:**
   - `StringConcat`: 连接两个 WebAssembly 字符串。
   - `StringEqual`: 比较两个 WebAssembly 字符串是否相等。
   - `StringCompare`: 比较两个 WebAssembly 字符串。
   - `StringHash`: 计算 WebAssembly 字符串的哈希值。
   - `StringIsUSVSequence`: 检查字符串是否为 USV (Unicode Scalar Value) 序列。

3. **字符串视图 (View) 和迭代器 (Iterator) 的操作:**
   - `StringAsIter`: 将字符串转换为迭代器。
   - `StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`:  操作 WTF-8 字符串视图，包括前进、编码到内存、切片。
   - `StringViewWtf16GetCodeUnit`, `StringViewWtf16Encode`, `StringViewWtf16Slice`: 操作 WTF-16 字符串视图，包括获取代码单元、编码到内存、切片。
   - `StringViewIterNext`, `StringViewIterAdvance`, `StringViewIterRewind`, `StringViewIterSlice`:  操作字符串迭代器，包括获取下一个元素、前进、后退、切片。

4. **获取字符串信息:**
   - `WellKnown_StringIndexOf`:  实现类似于 JavaScript 的 `String.prototype.indexOf()` 功能。

5. **与其他类型的转换:**
   - `WellKnown_ParseFloat`: 将字符串解析为浮点数，类似于 JavaScript 的 `parseFloat()`。
   - `WellKnown_DoubleToString`, `WellKnown_IntToString`: 将数字转换为字符串，类似于 JavaScript 的 `Number.prototype.toString()`。

6. **国际化支持 (如果启用):**
   - `WellKnown_StringToLocaleLowerCaseStringref`, `WellKnown_StringToLowerCaseStringref`: 实现类似于 JavaScript 的 `String.prototype.toLocaleLowerCase()` 和 `String.prototype.toLowerCase()` 功能。

**与 JavaScript 的关系及 JavaScript 示例:**

这段代码的功能直接对应了 JavaScript 中 `String` 对象及其原型上的方法。WebAssembly 需要一种方式来操作字符串，以便与 JavaScript 代码进行互操作。`WasmGraphBuilder` 中定义的这些方法最终会被编译成机器码，用于执行 WebAssembly 模块中的字符串操作。

以下是一些 JavaScript 示例，展示了 C++ 代码中功能的对应关系：

* **`StringConcat` 对应 JavaScript 的字符串连接：**

   ```javascript
   const str1 = "Hello";
   const str2 = "World";
   const result = str1 + " " + str2; // 对应 StringConcat
   console.log(result); // 输出 "Hello World"
   ```

* **`StringEqual` 对应 JavaScript 的字符串相等比较：**

   ```javascript
   const strA = "test";
   const strB = "test";
   const isEqual = (strA === strB); // 对应 StringEqual
   console.log(isEqual); // 输出 true
   ```

* **`WellKnown_StringIndexOf` 对应 JavaScript 的 `String.prototype.indexOf()`：**

   ```javascript
   const text = "This is a test string";
   const index = text.indexOf("test"); // 对应 WellKnown_StringIndexOf
   console.log(index); // 输出 10
   ```

* **`WellKnown_ParseFloat` 对应 JavaScript 的 `parseFloat()`：**

   ```javascript
   const floatStr = "3.14";
   const floatNum = parseFloat(floatStr); // 对应 WellKnown_ParseFloat
   console.log(floatNum); // 输出 3.14
   ```

* **`WellKnown_DoubleToString` 对应 JavaScript 的 `Number.prototype.toString()`：**

   ```javascript
   const num = 123.45;
   const numStr = num.toString(); // 对应 WellKnown_DoubleToString
   console.log(numStr); // 输出 "123.45"
   ```

* **`String.fromCodePoint` 对应 `StringFromCodePoint`：**

   ```javascript
   const emoji = String.fromCodePoint(0x1F600); // 对应 StringFromCodePoint
   console.log(emoji); // 输出 😊
   ```

**作为第 5 部分的功能:**

考虑到这是 `wasm-compiler.cc` 的第五部分，并且专注于字符串操作，可以推测：

* **前面的部分 (1-4) 可能处理了 WebAssembly 模块的解析、验证、基本类型的处理（数字、布尔值等）、内存操作等。**
* **后面的部分 (6) 很可能处理编译的最后阶段，例如代码生成、优化、或者与其他 V8 引擎的集成。**

因此，第五部分在整个 WebAssembly 编译流程中扮演着关键的角色，**负责将 WebAssembly 字符串相关的指令转换为底层的图节点，以便后续的优化和代码生成阶段能够处理这些字符串操作。** 它确保了 WebAssembly 模块能够有效地处理文本数据，并与 JavaScript 环境中的字符串进行互操作。

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
osition);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start,
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringToUtf8Array(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringToUtf8Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string);
}

Node* WasmGraphBuilder::StringEncodeWtf16(const wasm::WasmMemory* memory,
                                          Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            offset, gasm_->Int32Constant(memory->index));
}

Node* WasmGraphBuilder::StringAsWtf16(Node* string, CheckForNull null_check,
                                      wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->StringAsWtf16(string);
}

Node* WasmGraphBuilder::StringEncodeWtf16Array(
    Node* string, CheckForNull string_null_check, Node* array,
    CheckForNull array_null_check, Node* start,
    wasm::WasmCodePosition position) {
  if (string_null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringEncodeWtf16Array,
                            Operator::kNoDeopt | Operator::kNoThrow, string,
                            array, start);
}

Node* WasmGraphBuilder::StringConcat(Node* head, CheckForNull head_null_check,
                                     Node* tail, CheckForNull tail_null_check,
                                     wasm::WasmCodePosition position) {
  if (head_null_check == kWithNullCheck) {
    head = AssertNotNull(head, wasm::kWasmStringRef, position);
  }
  if (tail_null_check == kWithNullCheck) {
    tail = AssertNotNull(tail, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(
      Builtin::kStringAdd_CheckNone, Operator::kNoDeopt | Operator::kNoThrow,
      head, tail,
      LOAD_INSTANCE_FIELD(NativeContext, MachineType::TaggedPointer()));
}

Node* WasmGraphBuilder::StringEqual(Node* a, wasm::ValueType a_type, Node* b,
                                    wasm::ValueType b_type,
                                    wasm::WasmCodePosition position) {
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  // Covers "identical string pointer" and "both are null" cases.
  gasm_->GotoIf(gasm_->TaggedEqual(a, b), &done, Int32Constant(1));
  if (a_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(a, a_type), &done, Int32Constant(0));
  }
  if (b_type.is_nullable()) {
    gasm_->GotoIf(gasm_->IsNull(b, b_type), &done, Int32Constant(0));
  }
  // TODO(jkummerow): Call Builtin::kStringEqual directly.
  gasm_->Goto(&done, gasm_->CallBuiltin(Builtin::kWasmStringEqual,
                                        Operator::kEliminatable, a, b));
  gasm_->Bind(&done);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringIsUSVSequence(Node* str, CheckForNull null_check,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringIsUSVSequence,
                            Operator::kEliminatable, str);
}

Node* WasmGraphBuilder::StringAsWtf8(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsWtf8, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewWtf8Advance(Node* view,
                                              CheckForNull null_check,
                                              Node* pos, Node* bytes,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Advance,
                            Operator::kEliminatable, view, pos, bytes);
}

void WasmGraphBuilder::StringViewWtf8Encode(
    const wasm::WasmMemory* memory, unibrow::Utf8Variant variant, Node* view,
    CheckForNull null_check, Node* addr, Node* pos, Node* bytes,
    Node** next_pos, Node** bytes_written, wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&addr}, position);
  Node* pair =
      gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Encode,
                         Operator::kNoDeopt | Operator::kNoThrow, addr, pos,
                         bytes, view, gasm_->SmiConstant(memory->index),
                         gasm_->SmiConstant(static_cast<int32_t>(variant)));
  *next_pos = gasm_->Projection(0, pair);
  *bytes_written = gasm_->Projection(1, pair);
}

Node* WasmGraphBuilder::StringViewWtf8Slice(Node* view, CheckForNull null_check,
                                            Node* pos, Node* bytes,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf8Slice,
                            Operator::kEliminatable, view, pos, bytes);
}

Node* WasmGraphBuilder::StringViewWtf16GetCodeUnit(
    Node* string, CheckForNull null_check, Node* offset,
    wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* result = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                                object_offset);
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringViewWtf16GetCodeUnit,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringCodePointAt(Node* string, CheckForNull null_check,
                                          Node* offset,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  Node* prepare = gasm_->StringPrepareForGetCodeunit(string);
  Node* base = gasm_->Projection(0, prepare);
  Node* base_offset = gasm_->Projection(1, prepare);
  Node* charwidth_shift = gasm_->Projection(2, prepare);

  // Bounds check.
  Node* length = gasm_->LoadStringLength(string);
  TrapIfFalse(wasm::kTrapStringOffsetOutOfBounds,
              gasm_->Uint32LessThan(offset, length), position);

  auto onebyte = gasm_->MakeLabel();
  auto bailout = gasm_->MakeDeferredLabel();
  auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);
  gasm_->GotoIf(
      gasm_->Word32Equal(charwidth_shift,
                         gasm_->Int32Constant(kCharWidthBailoutSentinel)),
      &bailout);
  gasm_->GotoIf(gasm_->Word32Equal(charwidth_shift, gasm_->Int32Constant(0)),
                &onebyte);

  // Two-byte.
  Node* object_offset =
      gasm_->IntAdd(gasm_->IntMul(gasm_->BuildChangeInt32ToIntPtr(offset),
                                  gasm_->IntPtrConstant(2)),
                    base_offset);
  Node* lead = gasm_->LoadImmutableFromObject(MachineType::Uint16(), base,
                                              object_offset);
  Node* is_lead_surrogate =
      gasm_->Word32Equal(gasm_->Word32And(lead, gasm_->Int32Constant(0xFC00)),
                         gasm_->Int32Constant(0xD800));
  gasm_->GotoIfNot(is_lead_surrogate, &done, lead);
  Node* trail_offset = gasm_->Int32Add(offset, gasm_->Int32Constant(1));
  gasm_->GotoIfNot(gasm_->Uint32LessThan(trail_offset, length), &done, lead);
  Node* trail = gasm_->LoadImmutableFromObject(
      MachineType::Uint16(), base,
      gasm_->IntAdd(object_offset, gasm_->IntPtrConstant(2)));
  Node* is_trail_surrogate =
      gasm_->WordEqual(gasm_->Word32And(trail, gasm_->Int32Constant(0xFC00)),
                       gasm_->Int32Constant(0xDC00));
  gasm_->GotoIfNot(is_trail_surrogate, &done, lead);
  Node* surrogate_bias =
      gasm_->Int32Constant(0x10000 - (0xD800 << 10) - 0xDC00);
  Node* result =
      gasm_->Int32Add(gasm_->Word32Shl(lead, gasm_->Int32Constant(10)),
                      gasm_->Int32Add(trail, surrogate_bias));
  gasm_->Goto(&done, result);

  // One-byte.
  gasm_->Bind(&onebyte);
  object_offset =
      gasm_->IntAdd(gasm_->BuildChangeInt32ToIntPtr(offset), base_offset);
  result =
      gasm_->LoadImmutableFromObject(MachineType::Uint8(), base, object_offset);
  gasm_->Goto(&done, result);

  gasm_->Bind(&bailout);
  gasm_->Goto(&done, gasm_->CallBuiltinThroughJumptable(
                         Builtin::kWasmStringCodePointAt,
                         Operator::kEliminatable, string, offset));

  gasm_->Bind(&done);
  // Make sure the original string is kept alive as long as we're operating
  // on pointers extracted from it (otherwise e.g. external strings' resources
  // might get freed prematurely).
  gasm_->Retain(string);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::StringViewWtf16Encode(const wasm::WasmMemory* memory,
                                              Node* string,
                                              CheckForNull null_check,
                                              Node* offset, Node* start,
                                              Node* codeunits,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Encode,
                            Operator::kNoDeopt | Operator::kNoThrow, offset,
                            start, codeunits, string,
                            gasm_->SmiConstant(memory->index));
}

Node* WasmGraphBuilder::StringViewWtf16Slice(Node* string,
                                             CheckForNull null_check,
                                             Node* start, Node* end,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringViewWtf16Slice,
                            Operator::kEliminatable, string, start, end);
}

Node* WasmGraphBuilder::StringAsIter(Node* str, CheckForNull null_check,
                                     wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    str = AssertNotNull(str, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringAsIter, Operator::kEliminatable,
                            str);
}

Node* WasmGraphBuilder::StringViewIterNext(Node* view, CheckForNull null_check,
                                           wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterNext,
                            Operator::kEliminatable, view);
}

Node* WasmGraphBuilder::StringViewIterAdvance(Node* view,
                                              CheckForNull null_check,
                                              Node* codepoints,
                                              wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterAdvance,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterRewind(Node* view,
                                             CheckForNull null_check,
                                             Node* codepoints,
                                             wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterRewind,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringViewIterSlice(Node* view, CheckForNull null_check,
                                            Node* codepoints,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    view = AssertNotNull(view, wasm::kWasmStringRef, position);
  }

  return gasm_->CallBuiltin(Builtin::kWasmStringViewIterSlice,
                            Operator::kEliminatable, view, codepoints);
}

Node* WasmGraphBuilder::StringCompare(Node* lhs, CheckForNull null_check_lhs,
                                      Node* rhs, CheckForNull null_check_rhs,
                                      wasm::WasmCodePosition position) {
  if (null_check_lhs == kWithNullCheck) {
    lhs = AssertNotNull(lhs, wasm::kWasmStringRef, position);
  }
  if (null_check_rhs == kWithNullCheck) {
    rhs = AssertNotNull(rhs, wasm::kWasmStringRef, position);
  }
  return gasm_->BuildChangeSmiToInt32(gasm_->CallBuiltin(
      Builtin::kStringCompare, Operator::kEliminatable, lhs, rhs));
}

Node* WasmGraphBuilder::StringFromCharCode(Node* char_code) {
  Node* capped = gasm_->Word32And(char_code, gasm_->Uint32Constant(0xFFFF));
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kEliminatable, capped);
}

Node* WasmGraphBuilder::StringFromCodePoint(Node* code_point) {
  // TODO(jkummerow): Refactor the code in
  // EffectControlLinearizer::LowerStringFromSingleCodePoint to make it
  // accessible for Wasm.
  // This call traps when the {code_point} is invalid.
  return gasm_->CallBuiltin(Builtin::kWasmStringFromCodePoint,
                            Operator::kNoDeopt | Operator::kNoWrite,
                            code_point);
}

Node* WasmGraphBuilder::StringHash(Node* string, CheckForNull null_check,
                                   wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }

  auto runtime_label = gasm_->MakeLabel();
  auto end_label = gasm_->MakeLabel(MachineRepresentation::kWord32);

  Node* raw_hash = gasm_->LoadFromObject(
      MachineType::Int32(), string,
      wasm::ObjectAccess::ToTagged(offsetof(Name, raw_hash_field_)));
  Node* hash_not_computed_mask =
      gasm_->Int32Constant(static_cast<int32_t>(Name::kHashNotComputedMask));
  static_assert(Name::HashFieldTypeBits::kShift == 0);
  Node* hash_not_computed = gasm_->Word32And(raw_hash, hash_not_computed_mask);
  gasm_->GotoIf(hash_not_computed, &runtime_label);

  // Fast path if hash is already computed: Decode raw hash value.
  static_assert(Name::HashBits::kLastUsedBit == kBitsPerInt - 1);
  Node* hash = gasm_->Word32Shr(
      raw_hash,
      gasm_->Int32Constant(static_cast<int32_t>(Name::HashBits::kShift)));
  gasm_->Goto(&end_label, hash);

  gasm_->Bind(&runtime_label);
  Node* hash_runtime = gasm_->CallBuiltin(Builtin::kWasmStringHash,
                                          Operator::kEliminatable, string);
  gasm_->Goto(&end_label, hash_runtime);

  gasm_->Bind(&end_label);
  return end_label.PhiAt(0);
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlagHelper(
    Node* thread_in_wasm_flag_address, bool new_value) {
  if (v8_flags.debug_code) {
    Node* flag_value =
        gasm_->Load(MachineType::Int32(), thread_in_wasm_flag_address, 0);
    Node* check =
        gasm_->Word32Equal(flag_value, Int32Constant(new_value ? 0 : 1));
    Assert(check, new_value ? AbortReason::kUnexpectedThreadInWasmSet
                            : AbortReason::kUnexpectedThreadInWasmUnset);
  }

  gasm_->Store({MachineRepresentation::kWord32, kNoWriteBarrier},
               thread_in_wasm_flag_address, 0,
               Int32Constant(new_value ? 1 : 0));
}

void WasmGraphBuilder::BuildModifyThreadInWasmFlag(bool new_value) {
  if (!trap_handler::IsTrapHandlerEnabled()) return;
  Node* isolate_root = BuildLoadIsolateRoot();

  Node* thread_in_wasm_flag_address =
      gasm_->Load(MachineType::Pointer(), isolate_root,
                  Isolate::thread_in_wasm_flag_address_offset());

  BuildModifyThreadInWasmFlagHelper(thread_in_wasm_flag_address, new_value);
}

void WasmGraphBuilder::Assert(Node* condition, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  Diamond check(graph(), mcgraph()->common(), condition, BranchHint::kTrue);
  check.Chain(control());
  SetControl(check.if_false);
  Node* message_id = gasm_->NumberConstant(static_cast<int32_t>(abort_reason));
  Node* old_effect = effect();
  Node* call = BuildCallToRuntimeWithContext(
      Runtime::kAbort, NoContextConstant(), &message_id, 1);
  check.merge->ReplaceInput(1, call);
  SetEffectControl(check.EffectPhi(old_effect, effect()), check.merge);
}

Node* WasmGraphBuilder::WellKnown_StringIndexOf(
    Node* string, Node* search, Node* start, CheckForNull string_null_check,
    CheckForNull search_null_check) {
  if (string_null_check == kWithNullCheck) {
    // If string is null, throw.
    auto if_not_null = gasm_->MakeLabel();
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    gasm_->Goto(&if_not_null);
    gasm_->Bind(&if_null);
    gasm_->CallBuiltin(Builtin::kThrowIndexOfCalledOnNull, Operator::kNoWrite);
    gasm_->Unreachable();
    gasm_->Bind(&if_not_null);
  }
  if (search_null_check == kWithNullCheck) {
    // If search is null, replace it with "null".
    auto search_not_null =
        gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
    gasm_->GotoIfNot(IsNull(search, wasm::kWasmStringRef), &search_not_null,
                     search);
    Node* null_string = LOAD_ROOT(null_string, null_string);
    gasm_->Goto(&search_not_null, null_string);
    gasm_->Bind(&search_not_null);
    search = search_not_null.PhiAt(0);
  }
  {
    // Clamp the start index.
    auto clamped_start = gasm_->MakeLabel(MachineRepresentation::kWord32);
    gasm_->GotoIf(gasm_->Int32LessThan(start, Int32Constant(0)), &clamped_start,
                  Int32Constant(0));
    Node* length = gasm_->LoadStringLength(string);
    gasm_->GotoIf(gasm_->Int32LessThan(start, length), &clamped_start, start);
    gasm_->Goto(&clamped_start, length);
    gasm_->Bind(&clamped_start);
    start = clamped_start.PhiAt(0);
  }

  BuildModifyThreadInWasmFlag(false);
  // This can't overflow because we've clamped {start} above.
  Node* start_smi = gasm_->BuildChangeInt32ToSmi(start);
  Node* result =
      gasm_->CallBuiltin(Builtin::kStringIndexOf, Operator::kEliminatable,
                         string, search, start_smi);
  BuildModifyThreadInWasmFlag(true);
  return gasm_->BuildChangeSmiToInt32(result);
}

Node* WasmGraphBuilder::WellKnown_StringToLocaleLowerCaseStringref(
    int func_index, Node* string, Node* locale,
    CheckForNull string_null_check) {
#if V8_INTL_SUPPORT
  if (string_null_check == kWithNullCheck) {
    // We can let the builtin throw the exception, but it only checks for
    // JS null, so we must externalize any Wasm null here.
    // Externalizing the {locale} is not required, because
    // {Object::ConvertToString} has been taught how to deal with WasmNull.
    string = gasm_->WasmExternConvertAny(string);
  }
  int param_count = 2;  // String, locale.
  CallDescriptor* call_descriptor = Linkage::GetJSCallDescriptor(
      zone_, false, param_count, CallDescriptor::kCanUseRoots,
      Operator::kNoDeopt | Operator::kNoWrite);
  Node* callees_array =
      LOAD_INSTANCE_FIELD(WellKnownImports, MachineType::TaggedPointer());
  Node* callee = gasm_->LoadFixedArrayElementPtr(callees_array, func_index);
  Node* context = gasm_->LoadContextFromJSFunction(callee);
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->Call(call_descriptor, callee, string, locale,
                             UndefinedValue(),                   // new.target
                             gasm_->Int32Constant(param_count),  // argc
                             context);                           // context
  BuildModifyThreadInWasmFlag(true);
  return result;
#else
  UNREACHABLE();
#endif
}

Node* WasmGraphBuilder::WellKnown_StringToLowerCaseStringref(
    Node* string, CheckForNull null_check) {
#if V8_INTL_SUPPORT
  BuildModifyThreadInWasmFlag(false);
  if (null_check == kWithNullCheck) {
    auto if_not_null = gasm_->MakeLabel();
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    gasm_->Goto(&if_not_null);
    gasm_->Bind(&if_null);
    gasm_->CallBuiltin(Builtin::kThrowToLowerCaseCalledOnNull,
                       Operator::kNoWrite);
    gasm_->Unreachable();
    gasm_->Bind(&if_not_null);
  }
  Node* result =
      gasm_->CallBuiltin(Builtin::kStringToLowerCaseIntl,
                         Operator::kEliminatable, string, NoContextConstant());
  BuildModifyThreadInWasmFlag(true);
  return result;
#else
  UNREACHABLE();
#endif
}

Node* WasmGraphBuilder::WellKnown_ParseFloat(Node* string,
                                             CheckForNull null_check) {
  if (null_check == kWithNullCheck) {
    auto done = gasm_->MakeLabel(MachineRepresentation::kFloat64);
    auto if_null = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsNull(string, wasm::kWasmStringRef), &if_null);
    BuildModifyThreadInWasmFlag(false);
    Node* result = gasm_->CallBuiltin(Builtin::kWasmStringToDouble,
                                      Operator::kEliminatable, string);
    BuildModifyThreadInWasmFlag(true);
    gasm_->Goto(&done, result);
    gasm_->Bind(&if_null);
    gasm_->Goto(&done,
                Float64Constant(std::numeric_limits<double>::quiet_NaN()));
    gasm_->Bind(&done);
    return done.PhiAt(0);
  } else {
    BuildModifyThreadInWasmFlag(false);
    Node* result = gasm_->CallBuiltin(Builtin::kWasmStringToDouble,
                                      Operator::kEliminatable, string);
    BuildModifyThreadInWasmFlag(true);
    return result;
  }
}

Node* WasmGraphBuilder::WellKnown_DoubleToString(Node* n) {
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->CallBuiltin(Builtin::kWasmFloat64ToString,
                                    Operator::kEliminatable, n);
  BuildModifyThreadInWasmFlag(true);
  return result;
}

Node* WasmGraphBuilder::WellKnown_IntToString(Node* n, Node* radix) {
  BuildModifyThreadInWasmFlag(false);
  Node* result = gasm_->CallBuiltin(Builtin::kWasmIntToString,
                                    Operator::kNoDeopt, n, radix);
  BuildModifyThreadInWasmFlag(true);
  return result;
}

Node* WasmGraphBuilder::RefI31(Node* input) {
  if constexpr (SmiValuesAre31Bits()) {
    return gasm_->Word32Shl(input, gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // Set the topmost bit to sign-extend the second bit. This way,
    // interpretation in JS (if this value escapes there) will be the same as
    // i31.get_s.
    input = gasm_->BuildChangeInt32ToIntPtr(input);
    return gasm_->WordSar(
        gasm_->WordShl(input,
                       gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize + 1)),
        gasm_->IntPtrConstant(1));
  }
}

Node* WasmGraphBuilder::I31GetS(Node* input, CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    input = AssertNotNull(input, wasm::kWasmI31Ref, position);
  }
  if constexpr (SmiValuesAre31Bits()) {
    input = gasm_->BuildTruncateIntPtrToInt32(input);
    return gasm_->Word32SarShiftOutZeros(input,
                                         gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // Topmost bit is already sign-extended.
    return gasm_->BuildTruncateIntPtrToInt32(gasm_->WordSar(
        input, gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize)));
  }
}

Node* WasmGraphBuilder::I31GetU(Node* input, CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    input = AssertNotNull(input, wasm::kWasmI31Ref, position);
  }
  if constexpr (SmiValuesAre31Bits()) {
    input = gasm_->BuildTruncateIntPtrToInt32(input);
    return gasm_->Word32Shr(input, gasm_->BuildSmiShiftBitsConstant32());
  } else {
    DCHECK(SmiValuesAre32Bits());
    // We need to remove the topmost bit of the 32-bit Smi.
    return gasm_->BuildTruncateIntPtrToInt32(
        gasm_->WordShr(gasm_->WordShl(input, gasm_->IntPtrConstant(1)),
                       gasm_->IntPtrConstant(kSmiShiftSize + kSmiTagSize + 1)));
  }
}

Node* WasmGraphBuilder::SetType(Node* node, wasm::ValueType type) {
  DCHECK_NOT_NULL(env_);
  if (!compiler::NodeProperties::IsTyped(node)) {
    compiler::NodeProperties::SetType(
        node, compiler::Type::Wasm(type, env_->module, graph_zone()));
  } else {
    // We might try to set the type twice since some nodes are cached in the
    // graph assembler, but we should never change the type.
    // The exception is imported strings support, which may special-case
    // values that are officially externref-typed as being known to be strings.
#if DEBUG
    static constexpr wasm::ValueType kRefExtern =
        wasm::ValueType::Ref(wasm::HeapType::kExtern);
    DCHECK((compiler::NodeProperties::GetType(node).AsWasm().type == type) ||
           (enabled_features_.has_imported_strings() &&
            compiler::NodeProperties::GetType(node).AsWasm().type ==
                wasm::kWasmRefExternString &&
            (type == wasm::kWasmExternRef || type == kRefExtern)));
#endif
  }
  return node;
}

class WasmDecorator final : public GraphDecorator {
 public:
  explicit WasmDecorator(NodeOriginTable* origins, wasm::Decoder* decoder)
      : origins_(origins), decoder_(decoder) {}

  void Decorate(Node* node) final {
    origins_->SetNodeOrigin(
        node, NodeOrigin("wasm graph creation", "n/a",
                         NodeOrigin::kWasmBytecode, decoder_->position()));
  }

 private:
  compiler::NodeOriginTable* origins_;
  wasm::Decoder* decoder_;
};

void WasmGraphBuilder::AddBytecodePositionDecorator(
    NodeOriginTable* node_origins, wasm::Decoder* decoder) {
  DCHECK_NULL(decorator_);
  decorator_ = graph()->zone()->New<WasmDecorator>(node_origins, decoder);
  graph()->AddDecorator(decorator_);
}

void WasmGraphBuilder::RemoveBytecodePositionDecorator() {
  DCHECK_NOT_NULL(decorator_);
  graph()->RemoveDecorator(decorator_);
  decorator_ = nullptr;
}

namespace {

// A non-null {isolate} signifies that the generated code is treated as being in
// a JS frame for functions like BuildLoadIsolateRoot().
class WasmWrapperGraphBuilder : public WasmGraphBuilder {
 public:
  WasmWrapperGraphBuilder(Zone* zone, MachineGraph* mcgraph,
                          const wasm::CanonicalSig* sig,
                          ParameterMode parameter_mode, Isolate* isolate,
                          compiler::SourcePositionTable* spt)
      : WasmGraphBuilder(nullptr, zone, mcgraph, nullptr, spt, parameter_mode,
                         isolate, wasm::WasmEnabledFeatures::All(), sig) {}

  CallDescriptor* GetBigIntToI64CallDescriptor(bool needs_frame_state) {
    return wasm::GetWasmEngine()->call_descriptors()->GetBigIntToI64Descriptor(
        needs_frame_state);
  }

  Node* GetTargetForBuiltinCall(Builtin builtin) {
    // Per-process shared wrappers don't have access to a jump table, so they
    // can't use kCallWasmRuntimeStub mode.
    return gasm_->GetBuiltinPointerTarget(builtin);
  }

  Node* IsNull(Node* object, wasm::CanonicalValueType type) {
    // We immediately lower null in wrappers, as they do not go through a
    // lowering phase.
    Node* null = type.use_wasm_null() ? LOAD_ROOT(WasmNull, wasm_null)
                                      : LOAD_ROOT(NullValue, null_value);
    return gasm_->TaggedEqual(object, null);
  }

  Node* BuildChangeInt32ToNumber(Node* value) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    if (SmiValuesAre32Bits()) {
      return gasm_->BuildChangeInt32ToSmi(value);
    }
    DCHECK(SmiValuesAre31Bits());

    auto builtin = gasm_->MakeDeferredLabel();
    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);

    // Double value to test if value can be a Smi, and if so, to convert it.
    Node* add = gasm_->Int32AddWithOverflow(value, value);
    Node* ovf = gasm_->Projection(1, add);
    gasm_->GotoIf(ovf, &builtin);

    // If it didn't overflow, the result is {2 * value} as pointer-sized value.
    Node* smi_tagged =
        gasm_->BuildChangeInt32ToIntPtr(gasm_->Projection(0, add));
    gasm_->Goto(&done, smi_tagged);

    // Otherwise, call builtin, to convert to a HeapNumber.
    gasm_->Bind(&builtin);
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmInt32ToHeapNumber);
    if (!int32_to_heapnumber_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmInt32ToHeapNumberDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      int32_to_heapnumber_operator_.set(common->Call(call_descriptor));
    }
    Node* call =
        gasm_->Call(int32_to_heapnumber_operator_.get(), target, value);
    gasm_->Goto(&done, call);
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* BuildChangeTaggedToInt32(Node* value, Node* context,
                                 Node* frame_state) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    auto builtin = gasm_->MakeDeferredLabel();
    auto done = gasm_->MakeLabel(MachineRepresentation::kWord32);

    gasm_->GotoIfNot(IsSmi(value), &builtin);

    // If Smi, convert to int32.
    Node* smi = gasm_->BuildChangeSmiToInt32(value);
    gasm_->Goto(&done, smi);

    // Otherwise, call builtin which changes non-Smi to Int32.
    gasm_->Bind(&builtin);
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmTaggedNonSmiToInt32);
    if (!tagged_non_smi_to_int32_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmTaggedNonSmiToInt32Descriptor(), 0,
          frame_state ? CallDescriptor::kNeedsFrameState
                      : CallDescriptor::kNoFlags,
          Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
      tagged_non_smi_to_int32_operator_.set(common->Call(call_descriptor));
    }
    Node* call = frame_state
                     ? gasm_->Call(tagged_non_smi_to_int32_operator_.get(),
                                   target, value, context, frame_state)
                     : gasm_->Call(tagged_non_smi_to_int32_operator_.get(),
                                   target, value, context);
    // The source position here is needed for asm.js, see the comment on the
    // source position of the call to JavaScript in the wasm-to-js wrapper.
    SetSourcePosition(call, 1);
    gasm_->Goto(&done, call);
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* BuildChangeFloat32ToNumber(Node* value) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmFloat32ToNumber);
    if (!float32_to_number_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmFloat32ToNumberDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      float32_to_number_operator_.set(common->Call(call_descriptor));
    }
    return gasm_->Call(float32_to_number_operator_.get(), target, value);
  }

  Node* BuildChangeFloat64ToNumber(Node* value) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmFloat64ToNumber);
    if (!float64_to_number_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmFloat64ToTaggedDescriptor(), 0,
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      float64_to_number_operator_.set(common->Call(call_descriptor));
    }
    return gasm_->Call(float64_to_number_operator_.get(), target, value);
  }

  Node* BuildChangeTaggedToFloat64(Node* value, Node* context,
                                   Node* frame_state) {
    CommonOperatorBuilder* common = mcgraph()->common();
    Node* target = GetTargetForBuiltinCall(Builtin::kWasmTaggedToFloat64);
    bool needs_frame_state = frame_state != nullptr;
    if (!tagged_to_float64_operator_.is_set()) {
      auto call_descriptor = Linkage::GetStubCallDescriptor(
          mcgraph()->zone(), WasmTaggedToFloat64Descriptor(), 0,
          frame_state ? CallDescriptor::kNeedsFrameState
                      : CallDescriptor::kNoFlags,
          Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
      tagged_to_float64_operator_.set(common->Call(call_descriptor));
    }
    Node* call = needs_frame_state
                     ? gasm_->Call(tagged_to_float64_operator_.get(), target,
                                   value, context, frame_state)
                     : gasm_->Call(tagged_to_float64_operator_.get(), target,
                                   value, context);
    // The source position here is needed for asm.js, see the comment on the
    // source position of the call to JavaScript in the wasm-to-js wrapper.
    SetSourcePosition(call, 1);
    return call;
  }

  int AddArgumentNodes(base::Vector<Node*> args, int pos, int param_count,
                       const wasm::CanonicalSig* sig, Node* context) {
    // Convert wasm numbers to JS values and drop the instance node.
    for (int i = 0; i < param_count; ++i) {
      Node* param = Param(i + 1);
      args[pos++] = ToJS(param, sig->GetParam(i), context);
    }
    return pos;
  }

  Node* ToJS(Node* node, wasm::CanonicalValueType type, Node* context) {
    switch (type.kind()) {
      case wasm::kI32:
        return BuildChangeInt32ToNumber(node);
      case wasm::kI64:
        return BuildChangeInt64ToBigInt(node,
                                        StubCallMode::kCallBuiltinPointer);
      case wasm::kF32:
        return BuildChangeFloat32ToNumber(node);
      case wasm::kF64:
        return BuildChangeFloat64ToNumber(node);
      case wasm::kRef:
        switch (type.heap_representation_non_shared()) {
          case wasm::HeapType::kEq:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kAny:
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kString:
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kExn:
          case wasm::HeapType::kNoExn:
            return node;
          case wasm::HeapType::kBottom:
          case wasm::HeapType::kTop:
          case wasm::HeapType::kStringViewWtf8:
          case wasm::HeapType::kStringViewWtf16:
          case wasm::HeapType::kStringViewIter:
            UNREACHABLE();
          case wasm::HeapType::kFunc:
          default:
            if (type.heap_representation_non_shared() ==
                    wasm::HeapType::kFunc ||
                wasm::GetTypeCanonicalizer()->IsFunctionSignature(
                    type.ref_index())) {
              // Function reference. Extract the external function.
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              Node* internal = gasm_->LoadTrustedPointerFromObject(
                  node,
                  wasm::ObjectAccess::ToTagged(
                      WasmFuncRef::kTrustedInternalOffset),
                  kWasmInternalFunctionIndirectPointerTag);
              Node* maybe_external = gasm_->LoadFromObject(
                  MachineType::TaggedPointer(), internal,
                  wasm::ObjectAccess::ToTagged(
                      WasmInternalFunction::kExternalOffset));
              gasm_->GotoIfNot(
                  gasm_->TaggedEqual(maybe_external, UndefinedValue()), &done,
                  maybe_external);
              Node* from_builtin = gasm_->CallBuiltin(
                  Builtin::kWasmInternalFunctionCreateExternal,
                  Operator::kNoProperties, internal, context);
              gasm_->Goto(&done, from_builtin);
              gasm_->Bind(&done);
              return done.PhiAt(0);
            } else {
              return node;
            }
        }
      case wasm::kRefNull:
        switch (type.heap_representation_non_shared()) {
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kExn:
          case wasm::HeapType::kNoExn:
            return node;
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
            return LOAD_ROOT(NullValue, null_value);
          case wasm::HeapType::kEq:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kString:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kAny: {
            auto done = gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
            gasm_->GotoIfNot(IsNull(node, type), &done, node);
            gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
            gasm_->Bind(&done);
            return done.PhiAt(0);
          }
          case wasm::HeapType::kFunc:
          default: {
            if (type.heap_representation_non_shared() ==
                    wasm::HeapType::kFunc ||
                wasm::GetTypeCanonicalizer()->IsFunctionSignature(
                    type.ref_index())) {
              // Function reference. Extract the external function.
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              auto null_label = gasm_->MakeLabel();
              gasm_->GotoIf(IsNull(node, type), &null_label);
              Node* internal = gasm_->LoadTrustedPointerFromObject(
                  node,
                  wasm::ObjectAccess::ToTagged(
                      WasmFuncRef::kTrustedInternalOffset),
                  kWasmInternalFunctionIndirectPointerTag);
              Node* maybe_external = gasm_->LoadFromObject(
                  MachineType::TaggedPointer(), internal,
                  wasm::ObjectAccess::ToTagged(
                      WasmInternalFunction::kExternalOffset));
              gasm_->GotoIfNot(
                  gasm_->TaggedEqual(maybe_external, UndefinedValue()), &done,
                  maybe_external);
              Node* from_builtin = gasm_->CallBuiltin(
                  Builtin::kWasmInternalFunctionCreateExternal,
                  Operator::kNoProperties, internal, context);
              gasm_->Goto(&done, from_builtin);
              gasm_->Bind(&null_label);
              gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
              gasm_->Bind(&done);
              return done.PhiAt(0);
            } else {
              auto done =
                  gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
              gasm_->GotoIfNot(IsNull(node, type), &done, node);
              gasm_->Goto(&done, LOAD_ROOT(NullValue, null_value));
              gasm_->Bind(&done);
              return done.PhiAt(0);
            }
          }
        }
      case wasm::kRtt:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kS128:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  Node* BuildChangeBigIntToInt64(Node* input, Node* context,
                                 Node* frame_state) {
    Node* target;
    if (mcgraph()->machine()->Is64()) {
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI64);
    } else {
      DCHECK(mcgraph()->machine()->Is32());
      // On 32-bit platforms we already set the target to the
      // BigIntToI32Pair builtin here, so that we don't have to replace the
      // target in the int64-lowering.
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI32Pair);
    }

    return frame_state ? gasm_->Call(GetBigIntToI64CallDescriptor(true), target,
                                     input, context, frame_state)
                       : gasm_->Call(GetBigIntToI64CallDescriptor(false),
                                     target, input, context);
  }

  Node* BuildCheckString(Node* input, Node* js_context,
                         wasm::CanonicalValueType type) {
    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);
    auto type_error = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(IsSmi(input), &type_error, BranchHint::kFalse);
    if (type.is_nullable()) {
      auto not_null = gasm_->MakeLabel();
      gasm_->GotoIfNot(IsNull(input, wasm::kCanonicalExternRef), &not_null);
      gasm_->Goto(&done, LOAD_ROOT(WasmNull, wasm_null));
      gasm_->Bind(&not_null);
    }
    Node* map = gasm_->LoadMap(input);
    Node* instance_type = gasm_->LoadInstanceType(map);
    Node* check = gasm_->Uint32LessThan(
        instance_type, gasm_->Uint32Constant(FIRST_NONSTRING_TYPE));
    gasm_->GotoIf(check, &done, BranchHint::kTrue, input);
    gasm_->Goto(&type_error);
    gasm_->Bind(&type_error);
    BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError, js_context,
                                  nullptr, 0);
    TerminateThrow(effect(), control());
    gasm_->Bind(&done);
    return done.PhiAt(0);
  }

  Node* FromJS(Node* input, Node* js_context, wasm::CanonicalValueType type,
               Node* frame_state = nullptr) {
    switch (type.kind()) {
      case wasm::kRef:
      case wasm::kRefNull: {
        switch (type.heap_representation_non_shared()) {
          // TODO(14034): Add more fast paths?
          case wasm::HeapType::kExtern:
          case wasm::HeapType::kExn:
            if (type.kind() == wasm::kRef) {
              Node* null_value = gasm_->LoadImmutable(
                  MachineType::Pointer(), gasm_->LoadRootRegister(),
                  IsolateData::root_slot_offset(RootIndex::kNullValue));
              auto throw_label = gasm_->MakeDeferredLabel();
              auto done = gasm_->MakeLabel();
              gasm_->GotoIf(gasm_->TaggedEqual(input, null_value),
                            &throw_label);
              gasm_->Goto(&done);

              gasm_->Bind(&throw_label);
              BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError,
                                            js_context, {}, 0);
              gasm_->Unreachable();

              gasm_->Bind(&done);
            }
            return input;
          case wasm::HeapType::kString:
            return BuildCheckString(input, js_context, type);
          case wasm::HeapType::kNoExtern:
          case wasm::HeapType::kNoExn:
          case wasm::HeapType::kNone:
          case wasm::HeapType::kNoFunc:
          case wasm::HeapType::kI31:
          case wasm::HeapType::kAny:
          case wasm::HeapType::kFunc:
          case wasm::HeapType::kStruct:
          case wasm::HeapType::kArray:
          case wasm::HeapType::kEq:
          default: {
            // Make sure CanonicalValueType fits in a Smi.
            static_assert(wasm::CanonicalValueType::kLastUsedBit + 1 <=
                          kSmiValueSize);

            Node* inputs[] = {
                input, mcgraph()->IntPtrConstant(
                           IntToSmi(static_cast<int>(type.raw_bit_field())))};

            return BuildCallToRuntimeWithContext(Runtime::kWasmJSToWasmObject,
                                                 js_context, inputs, 2);
          }
        }
      }
      case wasm::kF32:
        return gasm_->TruncateFloat64ToFloat32(
            BuildChangeTaggedToFloat64(input, js_context, frame_state));

      case wasm::kF64:
        return BuildChangeTaggedToFloat64(input, js_context, frame_state);

      case wasm::kI32:
        return BuildChangeTaggedToInt32(input, js_context, frame_state);

      case wasm::kI64:
        // i64 values can only come from BigInt.
        return BuildChangeBigIntToInt64(input, js_context, frame_state);

      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  Node* SmiToFloat32(Node* input) {
    return gasm_->RoundInt32ToFloat32(gasm_->BuildChangeSmiToInt32(input));
  }

  Node* SmiToFloat64(Node* input) {
    return gasm_->ChangeInt32ToFloat64(gasm_->BuildChangeSmiToInt32(input));
  }

  Node* HeapNumberToFloat64(Node* input) {
    return gasm_->LoadFromObject(
        MachineType::Float64(), input,
        wasm::ObjectAccess::ToTagged(
            AccessBuilder::ForHeapNumberValue().offset));
  }

  Node* FromJSFast(Node* input, wasm::CanonicalValueType type) {
    switch (type.kind()) {
      case wasm::kI32:
        return gasm_->BuildChangeSmiToInt32(input);
      case wasm::kF32: {
        auto done = gasm_->MakeLabel(MachineRepresentation::kFloat32);
        auto heap_number = gasm_->MakeLabel();
        gasm_->GotoIfNot(IsSmi(input), &heap_number);
        gasm_->Goto(&done, SmiToFloat32(input));
        gasm_->Bind(&heap_number);
        Node* value =
            gasm_->TruncateFloat64ToFloat32(HeapNumberToFloat64(input));
        gasm_->Goto(&done, value);
        gasm_->Bind(&done);
        return done.PhiAt(0);
      }
      case wasm::kF64: {
        auto done = gasm_->MakeLabel(MachineRepresentation::kFloat64);
        auto heap_number = gasm_->MakeLabel();
        gasm_->GotoIfNot(IsSmi(input), &heap_number);
        gasm_->Goto(&done, SmiToFloat64(input));
        gasm_->Bind(&heap_number);
        gasm_->Goto(&done, HeapNumberToFloat64(input));
        gasm_->Bind(&done);
        return done.PhiAt(0);
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kI64:
      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        UNREACHABLE();
    }
  }

  class ModifyThreadInWasmFlagScope {
   public:
    ModifyThreadInWasmFlagScope(
        WasmWrapperGraphBuilder* wasm_wrapper_graph_builder,
        WasmGraphAssembler* gasm)
        : wasm_wrapper_graph_builder_(wasm_wrapper_graph_builder) {
      if (!trap_handler::IsTrapHandlerEnabled()) return;
      Node* isolate_root = wasm_wrapper_graph_builder_->BuildLoadIsolateRoot();

      thread_in_wasm_flag_address_ =
          gasm->Load(MachineType::Pointer(), isolate_root,
                     Isolate::thread_in_wasm_flag_address_offset());

      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          thread_in_wasm_flag_address_, true);
    }

    ModifyThreadInWasmFlagScope(const ModifyThreadInWasmFlagScope&) = delete;

    ~ModifyThreadInWasmFlagScope() {
      if (!trap_handler::IsTrapHandlerEnabled()) return;

      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          thread_in_wasm_flag_address_, false);
    }

   private:
    WasmWrapperGraphBuilder* wasm_wrapper_graph_builder_;
    Node* thread_in_wasm_flag_address_;
  };

  Node* BuildMultiReturnFixedArrayFromIterable(const wasm::CanonicalSig* sig,
                                               Node* iterable, Node* context) {
    Node* length = gasm_->BuildChangeUint31ToSmi(
        mcgraph()->Uint32Constant(static_cast<uint32_t>(sig->return_count())));
    return gasm_->CallBuiltin(Builtin::kIterableToFixedArrayForWasm,
                              Operator::kEliminatable, iterable, length,
                              context);
  }

  // Generate a call to the AllocateJSArray builtin.
  Node* BuildCallAllocateJSArray(Node* array_length, Node* context) {
    // Since we don't check that args will fit in an array,
    // we make sure this is true based on statically known limits.
    static_assert(wasm::kV8MaxWasmFunctionReturns <=
                  JSArray::kInitialMaxFastElementArray);
    return gasm_->CallBuiltin(Builtin::kWasmAllocateJSArray,
                              Operator::kEliminatable, array_length, context);
  }

  Node* BuildCallAndReturn(Node* js_context, Node* function_data,
                           base::SmallVector<Node*, 16> args,
                           bool do_conversion, Node* frame_state,
                           bool set_in_wasm_flag) {
    const int rets_count = static_cast<int>(wrapper_sig_->return_count());
    base::SmallVector<Node*, 1> rets(rets_count);

    // Set the ThreadInWasm flag before we do the actual call.
    {
      std::optional<ModifyThreadInWasmFlagScope>
          modify_thread_in_wasm_flag_builder;
      if (set_in_wasm_flag) {
        modify_thread_in_wasm_flag_builder.emplace(this, gasm_.get());
      }

      // Call to an import or a wasm function defined in this module.
      // The (cached) call target is the jump table slot for that function.
      // We do not use the imports dispatch table here so that the wrapper is
      // target independent, in particular for tier-up.
      Node* internal = gasm_->LoadImmutableProtectedPointerFromObject(
          function_data, wasm::ObjectAccess::ToTagged(
                             WasmFunctionData::kProtectedInternalOffset));
      args[0] =
          gasm_->LoadFromObject(MachineType::WasmCodePointer(), internal,
                                wasm::ObjectAccess::ToTagged(
                                    WasmInternalFunction::kCallTargetOffset));
      Node* implicit_arg = gasm_->LoadImmutableProtectedPointerFromObject(
          internal, wasm::ObjectAccess::ToTagged(
                        WasmInternalFunction::kProtectedImplicitArgOffset));
      BuildWasmCall(wrapper_sig_, base::VectorOf(args), base::VectorOf(rets),
                    wasm::kNoCodePosition, implicit_arg, frame_state);
    }

    Node* jsval;
    if (wrapper_sig_->return_count() == 0) {
      jsval = UndefinedValue();
    } else if (wrapper_sig_->return_count() == 1) {
      jsval = !do_conversion
                  ? rets[0]
                  : ToJS(rets[0], wrapper_sig_->GetReturn(), js_context);
    } else {
      int32_t return_count = static_cast<int32_t>(wrapper_sig_->return_count());
      Node* size = gasm_->NumberConstant(return_count);

      jsval = BuildCallAllocateJSArray(size, js_context);

      Node* fixed_array = gasm_->LoadJSArrayElements(jsval);

      for (int i = 0; i < return_count; ++i) {
        Node* value = ToJS(rets[i], wrapper_sig_->GetReturn(i), js_context);
        gasm_->StoreFixedArrayElementAny(fixed_array, i, value);
      }
    }
    return jsval;
  }

  bool QualifiesForFastTransform(const wasm::CanonicalSig* sig) {
    const int wasm_count = static_cast<int>(sig->parameter_count());
    for (int i = 0; i < wasm_count; ++i) {
      wasm::CanonicalValueType type = sig->GetParam(i);
      switch (type.kind()) {
        case wasm::kRef:
        case wasm::kRefNull:
        case wasm::kI64:
        case wasm::kRtt:
        case wasm::kS128:
        case wasm::kI8:
        case wasm::kI16:
        case wasm::kF16:
        case wasm::kTop:
        case wasm::kBottom:
        case wasm::kVoid:
          return false;
        case wasm::kI32:
        case wasm::kF32:
        case wasm::kF64:
          break;
      }
    }
    return true;
  }

  Node* IsSmi(Node* input) {
    return gasm_->Word32Equal(
        gasm_->Word32And(gasm_->BuildTruncateIntPtrToInt32(input),
                         Int32Constant(kSmiTagMask)),
        Int32Constant(kSmiTag));
  }

  void CanTransformFast(
      Node* input, wasm::CanonicalValueType type,
      v8::internal::compiler::GraphAssemblerLabel<0>* slow_path) {
    switch (type.kind()) {
      case wasm::kI32: {
        gasm_->GotoIfNot(IsSmi(input), slow_path);
        return;
      }
      case wasm::kF32:
      case wasm::kF64: {
        auto done = gasm_->MakeLabel();
        gasm_->GotoIf(IsSmi(input), &done);
        Node* map = gasm_->LoadMap(input);
        Node* heap_number_map = LOAD_ROOT(HeapNumberMap, heap_number_map);
#if V8_MAP_PACKING
        Node* is_heap_number = gasm_->WordEqual(heap_number_map, map);
#else
        Node* is_heap_number = gasm_->TaggedEqual(heap_number_map, map);
#endif
        gasm_->GotoIf(is_heap_number, &done);
        gasm_->Goto(slow_path);
        gasm_->Bind(&done);
        return;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kI64:
      case wasm::kRtt:
      case wasm::kS128:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kVoid:
        UNREACHABLE();
    }
  }

  void BuildJSToWasmWrapper(bool do_conversion = true,
                            Node* frame_state = nullptr,
                            bool set_in_wasm_flag = true) {
    const int wasm_param_count =
        static_cast<int>(wrapper_sig_->parameter_count());

    // Build the start and the JS parameter nodes.
    // TODO(saelo): this should probably be a constant with a descriptive name.
    // As far as I understand, it's the number of additional parameters in the
    // JS calling convention. Also there should be a static_assert here that it
    // matches the number of parameters in the JSTrampolineDescriptor?
    // static_assert
    Start(wasm_param_count + 6);

    // Create the js_closure and js_context parameters.
    Node* js_closure = Param(Linkage::kJSCallClosureParamIndex, "%closure");
    Node* js_context = Param(
        Linkage::GetJSCallContextParamIndex(wasm_param_count + 1), "%context");
    Node* function_data = gasm_->LoadFunctionDataFromJSFunction(js_closure);

    if (!wasm::IsJSCompatibleSignature(wrapper_sig_)) {
      // Throw a TypeError. Use the js_context of the calling javascript
      // function (passed as a parameter), such that the generated code is
      // js_context independent.
      BuildCallToRuntimeWithContext(Runtime::kWasmThrowJSTypeError, js_context,
                                    nullptr, 0);
      TerminateThrow(effect(), control());
      return;
    }

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceBeginExecution, js_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    const int args_count = wasm_param_count + 1;  // +1 for wasm_code.

    // Check whether the signature of the function allows for a fast
    // transformation (if any params exist that need transformation).
    // Create a fast transformation path, only if it does.
    bool include_fast_path = do_conversion && wasm_param_count > 0 &&
                             QualifiesForFastTransform(wrapper_sig_);

    // Prepare Param() nodes. Param() nodes can only be created once,
    // so we need to use the same nodes along all possible transformation paths.
    base::SmallVector<Node*, 16> params(args_count);
    for (int i = 0; i < wasm_param_count; ++i) params[i + 1] = Param(i + 1);

    auto done = gasm_->MakeLabel(MachineRepresentation::kTagged);
    if (include_fast_path) {
      auto slow_path = gasm_->MakeDeferredLabel();
      // Check if the params received on runtime can be actually transformed
      // using the fast transformation. When a param that cannot be transformed
      // fast is encountered, skip checking the rest and fall back to the slow
      // path.
      for (int i = 0; i < wasm_param_count; ++i) {
        CanTransformFast(params[i + 1], wrapper_sig_->GetParam(i), &slow_path);
      }
      // Convert JS parameters to wasm numbers using the fast transformation
      // and build the call.
      base::SmallVector<Node*, 16> args(args_count);
      for (int i = 0; i < wasm_param_count; ++i) {
        Node* wasm_param = FromJSFast(params[i + 1], wrapper_sig_->GetParam(i));
        args[i + 1] = wasm_param;
      }
      Node* jsval =
          BuildCallAndReturn(js_context, function_data, args, do_conversion,
                             frame_state, set_in_wasm_flag);

#if V8_ENABLE_DRUMBRAKE
      if (v8_flags.wasm_enable_exec_time_histograms &&
          v8_flags.slow_histograms && !v8_flags.wasm_jitless) {
        Node* runtime_call = BuildCallToRuntimeWithContext(
            Runtime::kWasmTraceEndExecution, js_context, nullptr, 0);
        SetControl(runtime_call);
      }
#endif  // V8_ENABLE_DRUMBRAKE

      gasm_->Goto(&done, jsval);
      gasm_->Bind(&slow_path);
    }
    // Convert JS parameters to wasm numbers using the default transformation
    // and build the call.
    base::SmallVector<Node*, 16> args(args_count);
    for (int i = 0; i < wasm_param_count; ++i) {
      if (do_conversion) {
        args[i + 1] = FromJS(params[i + 1], js_context,
                             wrapper_sig_->GetParam(i), frame_state);
      } else {
        Node* wasm_param = params[i + 1];

        // For Float32 parameters
        // we set UseInfo::CheckedNumberOrOddballAsFloat64 in
        // simplified-lowering and we need to add here a conversion from Float64
        // to Float32.
        if (wrapper_sig_->GetParam(i).kind() == wasm::kF32) {
          wasm_param = gasm_->TruncateFloat64ToFloat32(wasm_param);
        }

        args[i + 1] = wasm_param;
      }
    }

    Node* jsval =
        BuildCallAndReturn(js_context, function_data, args, do_conversion,
                           frame_state, set_in_wasm_flag);

#if V8_ENABLE_DRUMBRAKE
    if (v8_flags.wasm_enable_exec_time_histograms && v8_flags.slow_histograms &&
        !v8_flags.wasm_jitless) {
      Node* runtime_call = BuildCallToRuntimeWithContext(
          Runtime::kWasmTraceEndExecution, js_context, nullptr, 0);
      SetControl(runtime_call);
    }
#endif  // V8_ENABLE_DRUMBRAKE

    // If both the default and a fast transformation paths are present,
    // get the return value based on the path used.
    if (include_fast_path) {
      gasm_->Goto(&done, jsval);
      gasm_->Bind(&done);
      Return(done.PhiAt(0));
    } else {
      Return(jsval);
    }
    if (ContainsInt64(wrapper_sig_)) LowerInt64(wasm::kCalledFromJS);
  }

  Node* BuildReceiverNode(Node* callable_node, Node* native_context,
                          Node* undefined_node) {
    // Check function strict bit.
    Node* shared_function_info = gasm_->LoadSharedFunctionInfo(callable_node);
    Node* flags = gasm_->LoadFromObject(
        MachineType::Int32(), shared_function_info,
        wasm::ObjectAccess::FlagsOffsetInSharedFunctionInfo());
    Node* strict_check =
        Binop(wasm::kExprI32And, flags,
              Int32Constant(SharedFunctionInfo::IsNativeBit::kMask |
                            SharedFunctionInfo::IsStrictBit::kMask));

    // Load global receiver if sloppy else use undefined.
    Diamond strict_d(graph(), mcgraph()->common(), strict_check,
                     BranchHint::kNone);
    Node* old_effect = effect();
    SetControl(strict_d.if_false);
    Node* global_proxy = gasm_->LoadFixedArrayElementPtr(
        native_context, Context::GLOBAL_PROXY_INDEX);
    SetEffectControl(strict_d.EffectPhi(old_effect, global_proxy),
                     strict_d.merge);
    return strict_d.Phi(MachineRepresentation::kTagged, undefined_node,
                        global_proxy);
  }

  Node* BuildSuspend(Node* value, Node* import_data, Node** old_sp) {
    Node* native_context = gasm_->Load(
        MachineType::TaggedPointer(), import_data,
        wasm::ObjectAccess::ToTagged(WasmImportData::kNativeContextOffset));
    // If value is a promise, suspend to the js-to-wasm prompt, and resume later
    // with the promise's resolved value.
    auto resume = gasm_->MakeLabel(MachineRepresentation::kTagged,
                                   MachineType::UintPtr().representation());
    gasm_->GotoIf(IsSmi(value), &resume, value, *old_sp);
    gasm_->GotoIfNot(gasm_->HasInstanceType(value, JS_PROMISE_TYPE), &resume,
                     BranchHint::kTrue, value, *old_sp);

    // Trap if the suspender is undefined, which occurs when the export was
    // not wrapped with WebAssembly.promising.
    Node* suspender = LOAD_MUTABLE_ROOT(ActiveSuspender, active_suspender);
    auto bad_suspender = gasm_->MakeDeferredLabel();
    gasm_->GotoIf(gasm_->TaggedEqual(suspender, UndefinedValue()),
                  &bad_suspender, BranchHint::kFalse);

    if (v8_flags.stress_wasm_stack_switching) {
      Node* undefined = LOAD_ROOT(UndefinedValue, undefined_value);
      Node* for_stress_testing = gasm_->TaggedEqual(
          gasm_->Load(
              MachineType::TaggedPointer(), suspender,
              wasm::ObjectAccess::ToTagged(WasmSuspenderObject::kResumeOffset)),
          undefined);
      gasm_->GotoIf(for_stress_testing, &bad_suspender);
    }

    auto* call_descriptor = GetBuiltinCallDescriptor(
        Builtin::kWasmSuspend, zone_, StubCallMode::kCallBuiltinPointer);
    Node* call_target = GetTargetForBuiltinCall(Builtin::kWasmSuspend);
    // If {old_sp} is null, it must be that we were on the central stack before
    // entering the wasm-to-js wrapper, which means that there are JS frames in
    // the current suspender. JS frames cannot be suspended, so trap.
    Node* has_js_frames = gasm_->IntPtrEqual(gasm_->IntPtrConstant(0), *old_sp);
    auto suspend = gasm_->MakeLabel();
    gasm_->GotoIfNot(has_js_frames, &suspend);
    // {ThrowWasmError} expects to be called from wasm code, so set the
    // thread-in-wasm flag now.
    // Usually we set this flag later so that it stays off while we convert the
    // return values. This is a special case, it is safe to set it now because
    // the error will unwind this frame.
    BuildModifyThreadInWasmFlag(true);
    Node* error = gasm_->SmiConstant(
        Smi::FromInt(
            static_cast<int32_t>(Messag
"""


```