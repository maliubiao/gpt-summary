Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes through these stages:

1. **Understanding the Request:**  The user wants a summary of the functionality of the given C++ code from `v8/src/codegen/code-stub-assembler.cc`. They also have specific requests related to `.tq` files, JavaScript connections, logical reasoning, common errors, and finally, a summary of the *current* (part 9 of 23) section's functionality.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the code looking for recognizable V8 API calls and common programming patterns related to data conversion and type checking. Keywords like `TruncateFloat64ToFloat16RawBits`, `Bitcast`, `ChangeFloat32ToTagged`, `ThrowTypeError`, `LoadMap`, `IsSmi`, etc., immediately stand out. These provide clues about the code's purpose.

3. **Focusing on Functionalities:** I start grouping related code blocks. For example, the functions dealing with `Float16RawBitsT` are clearly related to 16-bit floating-point conversions. The functions starting with `Change...To...` suggest type conversions between different V8 value representations (Smi, HeapNumber, Float64, etc.). The `Throw...` functions indicate error handling. Functions like `ToThisString` and `ToThisValue` point towards object coercion and type checking related to method calls.

4. **Inferring High-Level Purpose:**  Based on the identified functionalities, I can infer that this code is part of the `CodeStubAssembler` and is responsible for low-level operations related to:
    * **Floating-point conversions:**  Specifically, converting between different floating-point precisions (64-bit to 16-bit).
    * **Type conversions:** Converting between tagged values (Smi, HeapObject), and primitive types (integers, floats, booleans). This is crucial for the interaction between JavaScript and the V8 engine.
    * **Type checking and coercion:** Enforcing type constraints and converting values to the expected types before performing operations (e.g., in method calls).
    * **Error handling:**  Throwing specific JavaScript errors (TypeError, RangeError) when type constraints are violated or operations fail.
    * **Protector Cells:**  Checking the validity of protector cells, which are used for optimization and deoptimization in V8.
    * **Map checks:**  Verifying the properties of object maps (e.g., whether a map is a dictionary map, extensible, callable).

5. **Addressing Specific User Requests:**

    * **`.tq` files:** The code snippet is C++, not a `.tq` file, so I address this directly.
    * **JavaScript relationship:**  I look for conversion functions that bridge the gap between JavaScript values and internal V8 representations. The `Change...ToTagged` functions are prime examples. I then construct JavaScript examples that would trigger these conversions (e.g., adding a large integer that exceeds Smi limits).
    * **Logical reasoning:** The `TruncateFloat64ToFloat16RawBits` function has complex logic for handling different floating-point cases (infinity, NaN, denormals). I analyze the branching logic and provide hypothetical input/output examples to illustrate the different paths.
    * **Common errors:**  The `ThrowTypeError` functions are directly linked to common JavaScript errors. I give examples like calling array methods on non-array objects, which would lead to such errors.

6. **Focusing on Part 9:** I re-read the code snippet, specifically noting the functions and logic within this section. It predominantly deals with:
    * More type conversions (boolean to int32, number to float64).
    * The `ToThisString` function, highlighting its role in ensuring a string context for string methods.
    * Handling of non-negative numbers to unsigned 32-bit integers.
    * The `ChangeTaggedNonSmiToInt32` and `ChangeTaggedToFloat64` functions, demonstrating conversions from tagged values to primitive numeric types, including handling of non-number objects.
    * Utility functions for scaling values by pointer/tagged/double size.
    * The `ToThisValue` function, responsible for unboxing primitive wrapper objects and enforcing type constraints for generic methods.
    * Functions for throwing TypeErrors based on instance type and callability.
    * Functions for throwing RangeErrors and general TypeErrors.
    * Functions for terminating execution and managing pending messages.
    * Functions for accessing and modifying continuation embedder data.
    * Functions for checking map properties (dictionary, extensible, callable, deprecated, undetectable).
    * Functions for checking the validity of various protector cells.
    * Functions related to prototype chains of Array and TypedArray.
    * Functions for invalidating the String wrapper to primitive protector.
    * Functions for identifying different types of arguments maps.

7. **Structuring the Answer:** I organize the information logically, starting with a general overview of the file's purpose and then addressing each of the user's specific requests. I use clear headings and bullet points to make the information easy to read and understand. I ensure that the JavaScript examples are concise and illustrative. For logical reasoning, I present clear input and expected output. For common errors, I provide simple, relatable examples.

8. **Review and Refinement:** I reread my answer to ensure accuracy, clarity, and completeness, making any necessary edits or additions. I double-check that I've addressed all aspects of the user's request.
好的，让我们来分析一下 `v8/src/codegen/code-stub-assembler.cc` 的这段代码。

**功能归纳:**

这段代码是 `v8::internal::CodeStubAssembler` 类的一部分，主要负责提供一系列底层的、与类型转换、错误处理和对象属性相关的汇编操作的抽象。它为生成高效的机器码提供便利，特别是针对 V8 引擎的内置函数和优化的代码路径。

具体来说，这段代码片段实现了以下功能：

1. **浮点数类型转换:**
   - `TruncateFloat64ToFloat16RawBits`:  将 64 位浮点数（`Float64T`）截断转换为 16 位浮点数的原始位表示（`Float16RawBitsT`）。它考虑了硬件是否原生支持该操作，并提供了回退的软件实现。
   - `BitcastFloat16ToUint32` 和 `BitcastUint32ToFloat16`:  在 `Float16RawBitsT` 和 `Uint32T` 之间进行位级别的转换。
   - `RoundInt32ToFloat16`: 将 32 位整数转换为 16 位浮点数。
   - `ChangeFloat16ToFloat64`: 将 16 位浮点数转换为 64 位浮点数。

2. **数值类型到 Tagged 值的转换:**
   - `ChangeFloat32ToTagged`: 将 32 位浮点数（`Float32T`）转换为 V8 的 Tagged 值（`Number`），优先尝试转换为 Smi，否则分配 HeapNumber。
   - `ChangeFloat64ToTagged`: 将 64 位浮点数转换为 Tagged 值，同样优先尝试 Smi。
   - `ChangeInt32ToTagged`: 将 32 位有符号整数转换为 Tagged 值，会处理溢出情况，溢出时会分配 HeapNumber。
   - `ChangeInt32ToTaggedNoOverflow`:  将 32 位有符号整数转换为 Tagged 值，假设不会溢出。
   - `ChangeUint32ToTagged`: 将 32 位无符号整数转换为 Tagged 值，会处理超出 Smi 范围的情况。
   - `ChangeUintPtrToTagged`: 将平台相关的无符号指针转换为 Tagged 值，处理超出 Smi 范围的情况。

3. **其他类型转换:**
   - `ChangeBoolToInt32`: 将布尔值转换为 32 位整数（true 为 1，false 为 0）。
   - `ToThisString`: 确保一个值可以安全地用作字符串操作的 `this` 值，如果需要会进行类型转换（例如，将数字转换为字符串）。
   - `ChangeNonNegativeNumberToUint32`: 将非负数（Smi 或 HeapNumber）转换为 32 位无符号整数。
   - `ChangeNumberToFloat64`: 将 Number 类型转换为 64 位浮点数。
   - `ChangeTaggedNonSmiToInt32`: 将非 Smi 的 Tagged 值转换为 32 位整数。
   - `ChangeTaggedToFloat64`: 将 Tagged 值转换为 64 位浮点数。

4. **内存大小计算:**
   - `TimesSystemPointerSize`:  将一个值乘以系统指针的大小。
   - `TimesTaggedSize`: 将一个值乘以 Tagged 值的大小。
   - `TimesDoubleSize`: 将一个值乘以 double 类型的大小。

5. **对象类型检查和转换:**
   - `ToThisValue`:  用于将一个值转换为特定的原始类型（Boolean, Number, String, Symbol），如果不是该类型或其包装对象，则抛出 `TypeError`。
   - `ThrowIfNotInstanceType`: 如果一个对象不是指定的实例类型，则抛出 `TypeError`。
   - `ThrowIfNotJSReceiver`: 如果一个值不是 JS 接收器（非原始值），则抛出 `TypeError`。
   - `ThrowIfNotCallable`: 如果一个值不可调用，则抛出 `TypeError`。

6. **错误处理:**
   - `ThrowRangeError`: 抛出 `RangeError`。
   - `ThrowTypeError`: 抛出 `TypeError`。
   - `TerminateExecution`: 终止脚本执行。
   - `GetPendingMessage` 和 `SetPendingMessage`: 获取和设置待处理的错误消息。
   - `IsExecutionTerminating`: 检查执行是否正在终止。

7. **访问隔离区数据:**
   - `GetContinuationPreservedEmbedderData` 和 `SetContinuationPreservedEmbedderData`: 获取和设置与 continuation 相关的嵌入器数据。

8. **Map 属性检查:**
   - 提供了一系列函数来检查 `Map` 对象的属性，例如是否是字典模式、是否可扩展、是否可调用、是否已弃用、是否不可检测等。

9. **保护器单元检查:**
   - 提供了一系列函数来检查各种保护器单元的状态，这些保护器用于 V8 的优化机制，当某些假设不再成立时会被失效。

10. **原型链检查:**
    - `IsPrototypeInitialArrayPrototype`: 检查给定 Map 的原型是否是初始的 Array 原型。
    - `IsPrototypeTypedArrayPrototype`: 检查给定 Map 的原型链是否包含 TypedArray 原型。

11. **其他:**
    - `InvalidateStringWrapperToPrimitiveProtector`: 失效字符串包装器到原始值转换的保护器。
    - 检查不同类型的 arguments 对象的 Map。

**关于 `.tq` 结尾的文件:**

如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言（DSL），用于生成高效的 C++ 代码，通常用于实现内置函数。这段代码是 `.cc` 文件，意味着它是直接用 C++ 编写的。

**与 JavaScript 功能的关系和示例:**

这段 C++ 代码直接支持着许多 JavaScript 的核心功能。例如：

- **类型转换:** JavaScript 是一门动态类型语言，经常需要在不同类型之间进行转换。例如，当你将一个数字与一个字符串相加时，JavaScript 会将数字转换为字符串。这段代码中的 `ChangeNumberToString`, `ChangeInt32ToTagged`, `ChangeFloat64ToTagged` 等函数就参与了这些底层的转换过程。

  ```javascript
  // JavaScript 示例：隐式类型转换
  let num = 10;
  let str = "20";
  let result = num + str; // JavaScript 会将数字 10 转换为字符串 "10"
  console.log(result); // 输出 "1020"
  ```

- **错误处理:** 当 JavaScript 代码执行出错时，会抛出各种类型的错误，如 `TypeError` 和 `RangeError`。这段代码中的 `ThrowTypeError` 和 `ThrowRangeError` 函数就用于在 V8 内部抛出这些错误，这些错误会被 JavaScript 捕获并处理。

  ```javascript
  // JavaScript 示例：抛出 TypeError
  function toUpperCase(str) {
    if (typeof str !== 'string') {
      throw new TypeError('Expected a string');
    }
    return str.toUpperCase();
  }

  try {
    toUpperCase(123); // 这会抛出一个 TypeError
  } catch (e) {
    console.error(e.message); // 输出 "Expected a string"
  }
  ```

- **方法调用和 `this` 值:** 当你在 JavaScript 中调用一个对象的方法时，`this` 关键字会指向该对象。`ToThisString` 和 `ToThisValue` 这样的函数确保 `this` 值在方法调用中是合法的，并进行必要的类型转换或抛出错误。

  ```javascript
  // JavaScript 示例：确保 this 是字符串
  let obj = {
    value: 10,
    toString() {
      // 在 toString 方法内部，this 指向 obj
      return "The value is: " + this.value;
    }
  };
  console.log(obj.toString());

  String.prototype.myMethod = function() {
    // 在 String 原型方法内部，this 指向调用该方法的字符串
    return "You called myMethod on: " + this;
  };
  console.log("hello".myMethod());
  ```

**代码逻辑推理的假设输入与输出:**

以 `TruncateFloat64ToFloat16RawBits` 函数为例：

**假设输入:** 一个 `Float64T` 类型的节点，其值为 JavaScript 中的 `65504.0` (接近 Float16 的最大值)。

**预期输出:** 一个 `Float16RawBitsT` 类型的节点，其对应的 16 位浮点数原始位表示是 `0x7bff`。

**详细推理:**

1. **检查硬件支持:** 代码首先检查当前架构是否支持原生的 float64 到 float16 的截断操作。
2. **如果支持:** 直接调用原生的截断指令。
3. **如果不支持 (回退路径):**
   - 将 `Float64T` 的值转换为 `Int64T` 以进行位操作。
   - 处理无穷大和 NaN 的情况，将 NaN 转换为 qNaN，无穷大保持不变。
   - 处理非规格化数（denormal），使用特定的 magic value 和浮点加法来对齐尾数。
   - 处理正常的浮点数，进行舍入到最近偶数的处理，并更新指数部分。
   - 最后，组合符号位和计算出的指数和尾数，得到 `Float16RawBitsT` 的原始位表示。

**用户常见的编程错误:**

这段代码涉及的底层操作与用户常见的编程错误密切相关，例如：

1. **类型不匹配:**  在 JavaScript 中调用方法时，如果对象的类型不符合方法的要求，就会抛出 `TypeError`。例如，尝试调用数组的 `push` 方法在一个普通对象上。

   ```javascript
   let obj = {};
   obj.push(1); // TypeError: obj.push is not a function
   ```
   `ThrowIfNotInstanceType` 和 `ThrowIfNotJSReceiver` 这样的函数就用于在 V8 内部检测这类错误。

2. **超出范围的数值:** 当数值超出特定类型的表示范围时，可能会导致错误。例如，尝试将一个非常大的数转换为 Smi。

   ```javascript
   let veryLargeNumber = 2**31; // 超过 Smi 的最大值
   // V8 会将其存储为 HeapNumber
   ```
   `ChangeInt32ToTagged` 和 `ChangeUint32ToTagged` 这样的函数在转换时会处理这些溢出情况。

3. **在 `null` 或 `undefined` 上调用方法:** 这是非常常见的错误，会导致 `TypeError`。

   ```javascript
   let myVar = null;
   myVar.toString(); // TypeError: Cannot read properties of null (reading 'toString')
   ```
   `ToThisString` 和 `ToThisValue` 在处理方法调用时会检查 `this` 值，防止这类错误。

**第 9 部分的功能归纳:**

总的来说，这段作为第 9 部分的代码，主要集中在 **数值类型之间的转换 (特别是浮点数和整数到 Tagged 值的转换)、类型检查、以及错误处理机制的实现**。它提供了构建 V8 引擎和实现 JavaScript 内置功能所需的底层工具。 这些函数确保了 JavaScript 运行时的类型安全性和正确的数值运算，并提供了在发生错误时抛出适当异常的能力。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共23部分，请归纳一下它的功能

"""
runcateFloat64ToFloat16RawBitsSupported()),
         &truncate_op_supported, &truncate_op_fallback);

  BIND(&truncate_op_supported);
  {
    float16_out = TruncateFloat64ToFloat16RawBits(value);
    Goto(&return_out);
  }

  // This is a verbatim CSA implementation of DoubleToFloat16.
  //
  // The 64-bit and 32-bit paths are implemented separately, but the algorithm
  // is the same in both cases. The 32-bit version requires manual pairwise
  // operations.
  BIND(&truncate_op_fallback);
  if (Is64()) {
    TVARIABLE(Uint16T, out);
    TNode<Int64T> signed_in = BitcastFloat64ToInt64(value);

    // Take the absolute value of the input.
    TNode<Word64T> sign = Word64And(signed_in, Uint64Constant(kFP64SignMask));
    TNode<Word64T> in = Word64Xor(signed_in, sign);

    Label if_infinity_or_nan(this), if_finite(this), done(this);
    Branch(Uint64GreaterThanOrEqual(in,
                                    Uint64Constant(kFP16InfinityAndNaNInfimum)),
           &if_infinity_or_nan, &if_finite);

    BIND(&if_infinity_or_nan);
    {
      // Result is infinity or NaN.
      out = Select<Uint16T>(
          Uint64GreaterThan(in, Uint64Constant(kFP64Infinity)),
          [=, this] { return Uint16Constant(kFP16qNaN); },       // NaN->qNaN
          [=, this] { return Uint16Constant(kFP16Infinity); });  // Inf->Inf
      Goto(&done);
    }

    BIND(&if_finite);
    {
      // Result is a (de)normalized number or zero.

      Label if_denormal(this), not_denormal(this);
      Branch(Uint64LessThan(in, Uint64Constant(kFP16DenormalThreshold)),
             &if_denormal, &not_denormal);

      BIND(&if_denormal);
      {
        // Result is a denormal or zero. Use the magic value and FP addition to
        // align 10 mantissa bits at the bottom of the float. Depends on FP
        // addition being round-to-nearest-even.
        TNode<Float64T> temp = Float64Add(
            BitcastInt64ToFloat64(ReinterpretCast<Int64T>(in)),
            Float64Constant(base::bit_cast<double>(kFP64To16DenormalMagic)));
        out = ReinterpretCast<Uint16T>(TruncateWord64ToWord32(
            Uint64Sub(ReinterpretCast<Uint64T>(BitcastFloat64ToInt64(temp)),
                      Uint64Constant(kFP64To16DenormalMagic))));
        Goto(&done);
      }

      BIND(&not_denormal);
      {
        // Result is not a denormal.

        // Remember if the result mantissa will be odd before rounding.
        TNode<Uint64T> mant_odd = ReinterpretCast<Uint64T>(Word64And(
            Word64Shr(in, Int64Constant(kFP64MantissaBits - kFP16MantissaBits)),
            Uint64Constant(1)));

        // Update the exponent and round to nearest even.
        //
        // Rounding to nearest even is handled in two parts. First, adding
        // kFP64To16RebiasExponentAndRound has the effect of rebiasing the
        // exponent and that if any of the lower 41 bits of the mantissa are
        // set, the 11th mantissa bit from the front becomes set. Second, adding
        // mant_odd ensures ties are rounded to even.
        TNode<Uint64T> temp1 =
            Uint64Add(ReinterpretCast<Uint64T>(in),
                      Uint64Constant(kFP64To16RebiasExponentAndRound));
        TNode<Uint64T> temp2 = Uint64Add(temp1, mant_odd);

        out = ReinterpretCast<Uint16T>(TruncateWord64ToWord32(Word64Shr(
            temp2, Int64Constant(kFP64MantissaBits - kFP16MantissaBits))));

        Goto(&done);
      }
    }

    BIND(&done);
    float16_out = ReinterpretCast<Float16RawBitsT>(
        Word32Or(TruncateWord64ToWord32(Word64Shr(sign, Int64Constant(48))),
                 out.value()));
  } else {
    TVARIABLE(Uint16T, out);
    TNode<Word32T> signed_in_hi_word = Float64ExtractHighWord32(value);
    TNode<Word32T> in_lo_word = Float64ExtractLowWord32(value);

    // Take the absolute value of the input.
    TNode<Word32T> sign = Word32And(
        signed_in_hi_word, Uint64HighWordConstantNoLowWord(kFP64SignMask));
    TNode<Word32T> in_hi_word = Word32Xor(signed_in_hi_word, sign);

    Label if_infinity_or_nan(this), if_finite(this), done(this);
    Branch(Uint32GreaterThanOrEqual(
               in_hi_word,
               Uint64HighWordConstantNoLowWord(kFP16InfinityAndNaNInfimum)),
           &if_infinity_or_nan, &if_finite);

    BIND(&if_infinity_or_nan);
    {
      // Result is infinity or NaN.
      out = Select<Uint16T>(
          Uint32GreaterThan(in_hi_word,
                            Uint64HighWordConstantNoLowWord(kFP64Infinity)),
          [=, this] { return Uint16Constant(kFP16qNaN); },       // NaN->qNaN
          [=, this] { return Uint16Constant(kFP16Infinity); });  // Inf->Inf
      Goto(&done);
    }

    BIND(&if_finite);
    {
      // Result is a (de)normalized number or zero.

      Label if_denormal(this), not_denormal(this);
      Branch(Uint32LessThan(in_hi_word, Uint64HighWordConstantNoLowWord(
                                            kFP16DenormalThreshold)),
             &if_denormal, &not_denormal);

      BIND(&if_denormal);
      {
        // Result is a denormal or zero. Use the magic value and FP addition to
        // align 10 mantissa bits at the bottom of the float. Depends on FP
        // addition being round-to-nearest-even.
        TNode<Float64T> double_in = Float64InsertHighWord32(
            Float64InsertLowWord32(Float64Constant(0), in_lo_word), in_hi_word);
        TNode<Float64T> temp = Float64Add(
            double_in,
            Float64Constant(base::bit_cast<double>(kFP64To16DenormalMagic)));
        out = ReinterpretCast<Uint16T>(Projection<0>(Int32PairSub(
            Float64ExtractLowWord32(temp), Float64ExtractHighWord32(temp),
            Uint64LowWordConstant(kFP64To16DenormalMagic),
            Uint64HighWordConstant(kFP64To16DenormalMagic))));

        Goto(&done);
      }

      BIND(&not_denormal);
      {
        // Result is not a denormal.

        // Remember if the result mantissa will be odd before rounding.
        TNode<Uint32T> mant_odd = ReinterpretCast<Uint32T>(Word32And(
            Word32Shr(in_hi_word, Int32Constant(kFP64MantissaBits -
                                                kFP16MantissaBits - 32)),
            Uint32Constant(1)));

        // Update the exponent and round to nearest even.
        //
        // Rounding to nearest even is handled in two parts. First, adding
        // kFP64To16RebiasExponentAndRound has the effect of rebiasing the
        // exponent and that if any of the lower 41 bits of the mantissa are
        // set, the 11th mantissa bit from the front becomes set. Second, adding
        // mant_odd ensures ties are rounded to even.
        TNode<PairT<Word32T, Word32T>> temp1 = Int32PairAdd(
            in_lo_word, in_hi_word,
            Uint64LowWordConstant(kFP64To16RebiasExponentAndRound),
            Uint64HighWordConstant(kFP64To16RebiasExponentAndRound));
        TNode<PairT<Word32T, Word32T>> temp2 =
            Int32PairAdd(Projection<0>(temp1), Projection<1>(temp1), mant_odd,
                         Int32Constant(0));

        out = ReinterpretCast<Uint16T>((Word32Shr(
            Projection<1>(temp2),
            Int32Constant(kFP64MantissaBits - kFP16MantissaBits - 32))));

        Goto(&done);
      }
    }

    BIND(&done);
    float16_out = ReinterpretCast<Float16RawBitsT>(
        Word32Or(Word32Shr(sign, Int32Constant(16)), out.value()));
  }
  Goto(&return_out);

  BIND(&return_out);
  return float16_out.value();
}

TNode<Uint32T> CodeStubAssembler::BitcastFloat16ToUint32(
    TNode<Float16RawBitsT> value) {
  return ReinterpretCast<Uint32T>(value);
}

TNode<Float16RawBitsT> CodeStubAssembler::BitcastUint32ToFloat16(
    TNode<Uint32T> value) {
  return ReinterpretCast<Float16RawBitsT>(value);
}

TNode<Float16RawBitsT> CodeStubAssembler::RoundInt32ToFloat16(
    TNode<Int32T> value) {
  return TruncateFloat32ToFloat16(RoundInt32ToFloat32(value));
}

TNode<Float64T> CodeStubAssembler::ChangeFloat16ToFloat64(
    TNode<Float16RawBitsT> value) {
  return ChangeFloat32ToFloat64(ChangeFloat16ToFloat32(value));
}

TNode<Number> CodeStubAssembler::ChangeFloat32ToTagged(TNode<Float32T> value) {
  Label not_smi(this), done(this);
  TVARIABLE(Number, var_result);
  var_result = TryFloat32ToSmi(value, &not_smi);
  Goto(&done);

  BIND(&not_smi);
  {
    var_result = AllocateHeapNumberWithValue(ChangeFloat32ToFloat64(value));
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::ChangeFloat64ToTagged(TNode<Float64T> value) {
  Label not_smi(this), done(this);
  TVARIABLE(Number, var_result);
  var_result = TryFloat64ToSmi(value, &not_smi);
  Goto(&done);

  BIND(&not_smi);
  {
    var_result = AllocateHeapNumberWithValue(value);
    Goto(&done);
  }
  BIND(&done);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::ChangeInt32ToTagged(TNode<Int32T> value) {
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(value));
  }
  DCHECK(SmiValuesAre31Bits());
  TVARIABLE(Number, var_result);
  TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(value, value);
  TNode<BoolT> overflow = Projection<1>(pair);
  Label if_overflow(this, Label::kDeferred), if_notoverflow(this),
      if_join(this);
  Branch(overflow, &if_overflow, &if_notoverflow);
  BIND(&if_overflow);
  {
    TNode<Float64T> value64 = ChangeInt32ToFloat64(value);
    TNode<HeapNumber> result = AllocateHeapNumberWithValue(value64);
    var_result = result;
    Goto(&if_join);
  }
  BIND(&if_notoverflow);
  {
    TNode<IntPtrT> almost_tagged_value =
        ChangeInt32ToIntPtr(Projection<0>(pair));
    TNode<Smi> result = BitcastWordToTaggedSigned(almost_tagged_value);
    var_result = result;
    Goto(&if_join);
  }
  BIND(&if_join);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::ChangeInt32ToTaggedNoOverflow(
    TNode<Int32T> value) {
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(value));
  }
  DCHECK(SmiValuesAre31Bits());
  TNode<Int32T> result_int32 = Int32Add(value, value);
  TNode<IntPtrT> almost_tagged_value = ChangeInt32ToIntPtr(result_int32);
  TNode<Smi> result = BitcastWordToTaggedSigned(almost_tagged_value);
  return result;
}

TNode<Number> CodeStubAssembler::ChangeUint32ToTagged(TNode<Uint32T> value) {
  Label if_overflow(this, Label::kDeferred), if_not_overflow(this),
      if_join(this);
  TVARIABLE(Number, var_result);
  // If {value} > 2^31 - 1, we need to store it in a HeapNumber.
  Branch(Uint32LessThan(Uint32Constant(Smi::kMaxValue), value), &if_overflow,
         &if_not_overflow);

  BIND(&if_not_overflow);
  {
    // The {value} is definitely in valid Smi range.
    var_result = SmiTag(Signed(ChangeUint32ToWord(value)));
  }
  Goto(&if_join);

  BIND(&if_overflow);
  {
    TNode<Float64T> float64_value = ChangeUint32ToFloat64(value);
    var_result = AllocateHeapNumberWithValue(float64_value);
  }
  Goto(&if_join);

  BIND(&if_join);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::ChangeUintPtrToTagged(TNode<UintPtrT> value) {
  Label if_overflow(this, Label::kDeferred), if_not_overflow(this),
      if_join(this);
  TVARIABLE(Number, var_result);
  // If {value} > 2^31 - 1, we need to store it in a HeapNumber.
  Branch(UintPtrLessThan(UintPtrConstant(Smi::kMaxValue), value), &if_overflow,
         &if_not_overflow);

  BIND(&if_not_overflow);
  {
    // The {value} is definitely in valid Smi range.
    var_result = SmiTag(Signed(value));
  }
  Goto(&if_join);

  BIND(&if_overflow);
  {
    TNode<Float64T> float64_value = ChangeUintPtrToFloat64(value);
    var_result = AllocateHeapNumberWithValue(float64_value);
  }
  Goto(&if_join);

  BIND(&if_join);
  return var_result.value();
}

TNode<Int32T> CodeStubAssembler::ChangeBoolToInt32(TNode<BoolT> b) {
  return UncheckedCast<Int32T>(b);
}

TNode<String> CodeStubAssembler::ToThisString(TNode<Context> context,
                                              TNode<Object> value,
                                              TNode<String> method_name) {
  TVARIABLE(Object, var_value, value);

  // Check if the {value} is a Smi or a HeapObject.
  Label if_valueissmi(this, Label::kDeferred), if_valueisnotsmi(this),
      if_valueisstring(this);
  Branch(TaggedIsSmi(value), &if_valueissmi, &if_valueisnotsmi);
  BIND(&if_valueisnotsmi);
  {
    // Load the instance type of the {value}.
    TNode<Uint16T> value_instance_type = LoadInstanceType(CAST(value));

    // Check if the {value} is already String.
    Label if_valueisnotstring(this, Label::kDeferred);
    Branch(IsStringInstanceType(value_instance_type), &if_valueisstring,
           &if_valueisnotstring);
    BIND(&if_valueisnotstring);
    {
      // Check if the {value} is null.
      Label if_valueisnullorundefined(this, Label::kDeferred);
      GotoIf(IsNullOrUndefined(value), &if_valueisnullorundefined);
      // Convert the {value} to a String.
      var_value = CallBuiltin(Builtin::kToString, context, value);
      Goto(&if_valueisstring);

      BIND(&if_valueisnullorundefined);
      {
        // The {value} is either null or undefined.
        ThrowTypeError(context, MessageTemplate::kCalledOnNullOrUndefined,
                       method_name);
      }
    }
  }
  BIND(&if_valueissmi);
  {
    // The {value} is a Smi, convert it to a String.
    var_value = CallBuiltin(Builtin::kNumberToString, context, value);
    Goto(&if_valueisstring);
  }
  BIND(&if_valueisstring);
  return CAST(var_value.value());
}

// This has platform-specific and ill-defined behavior for negative inputs.
TNode<Uint32T> CodeStubAssembler::ChangeNonNegativeNumberToUint32(
    TNode<Number> value) {
  TVARIABLE(Uint32T, var_result);
  Label if_smi(this), if_heapnumber(this, Label::kDeferred), done(this);
  Branch(TaggedIsSmi(value), &if_smi, &if_heapnumber);
  BIND(&if_smi);
  {
    var_result = Unsigned(SmiToInt32(CAST(value)));
    Goto(&done);
  }
  BIND(&if_heapnumber);
  {
    var_result = ChangeFloat64ToUint32(LoadHeapNumberValue(CAST(value)));
    Goto(&done);
  }
  BIND(&done);
  return var_result.value();
}

TNode<Float64T> CodeStubAssembler::ChangeNumberToFloat64(TNode<Number> value) {
  TVARIABLE(Float64T, result);
  Label smi(this);
  Label done(this, &result);
  GotoIf(TaggedIsSmi(value), &smi);
  result = LoadHeapNumberValue(CAST(value));
  Goto(&done);

  BIND(&smi);
  {
    result = SmiToFloat64(CAST(value));
    Goto(&done);
  }

  BIND(&done);
  return result.value();
}

TNode<Int32T> CodeStubAssembler::ChangeTaggedNonSmiToInt32(
    TNode<Context> context, TNode<HeapObject> input) {
  return Select<Int32T>(
      IsHeapNumber(input),
      [=, this] {
        return Signed(TruncateFloat64ToWord32(LoadHeapNumberValue(input)));
      },
      [=, this] {
        return TruncateNumberToWord32(
            CAST(CallBuiltin(Builtin::kNonNumberToNumber, context, input)));
      });
}

TNode<Float64T> CodeStubAssembler::ChangeTaggedToFloat64(TNode<Context> context,
                                                         TNode<Object> input) {
  TVARIABLE(Float64T, var_result);
  Label end(this), not_smi(this);

  GotoIfNot(TaggedIsSmi(input), &not_smi);
  var_result = SmiToFloat64(CAST(input));
  Goto(&end);

  BIND(&not_smi);
  var_result = Select<Float64T>(
      IsHeapNumber(CAST(input)),
      [=, this] { return LoadHeapNumberValue(CAST(input)); },
      [=, this] {
        return ChangeNumberToFloat64(
            CAST(CallBuiltin(Builtin::kNonNumberToNumber, context, input)));
      });
  Goto(&end);

  BIND(&end);
  return var_result.value();
}

TNode<WordT> CodeStubAssembler::TimesSystemPointerSize(TNode<WordT> value) {
  return WordShl(value, kSystemPointerSizeLog2);
}

TNode<WordT> CodeStubAssembler::TimesTaggedSize(TNode<WordT> value) {
  return WordShl(value, kTaggedSizeLog2);
}

TNode<WordT> CodeStubAssembler::TimesDoubleSize(TNode<WordT> value) {
  return WordShl(value, kDoubleSizeLog2);
}

TNode<Object> CodeStubAssembler::ToThisValue(TNode<Context> context,
                                             TNode<Object> input_value,
                                             PrimitiveType primitive_type,
                                             char const* method_name) {
  // We might need to loop once due to JSPrimitiveWrapper unboxing.
  TVARIABLE(Object, var_value, input_value);
  Label loop(this, &var_value), done_loop(this),
      done_throw(this, Label::kDeferred);
  Goto(&loop);
  BIND(&loop);
  {
    // Check if the {value} is a Smi or a HeapObject.
    GotoIf(
        TaggedIsSmi(var_value.value()),
        (primitive_type == PrimitiveType::kNumber) ? &done_loop : &done_throw);

    TNode<HeapObject> value = CAST(var_value.value());

    // Load the map of the {value}.
    TNode<Map> value_map = LoadMap(value);

    // Load the instance type of the {value}.
    TNode<Uint16T> value_instance_type = LoadMapInstanceType(value_map);

    // Check if {value} is a JSPrimitiveWrapper.
    Label if_valueiswrapper(this, Label::kDeferred), if_valueisnotwrapper(this);
    Branch(InstanceTypeEqual(value_instance_type, JS_PRIMITIVE_WRAPPER_TYPE),
           &if_valueiswrapper, &if_valueisnotwrapper);

    BIND(&if_valueiswrapper);
    {
      // Load the actual value from the {value}.
      var_value = LoadObjectField(value, JSPrimitiveWrapper::kValueOffset);
      Goto(&loop);
    }

    BIND(&if_valueisnotwrapper);
    {
      switch (primitive_type) {
        case PrimitiveType::kBoolean:
          GotoIf(TaggedEqual(value_map, BooleanMapConstant()), &done_loop);
          break;
        case PrimitiveType::kNumber:
          GotoIf(TaggedEqual(value_map, HeapNumberMapConstant()), &done_loop);
          break;
        case PrimitiveType::kString:
          GotoIf(IsStringInstanceType(value_instance_type), &done_loop);
          break;
        case PrimitiveType::kSymbol:
          GotoIf(TaggedEqual(value_map, SymbolMapConstant()), &done_loop);
          break;
      }
      Goto(&done_throw);
    }
  }

  BIND(&done_throw);
  {
    const char* primitive_name = nullptr;
    switch (primitive_type) {
      case PrimitiveType::kBoolean:
        primitive_name = "Boolean";
        break;
      case PrimitiveType::kNumber:
        primitive_name = "Number";
        break;
      case PrimitiveType::kString:
        primitive_name = "String";
        break;
      case PrimitiveType::kSymbol:
        primitive_name = "Symbol";
        break;
    }
    CHECK_NOT_NULL(primitive_name);

    // The {value} is not a compatible receiver for this method.
    ThrowTypeError(context, MessageTemplate::kNotGeneric, method_name,
                   primitive_name);
  }

  BIND(&done_loop);
  return var_value.value();
}

void CodeStubAssembler::ThrowIfNotInstanceType(TNode<Context> context,
                                               TNode<Object> value,
                                               InstanceType instance_type,
                                               char const* method_name) {
  Label out(this), throw_exception(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(value), &throw_exception);

  // Load the instance type of the {value}.
  TNode<Map> map = LoadMap(CAST(value));
  const TNode<Uint16T> value_instance_type = LoadMapInstanceType(map);

  Branch(Word32Equal(value_instance_type, Int32Constant(instance_type)), &out,
         &throw_exception);

  // The {value} is not a compatible receiver for this method.
  BIND(&throw_exception);
  ThrowTypeError(context, MessageTemplate::kIncompatibleMethodReceiver,
                 StringConstant(method_name), value);

  BIND(&out);
}

void CodeStubAssembler::ThrowIfNotJSReceiver(TNode<Context> context,
                                             TNode<Object> value,
                                             MessageTemplate msg_template,
                                             const char* method_name) {
  Label done(this), throw_exception(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(value), &throw_exception);

  Branch(JSAnyIsNotPrimitive(CAST(value)), &done, &throw_exception);

  // The {value} is not a compatible receiver for this method.
  BIND(&throw_exception);
  ThrowTypeError(context, msg_template, StringConstant(method_name), value);

  BIND(&done);
}

void CodeStubAssembler::ThrowIfNotCallable(TNode<Context> context,
                                           TNode<Object> value,
                                           const char* method_name) {
  Label out(this), throw_exception(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(value), &throw_exception);
  Branch(IsCallable(CAST(value)), &out, &throw_exception);

  // The {value} is not a compatible receiver for this method.
  BIND(&throw_exception);
  ThrowTypeError(context, MessageTemplate::kCalledNonCallable, method_name);

  BIND(&out);
}

void CodeStubAssembler::ThrowRangeError(TNode<Context> context,
                                        MessageTemplate message,
                                        std::optional<TNode<Object>> arg0,
                                        std::optional<TNode<Object>> arg1,
                                        std::optional<TNode<Object>> arg2) {
  TNode<Smi> template_index = SmiConstant(static_cast<int>(message));
  if (!arg0) {
    CallRuntime(Runtime::kThrowRangeError, context, template_index);
  } else if (!arg1) {
    CallRuntime(Runtime::kThrowRangeError, context, template_index, *arg0);
  } else if (!arg2) {
    CallRuntime(Runtime::kThrowRangeError, context, template_index, *arg0,
                *arg1);
  } else {
    CallRuntime(Runtime::kThrowRangeError, context, template_index, *arg0,
                *arg1, *arg2);
  }
  Unreachable();
}

void CodeStubAssembler::ThrowTypeError(TNode<Context> context,
                                       MessageTemplate message,
                                       char const* arg0, char const* arg1) {
  std::optional<TNode<Object>> arg0_node;
  if (arg0) arg0_node = StringConstant(arg0);
  std::optional<TNode<Object>> arg1_node;
  if (arg1) arg1_node = StringConstant(arg1);
  ThrowTypeError(context, message, arg0_node, arg1_node);
}

void CodeStubAssembler::ThrowTypeError(TNode<Context> context,
                                       MessageTemplate message,
                                       std::optional<TNode<Object>> arg0,
                                       std::optional<TNode<Object>> arg1,
                                       std::optional<TNode<Object>> arg2) {
  TNode<Smi> template_index = SmiConstant(static_cast<int>(message));
  if (!arg0) {
    CallRuntime(Runtime::kThrowTypeError, context, template_index);
  } else if (!arg1) {
    CallRuntime(Runtime::kThrowTypeError, context, template_index, *arg0);
  } else if (!arg2) {
    CallRuntime(Runtime::kThrowTypeError, context, template_index, *arg0,
                *arg1);
  } else {
    CallRuntime(Runtime::kThrowTypeError, context, template_index, *arg0, *arg1,
                *arg2);
  }
  Unreachable();
}

void CodeStubAssembler::TerminateExecution(TNode<Context> context) {
  CallRuntime(Runtime::kTerminateExecution, context);
  Unreachable();
}

TNode<HeapObject> CodeStubAssembler::GetPendingMessage() {
  TNode<ExternalReference> pending_message = ExternalConstant(
      ExternalReference::address_of_pending_message(isolate()));
  return UncheckedCast<HeapObject>(LoadFullTagged(pending_message));
}
void CodeStubAssembler::SetPendingMessage(TNode<HeapObject> message) {
  CSA_DCHECK(this, Word32Or(IsTheHole(message),
                            InstanceTypeEqual(LoadInstanceType(message),
                                              JS_MESSAGE_OBJECT_TYPE)));
  TNode<ExternalReference> pending_message = ExternalConstant(
      ExternalReference::address_of_pending_message(isolate()));
  StoreFullTaggedNoWriteBarrier(pending_message, message);
}

TNode<BoolT> CodeStubAssembler::IsExecutionTerminating() {
  TNode<HeapObject> pending_message = GetPendingMessage();
  return TaggedEqual(pending_message,
                     LoadRoot(RootIndex::kTerminationException));
}

TNode<Object> CodeStubAssembler::GetContinuationPreservedEmbedderData() {
  TNode<ExternalReference> continuation_data =
      IsolateField(IsolateFieldId::kContinuationPreservedEmbedderData);
  return LoadFullTagged(continuation_data);
}

void CodeStubAssembler::SetContinuationPreservedEmbedderData(
    TNode<Object> value) {
  TNode<ExternalReference> continuation_data =
      IsolateField(IsolateFieldId::kContinuationPreservedEmbedderData);
  StoreFullTaggedNoWriteBarrier(continuation_data, value);
}

TNode<BoolT> CodeStubAssembler::InstanceTypeEqual(TNode<Int32T> instance_type,
                                                  int type) {
  return Word32Equal(instance_type, Int32Constant(type));
}

TNode<BoolT> CodeStubAssembler::IsDictionaryMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits3::IsDictionaryMapBit>(LoadMapBitField3(map));
}

TNode<BoolT> CodeStubAssembler::IsExtensibleMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits3::IsExtensibleBit>(LoadMapBitField3(map));
}

TNode<BoolT> CodeStubAssembler::IsExtensibleNonPrototypeMap(TNode<Map> map) {
  int kMask =
      Map::Bits3::IsExtensibleBit::kMask | Map::Bits3::IsPrototypeMapBit::kMask;
  int kExpected = Map::Bits3::IsExtensibleBit::kMask;
  return Word32Equal(Word32And(LoadMapBitField3(map), Int32Constant(kMask)),
                     Int32Constant(kExpected));
}

TNode<BoolT> CodeStubAssembler::IsCallableMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::IsCallableBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsDeprecatedMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits3::IsDeprecatedBit>(LoadMapBitField3(map));
}

TNode<BoolT> CodeStubAssembler::IsUndetectableMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::IsUndetectableBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsNoElementsProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = NoElementsProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsMegaDOMProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = MegaDOMProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsArrayIteratorProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = ArrayIteratorProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsPromiseResolveProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = PromiseResolveProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsPromiseThenProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = PromiseThenProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsArraySpeciesProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = ArraySpeciesProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsIsConcatSpreadableProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = IsConcatSpreadableProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsTypedArraySpeciesProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = TypedArraySpeciesProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsRegExpSpeciesProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = RegExpSpeciesProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsPromiseSpeciesProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = PromiseSpeciesProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT>
CodeStubAssembler::IsNumberStringNotRegexpLikeProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = NumberStringNotRegexpLikeProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsSetIteratorProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = SetIteratorProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsMapIteratorProtectorCellInvalid() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = MapIteratorProtectorConstant();
  TNode<Object> cell_value = LoadObjectField(cell, PropertyCell::kValueOffset);
  return TaggedEqual(cell_value, invalid);
}

TNode<BoolT> CodeStubAssembler::IsPrototypeInitialArrayPrototype(
    TNode<Context> context, TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_array_prototype = LoadContextElement(
      native_context, Context::INITIAL_ARRAY_PROTOTYPE_INDEX);
  TNode<HeapObject> proto = LoadMapPrototype(map);
  return TaggedEqual(proto, initial_array_prototype);
}

TNode<BoolT> CodeStubAssembler::IsPrototypeTypedArrayPrototype(
    TNode<Context> context, TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> typed_array_prototype =
      LoadContextElement(native_context, Context::TYPED_ARRAY_PROTOTYPE_INDEX);
  TNode<HeapObject> proto = LoadMapPrototype(map);
  TNode<HeapObject> proto_of_proto = Select<HeapObject>(
      IsJSObject(proto), [=, this] { return LoadMapPrototype(LoadMap(proto)); },
      [=, this] { return NullConstant(); });
  return TaggedEqual(proto_of_proto, typed_array_prototype);
}

void CodeStubAssembler::InvalidateStringWrapperToPrimitiveProtector() {
  TNode<Smi> invalid = SmiConstant(Protectors::kProtectorInvalid);
  TNode<PropertyCell> cell = StringWrapperToPrimitiveProtectorConstant();
  StoreObjectField(cell, PropertyCell::kValueOffset, invalid);
}

TNode<BoolT> CodeStubAssembler::IsFastAliasedArgumentsMap(
    TNode<Context> context, TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> arguments_map = LoadContextElement(
      native_context, Context::FAST_ALIASED_ARGUMENTS_MAP_INDEX);
  return TaggedEqual(arguments_map, map);
}

TNode<BoolT> CodeStubAssembler::IsSlowAliasedArgumentsMap(
    TNode<Context> context, TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> arguments_map = LoadContextElement(
      native_context, Context::SLOW_ALIASED_ARGUMENTS_MAP_INDEX);
  return TaggedEqual(arguments_map, map);
}

TNode<BoolT> CodeStubAssembler::IsSloppyArgumentsMap(TNode<Context> context,
                                                     TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> arguments_map =
      LoadContextElement(native_context, Context::SLOPPY_ARGUMENTS_MAP_INDEX);
  return TaggedEqual(arguments_map, map);
}

TNode<BoolT> CodeStubAssembler::IsStrictArgumentsMap(TNode<Context> context,
                                                     TNode<Map> map) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> arguments_map =
      LoadContextElement(native_context, Context::
"""


```