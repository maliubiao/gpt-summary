Response: The user wants a summary of the C++ source code file `v8/src/codegen/code-stub-assembler.cc`.
Specifically, they are asking for the functionality of this part of the file (part 5 of 12) and how it relates to JavaScript. I need to identify the main functionalities implemented in this code snippet and provide a JavaScript example if applicable.

Looking at the code, it seems to focus on:
1. **Type conversions:**  Converting between different numerical representations (Float64, Float32, Float16, Int32, Uint32, Number, Tagged values).
2. **Tagged value manipulation:**  Converting to and from tagged values (Smis and HeapNumbers).
3. **String conversions:** Converting to string representations.
4. **Type checking:**  Various helper functions to check the type of JavaScript values (e.g., IsString, IsObject, IsFunction, IsArray).
5. **Error handling:**  Functions to throw type errors and range errors.
6. **Isolate state access:**  Functions to access isolate-level data like pending messages and continuation embedder data.
7. **Map and Instance Type related functions:**  Functions to check properties of Maps and Instance Types.
8. **Protector cell checks:**  Functions to check the validity of protector cells.
这个C++代码片段（`v8/src/codegen/code-stub-assembler.cc`的第5部分）主要提供了以下功能：

**核心功能：类型转换和类型检查的辅助函数**

这部分代码定义了大量的辅助函数，用于在V8的CodeStubAssembler (CSA) 中进行各种类型转换和类型检查。CSA是V8中用于生成机器码的一种高级抽象。这些辅助函数使得在生成代码时，可以方便地进行以下操作：

1. **数值类型转换:**
   - 在不同的浮点数格式之间转换 (Float64, Float32, Float16)。例如，将 `Float64` 转换为 `Float16RawBitsT`。
   - 在整数和浮点数之间转换 (Int32, Uint32, Float64, Float32)。
   - 将各种数值类型转换为 JavaScript 的 `Number` 类型 (它可以是Smi或HeapNumber)。

2. **Tagged 值处理:**
   - 将原始的整数或浮点数转换为 V8 的 tagged 指针 (`Number`)，其中包括 Smi（小整数）和 HeapNumber（堆上的数字对象）。
   - 尝试将浮点数或整数转换为 Smi，如果溢出则转换为 HeapNumber。

3. **字符串转换:**
   - 将任意 JavaScript 值转换为字符串 (`ToThisString`)。

4. **类型检查:**
   - 提供了一系列 `Is...` 函数，用于检查 JavaScript 对象的类型。例如：
     - `IsString`: 检查是否为字符串。
     - `IsObject`: 检查是否为对象。
     - `IsFunction`: 检查是否为函数。
     - `IsArray`: 检查是否为数组。
     - `IsSmi`: 检查是否为 Smi。
     - `IsHeapNumber`: 检查是否为 HeapNumber。
     - 还有许多针对特定类型的检查，例如 `IsJSArrayMap`, `IsJSObject`, `IsBigInt` 等。
   - 检查 Map 对象的属性，例如是否为字典模式 (`IsDictionaryMap`)，是否可扩展 (`IsExtensibleMap`)，是否为可调用对象 (`IsCallableMap`) 等。
   - 检查 Instance Type，这是一种更底层的类型表示。

5. **错误处理:**
   - 提供了 `ThrowTypeError` 和 `ThrowRangeError` 函数，用于在代码生成过程中抛出相应的 JavaScript 错误。

6. **Isolate 状态访问:**
   - 提供了访问 Isolate 级别状态的函数，例如 `GetPendingMessage`（获取待处理的异常消息），`IsExecutionTerminating`（检查执行是否正在终止）等。

7. **Protector Cell 检查:**
   - 提供了检查各种 protector cell 是否无效的函数。Protector cells 是 V8 用来优化某些操作的关键机制。

**与 JavaScript 的关系及 JavaScript 示例**

这些 C++ 函数是 V8 引擎内部实现 JavaScript 功能的基础。虽然我们不能直接在 JavaScript 中调用这些 C++ 函数，但它们的行为反映了 JavaScript 的类型转换和类型检查规则。

**类型转换示例:**

```javascript
// JavaScript 会根据上下文自动进行类型转换
let num = 10;
let str = "The number is " + num; // JavaScript 将数字 10 转换为字符串

// 对应于 C++ 中的 CodeStubAssembler::ToThisString 等函数

let floatNum = 3.14;
let intNum = parseInt(floatNum); // JavaScript 将浮点数转换为整数

// 对应于 C++ 中的 CodeStubAssembler::TruncateFloat64ToWord32 等函数
```

**类型检查示例:**

```javascript
let value = "hello";
console.log(typeof value === "string"); // true

let obj = {};
console.log(typeof obj === "object"); // true

function myFunction() {}
console.log(typeof myFunction === "function"); // true

let arr = [1, 2, 3];
console.log(Array.isArray(arr)); // true

// 对应于 C++ 中的 CodeStubAssembler::IsString, CodeStubAssembler::IsJSObject, CodeStubAssembler::IsCallable, CodeStubAssembler::IsJSArray 等函数
```

**错误处理示例:**

```javascript
function onlyAcceptNumbers(value) {
  if (typeof value !== 'number') {
    throw new TypeError("Expected a number"); // 抛出 TypeError
  }
  // ...
}

try {
  onlyAcceptNumbers("not a number");
} catch (e) {
  console.error(e.message); // "Expected a number"
}

// 对应于 C++ 中的 CodeStubAssembler::ThrowTypeError 等函数
```

**总结**

这段 C++ 代码是 V8 引擎实现 JavaScript 语义的关键部分，它提供了底层的类型转换、类型检查和错误处理机制。JavaScript 的许多动态特性和类型行为都依赖于这些 C++ 代码的实现。开发者虽然不能直接操作这些 C++ 函数，但理解它们的功能有助于更好地理解 JavaScript 的运行原理。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共12部分，请归纳一下它的功能

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
      LoadContextElement(native_context, Context::STRICT_ARGUMENTS_MAP_INDEX);
  return TaggedEqual(arguments_map, map);
}

TNode<BoolT> CodeStubAssembler::TaggedIsCallable(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        return IsCallableMap(LoadMap(UncheckedCast<HeapObject>(object)));
      });
}

TNode<BoolT> CodeStubAssembler::IsCallable(TNode<HeapObject> object) {
  return IsCallableMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::TaggedIsCode(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] { return IsCode(UncheckedCast<HeapObject>(object)); });
}

TNode<BoolT> CodeStubAssembler::IsCode(TNode<HeapObject> object) {
  return HasInstanceType(object, CODE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsConstructorMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::IsConstructorBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsConstructor(TNode<HeapObject> object) {
  return IsConstructorMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsFunctionWithPrototypeSlotMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::HasPrototypeSlotBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsSpecialReceiverInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(JS_GLOBAL_OBJECT_TYPE <= LAST_SPECIAL_RECEIVER_TYPE);
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_SPECIAL_RECEIVER_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsCustomElementsReceiverInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_CUSTOM_ELEMENTS_RECEIVER));
}

TNode<BoolT> CodeStubAssembler::IsStringInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(INTERNALIZED_TWO_BYTE_STRING_TYPE == FIRST_TYPE);
  return Int32LessThan(instance_type, Int32Constant(FIRST_NONSTRING_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsTemporalInstantInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_TEMPORAL_INSTANT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOneByteStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringEncodingMask)),
      Int32Constant(kOneByteStringTag));
}

TNode<BoolT> CodeStubAssembler::IsSequentialStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kSeqStringTag));
}

TNode<BoolT> CodeStubAssembler::IsSeqOneByteStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type,
                Int32Constant(kStringRepresentationAndEncodingMask)),
      Int32Constant(kSeqOneByteStringTag));
}

TNode<BoolT> CodeStubAssembler::IsConsStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kConsStringTag));
}

TNode<BoolT> CodeStubAssembler::IsIndirectStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  static_assert(kIsIndirectStringMask == 0x1);
  static_assert(kIsIndirectStringTag == 0x1);
  return UncheckedCast<BoolT>(
      Word32And(instance_type, Int32Constant(kIsIndirectStringMask)));
}

TNode<BoolT> CodeStubAssembler::IsExternalStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kExternalStringTag));
}

TNode<BoolT> CodeStubAssembler::IsUncachedExternalStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  static_assert(kUncachedExternalStringTag != 0);
  return IsSetWord32(instance_type, kUncachedExternalStringMask);
}

TNode<BoolT> CodeStubAssembler::IsJSReceiverInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  return Int32GreaterThanOrEqual(instance_type,
                                 Int32Constant(FIRST_JS_RECEIVER_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsSequentialStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  // Both sequential string maps are allocated at the start of the read only
  // heap, so we can use a single comparison to check for them.
  static_assert(
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.first == 0);
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.second);
#else
  return IsSequentialStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsExternalStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kExternalString.first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kExternalString.second);
#else
  return IsExternalStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsUncachedExternalStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kUncachedExternalString
          .first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kUncachedExternalString
          .second);
#else
  return IsUncachedExternalStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsOneByteStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  CSA_DCHECK(this, IsStringInstanceType(LoadMapInstanceType(map)));

  // These static asserts make sure that the following bit magic on the map word
  // is safe. See the definition of kStringMapEncodingMask for an explanation.
#define VALIDATE_STRING_MAP_ENCODING_BIT(instance_type, size, name, Name) \
  static_assert(                                                          \
      ((instance_type & kStringEncodingMask) == kOneByteStringTag) ==     \
      ((StaticReadOnlyRoot::k##Name##Map &                                \
        InstanceTypeChecker::kStringMapEncodingMask) ==                   \
       InstanceTypeChecker::kOneByteStringMapBit));                       \
  static_assert(                                                          \
      ((instance_type & kStringEncodingMask) == kTwoByteStringTag) ==     \
      ((StaticReadOnlyRoot::k##Name##Map &                                \
        InstanceTypeChecker::kStringMapEncodingMask) ==                   \
       InstanceTypeChecker::kTwoByteStringMapBit));
  STRING_TYPE_LIST(VALIDATE_STRING_MAP_ENCODING_BIT)
#undef VALIDATE_STRING_TYPE_RANGES

  return Word32Equal(
      Word32And(TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
                Int32Constant(InstanceTypeChecker::kStringMapEncodingMask)),
      Int32Constant(InstanceTypeChecker::kOneByteStringMapBit));
#else
  return IsOneByteStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsJSReceiverMap(TNode<Map> map) {
  return IsJSReceiverInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::JSAnyIsNotPrimitiveMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  // Assuming this is only called with primitive objects or js receivers.
  CSA_DCHECK(this, Word32Or(IsPrimitiveInstanceType(LoadMapInstanceType(map)),
                            IsJSReceiverMap(map)));
  // All primitive object's maps are allocated at the start of the read only
  // heap. Thus JS_RECEIVER's must have maps with larger (compressed) addresses.
  return Uint32GreaterThanOrEqual(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      Int32Constant(InstanceTypeChecker::kNonJsReceiverMapLimit));
#else
  return IsJSReceiverMap(map);
#endif
}

TNode<BoolT> CodeStubAssembler::IsJSReceiver(TNode<HeapObject> object) {
  return IsJSReceiverMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::JSAnyIsNotPrimitive(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  return JSAnyIsNotPrimitiveMap(LoadMap(object));
#else
  return IsJSReceiver(object);
#endif
}

TNode<BoolT> CodeStubAssembler::IsNullOrJSReceiver(TNode<HeapObject> object) {
  return UncheckedCast<BoolT>(Word32Or(IsJSReceiver(object), IsNull(object)));
}

TNode<BoolT> CodeStubAssembler::IsNullOrUndefined(TNode<Object> value) {
  // TODO(ishell): consider using Select<BoolT>() here.
  return UncheckedCast<BoolT>(Word32Or(IsUndefined(value), IsNull(value)));
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxyInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_GLOBAL_PROXY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxyMap(TNode<Map> map) {
  return IsJSGlobalProxyInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxy(TNode<HeapObject> object) {
  return IsJSGlobalProxyMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSGeneratorMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map), JS_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSObjectInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(LAST_JS_OBJECT_TYPE == LAST_TYPE);
  return Int32GreaterThanOrEqual(instance_type,
                                 Int32Constant(FIRST_JS_OBJECT_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObjectInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_API_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSObjectMap(TNode<Map> map) {
  return IsJSObjectInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObjectMap(TNode<Map> map) {
  return IsJSApiObjectInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSObject(TNode<HeapObject> object) {
  return IsJSObjectMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObject(TNode<HeapObject> object) {
  return IsJSApiObjectMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSFinalizationRegistryMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map),
                           JS_FINALIZATION_REGISTRY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFinalizationRegistry(
    TNode<HeapObject> object) {
  return IsJSFinalizationRegistryMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSPromiseMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map), JS_PROMISE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPromise(TNode<HeapObject> object) {
  return IsJSPromiseMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSProxy(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_PROXY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSStringIterator(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_STRING_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSShadowRealm(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_SHADOW_REALM_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRegExpStringIterator(
    TNode<HeapObject> object) {
  return HasInstanceType(object, JS_REG_EXP_STRING_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsMap(TNode<HeapObject> object) {
  return HasInstanceType(object, MAP_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapperInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_PRIMITIVE_WRAPPER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapper(TNode<HeapObject> object) {
  return IsJSPrimitiveWrapperMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapperMap(TNode<Map> map) {
  return IsJSPrimitiveWrapperInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSWrappedFunction(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_WRAPPED_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSArray(TNode<HeapObject> object) {
  return IsJSArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayMap(TNode<Map> map) {
  return IsJSArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayIterator(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ARRAY_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsAlwaysSharedSpaceJSObjectInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type, FIRST_ALWAYS_SHARED_SPACE_JS_OBJECT_TYPE,
                   LAST_ALWAYS_SHARED_SPACE_JS_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_SHARED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArrayMap(TNode<Map> map) {
  return IsJSSharedArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArray(TNode<HeapObject> object) {
  return IsJSSharedArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArray(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        TNode<HeapObject> heap_object = CAST(object);
        return IsJSSharedArray(heap_object);
      });
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStructInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_SHARED_STRUCT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStructMap(TNode<Map> map) {
  return IsJSSharedStructInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStruct(TNode<HeapObject> object) {
  return IsJSSharedStructMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStruct(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        TNode<HeapObject> heap_object = CAST(object);
        return IsJSSharedStruct(heap_object);
      });
}

TNode<BoolT> CodeStubAssembler::IsJSAsyncGeneratorObject(
    TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ASYNC_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFixedArray(TNode<HeapObject> object) {
  return HasInstanceType(object, FIXED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFixedArraySubclass(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(
      Word32And(Int32GreaterThanOrEqual(instance_type,
                                        Int32Constant(FIRST_FIXED_ARRAY_TYPE)),
                Int32LessThanOrEqual(instance_type,
                                     Int32Constant(LAST_FIXED_ARRAY_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsNotWeakFixedArraySubclass(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(Word32Or(
      Int32LessThan(instance_type, Int32Constant(FIRST_WEAK_FIXED_ARRAY_TYPE)),
      Int32GreaterThan(instance_type,
                       Int32Constant(LAST_WEAK_FIXED_ARRAY_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsPropertyArray(TNode<HeapObject> object) {
  return HasInstanceType(object, PROPERTY_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsPromiseReactionJobTask(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return IsInRange(instance_type, FIRST_PROMISE_REACTION_JOB_TASK_TYPE,
                   LAST_PROMISE_REACTION_JOB_TASK_TYPE);
}

// This complicated check is due to elements oddities. If a smi array is empty
// after Array.p.shift, it is replaced by the empty array constant. If it is
// later filled with a double element, we try to grow it but pass in a double
// elements kind. Usually this would cause a size mismatch (since the source
// fixed array has HOLEY_ELEMENTS and destination has
// HOLEY_DOUBLE_ELEMENTS), but we don't have to worry about it when the
// source array is empty.
// TODO(jgruber): It might we worth creating an empty_double_array constant to
// simplify this case.
TNode<BoolT> CodeStubAssembler::IsFixedArrayWithKindOrEmpty(
    TNode<FixedArrayBase> object, ElementsKind kind) {
  Label out(this);
  TVARIABLE(BoolT, var_result, Int32TrueConstant());

  GotoIf(IsFixedArrayWithKind(object, kind), &out);

  const TNode<Smi> length = LoadFixedArrayBaseLength(object);
  GotoIf(SmiEqual(length, SmiConstant(0)), &out);

  var_result = Int32FalseConstant();
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsFixedArrayWithKind(TNode<HeapObject> object,
                                                     ElementsKind kind) {
  if (IsDoubleElementsKind(kind)) {
    return IsFixedDoubleArray(object);
  } else {
    DCHECK(IsSmiOrObjectElementsKind(kind) || IsSealedElementsKind(kind) ||
           IsNonextensibleElementsKind(kind));
    return IsFixedArraySubclass(object);
  }
}

TNode<BoolT> CodeStubAssembler::IsBoolean(TNode<HeapObject> object) {
  return IsBooleanMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsPropertyCell(TNode<HeapObject> object) {
  return IsPropertyCellMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsHeapNumberInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, HEAP_NUMBER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNotAnyHole(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Word32BinaryNot(IsHoleInstanceType(
            LoadInstanceType(UncheckedCast<HeapObject>(object))));
      });
}

TNode<BoolT> CodeStubAssembler::IsHoleInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, HOLE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOddball(TNode<HeapObject> object) {
  return IsOddballInstanceType(LoadInstanceType(object));
}

TNode<BoolT> CodeStubAssembler::IsOddballInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, ODDBALL_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsName(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  TNode<Map> map = LoadMap(object);
  TNode<Word32T> map_as_word32 = ReinterpretCast<Word32T>(map);
  static_assert(InstanceTypeChecker::kStringMapUpperBound + Map::kSize ==
                StaticReadOnlyRoot::kSymbolMap);
  return Uint32LessThanOrEqual(map_as_word32,
                               Int32Constant(StaticReadOnlyRoot::kSymbolMap));
#else
  return IsNameInstanceType(LoadInstanceType(object));
#endif
}

TNode<BoolT> CodeStubAssembler::IsNameInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type, Int32Constant(LAST_NAME_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsString(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  TNode<Map> map = LoadMap(object);
  TNode<Word32T> map_as_word32 =
      TruncateIntPtrToInt32(BitcastTaggedToWord(map));
  return Uint32LessThanOrEqual(
      map_as_word32, Int32Constant(InstanceTypeChecker::kStringMapUpperBound));
#else
  return IsStringInstanceType(LoadInstanceType(object));
#endif
}

TNode<Word32T> CodeStubAssembler::IsStringWrapper(TNode<HeapObject> object) {
  return IsStringWrapperElementsKind(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsSeqOneByteString(TNode<HeapObject> object) {
  return IsSeqOneByteStringInstanceType(LoadInstanceType(object));
}

TNode<BoolT> CodeStubAssembler::IsSymbolInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, SYMBOL_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsInternalizedStringInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(kNotInternalizedTag != 0);
  return Word32Equal(
      Word32And(instance_type,
                Int32Constant(kIsNotStringMask | kIsNotInternalizedMask)),
      Int32Constant(kStringTag | kInternalizedTag));
}

TNode<BoolT> CodeStubAssembler::IsSharedStringInstanceType(
    TNode<Int32T> instance_type) {
  TNode<BoolT> is_shared = Word32Equal(
      Word32And(instance_type,
                Int32Constant(kIsNotStringMask | kSharedStringMask)),
      Int32Constant(kStringTag | kSharedStringTag));
  // TODO(v8:12007): Internalized strings do not have kSharedStringTag until
  // the shared string table ships.
  return Word32Or(is_shared,
                  Word32And(HasSharedStringTableFlag(),
                            IsInternalizedStringInstanceType(instance_type)));
}

TNode<BoolT> CodeStubAssembler::IsUniqueName(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] { return Int32TrueConstant(); },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

// Semantics: guaranteed not to be an integer index (i.e. contains non-digit
// characters, or is outside MAX_SAFE_INTEGER/size_t range). Note that for
// non-TypedArray receivers, there are additional strings that must be treated
// as named property keys, namely the range [0xFFFFFFFF, MAX_SAFE_INTEGER].
// The hash could be a forwarding index to an integer index.
// For now we conservatively assume that all forwarded hashes could be integer
// indices, allowing false negatives.
// TODO(pthier): We could use 1 bit of the forward index to indicate whether the
// forwarded hash contains an integer index, if this is turns out to be a
// performance issue, at the cost of slowing down creating the forwarded string.
TNode<BoolT> CodeStubAssembler::IsUniqueNameNoIndex(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] {
        return IsSetWord32(LoadNameRawHashField(CAST(object)),
                           Name::kDoesNotContainIntegerOrForwardingIndexMask);
      },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

// Semantics: {object} is a Symbol, or a String that doesn't have a cached
// index. This returns {true} for strings containing representations of
// integers in the range above 9999999 (per kMaxCachedArrayIndexLength)
// and below MAX_SAFE_INTEGER. For CSA_DCHECKs ensuring correct usage, this is
// better than no checking; and we don't have a good/fast way to accurately
// check such strings for being within "array index" (uint32_t) range.
TNode<BoolT> CodeStubAssembler::IsUniqueNameNoCachedIndex(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] {
        return IsSetWord32(LoadNameRawHash(CAST(object)),
                           Name::kDoesNotContainCachedArrayIndexMask);
      },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

TNode<BoolT> CodeStubAssembler::IsBigIntInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, BIGINT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsBigInt(TNode<HeapObject> object) {
  return IsBigIntInstanceType(LoadInstanceType(object));
}

void CodeStubAssembler::GotoIfLargeBigInt(TNode<BigInt> bigint,
                                          Label* true_label) {
  // Small BigInts are BigInts in the range [-2^63 + 1, 2^63 - 1] so that they
  // can fit in 64-bit registers. Excluding -2^63 from the range makes the check
  // simpler and faster. The other BigInts are seen as "large".
  // TODO(panq): We might need to reevaluate of the range of small BigInts.
  DCHECK(Is64());
  Label false_label(this);
  TNode<Uint32T> length =
      DecodeWord32<BigIntBase::LengthBits>(LoadBigIntBitfield(bigint));
  GotoIf(Word32Equal(length, Uint32Constant(0)), &false_label);
  GotoIfNot(Word32Equal(length, Uint32Constant(1)), true_label);
  Branch(WordEqual(UintPtrConstant(0),
                   WordAnd(LoadBigIntDigit(bigint, 0),
                           UintPtrConstant(static_cast<uintptr_t>(
                               1ULL << (sizeof(uintptr_t) * 8 - 1))))),
         &false_label, true_label);
  Bind(&false_label);
}

TNode<BoolT> CodeStubAssembler::IsPrimitiveInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_PRIMITIVE_HEAP_OBJECT_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsPrivateName(TNode<Symbol> symbol) {
  TNode<Uint32T> flags =
      LoadObjectField<Uint32T>(symbol, offsetof(Symbol, flags_));
  return IsSetWord32<Symbol::IsPrivateNameBit>(flags);
}

TNode<BoolT> CodeStubAssembler::IsHashTable(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(
      Word32And(Int32GreaterThanOrEqual(instance_type,
                                        Int32Constant(FIRST_HASH_TABLE_TYPE)),
                Int32LessThanOrEqual(instance_type,
                                     Int32Constant(LAST_HASH_TABLE_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsEphemeronHashTable(TNode<HeapObject> object) {
  return HasInstanceType(object, EPHEMERON_HASH_TABLE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsPropertyDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, PROPERTY_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOrderedNameDictionary(
    TNode<HeapObject> object) {
  return HasInstanceType(object, ORDERED_NAME_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsGlobalDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, GLOBAL_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNumberDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, NUMBER_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSGeneratorObject(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFunctionInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type,
                   FIRST_JS_FUNCTION_OR_BOUND_FUNCTION_OR_WRAPPED_FUNCTION_TYPE,
                   LAST_JS_FUNCTION_OR_BOUND_FUNCTION_OR_WRAPPED_FUNCTION_TYPE);
}
TNode<BoolT> CodeStubAssembler::IsJSFunctionInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type, FIRST_JS_FUNCTION_TYPE,
                   LAST_JS_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFunction(TNode<HeapObject> object) {
  return IsJSFunctionMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSBoundFunction(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_BOUND_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFunctionMap(TNode<Map> map) {
  return IsJSFunctionInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_TYPED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArrayMap(TNode<Map> map) {
  return IsJSTypedArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArray(TNode<HeapObject> object) {
  return IsJSTypedArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayBuffer(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ARRAY_BUFFER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSDataView(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_DATA_VIEW_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRabGsabDataView(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_RAB_GSAB_DATA_VIEW_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRegExp(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_REG_EXP_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNumeric(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return UncheckedCast<BoolT>(
            Word32Or(IsHeapNumber(CAST(object)), IsBigInt(CAST(object))));
      });
}

TNode<BoolT> CodeStubAssembler::IsNumberNormalized(TNode<Number> number) {
  TVARIABLE(BoolT, var_result, Int32TrueConstant());
  Label out(this);

  GotoIf(TaggedIsSmi(number), &out);

  TNode<Float64T> value = LoadHeapNumberValue(CAST(number));
  TNode<Float64T> smi_min =
      Float64Constant(static_cast<double>(Smi::kMinValue));
  TNode<Float64T> smi_max =
      Float64Constant(static_cast<double>(Smi::kMaxValue));

  GotoIf(Float64LessThan(value, smi_min), &out);
  GotoIf(Float64GreaterThan(value, smi_max), &out);
  GotoIfNot(Float64Equal(value, value), &out);  // NaN.

  var_result = Int32FalseConstant();
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsNumberPositive(TNode<Number> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return TaggedIsPositiveSmi(number); },
      [=, this] { return IsHeapNumberPositive(CAST(number)); });
}

// TODO(cbruni): Use TNode<HeapNumber> instead of custom name.
TNode<BoolT> CodeStubAssembler::IsHeapNumberPositive(TNode<HeapNumber> number) {
  TNode<Float64T> value = LoadHeapNumberValue(number);
  TNode<Float64T> float_zero = Float64Constant(0.);
  return Float64GreaterThanOrEqual(value, float_zero);
}

TNode<BoolT> CodeStubAssembler::IsNumberNonNegativeSafeInteger(
    TNode<Number> number) {
  return Select<BoolT>(
      // TODO(cbruni): Introduce TaggedIsNonNegateSmi to avoid confusion.
      TaggedIsSmi(number), [=, this] { return TaggedIsPositiveSmi(number); },
      [=, this] {
        TNode<HeapNumber> heap_number = CAST(number);
        return Select<BoolT>(
            IsInteger(heap_number),
            [=, this] { return IsHeapNumberPositive(heap_number); },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsSafeInteger(TNode<Object> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Select<BoolT>(
            IsHeapNumber(CAST(number)),
            [=, this] {
              return IsSafeInteger(UncheckedCast<HeapNumber>(number));
            },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsSafeInteger(TNode<HeapNumber> number) {
  // Load the actual value of {number}.
  TNode<Float64T> number_value = LoadHeapNumberValue(number);
  // Truncate the value of {number} to an integer (or an infinity).
  TNode<Float64T> integer = Float64Trunc(number_value);

  return Select<BoolT>(
      // Check if {number}s value matches the integer (ruling out the
      // infinities).
      Float64Equal(Float64Sub(number_value, integer), Float64Constant(0.0)),
      [=, this] {
        // Check if the {integer} value is in safe integer range.
        return Float64LessThanOrEqual(Float64Abs(integer),
                                      Float64Constant(kMaxSafeInteger));
      },
      [=, this] { return Int32FalseConstant(); });
}

TNode<BoolT> CodeStubAssembler::IsInteger(TNode<Object> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Select<BoolT>(
            IsHeapNumber(CAST(number)),
            [=, this] { return IsInteger(UncheckedCast<HeapNumber>(number)); },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsInteger(TNode<HeapNumber> number) {
  TNode<Float64T> number_value = LoadHeapNumberValue(number);
  // Truncate the value of {number} to an integer (or an infinity).
  TNode<Float64T> integer = Float64Trunc(number_value);
  // Check if {number}s value matches the integer (ruling out the infinities).
  return Float64Equal(Float64Sub(number_value, integer), Float64Constant(0.0));
}

TNode<BoolT> CodeStubAssembler::IsHeapNumberUint32(TNode<HeapNumber> number) {
  // Check that the HeapNumber is a valid uint32
  return Select<BoolT>(
      IsHeapNumberPositive(number),
      [=, this] {
        TNode<Float64T> value = LoadHeapNumberValue(nu
"""


```