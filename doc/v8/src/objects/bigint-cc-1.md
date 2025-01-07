Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/bigint.cc`. The request has several constraints:

1. **List Functionality:** Identify the primary tasks performed by the code.
2. **Torque Source:** Determine if the file is a Torque source (it's not, as it ends with `.cc`).
3. **JavaScript Relationship:** If related to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** Present an example of input and output based on the code's logic.
5. **Common Programming Errors:** Illustrate potential mistakes users might make when working with BigInts in JavaScript.
6. **Part of a Series:** Acknowledge that this is part 2 of a 3-part series.
7. **Summarize Functionality:**  Provide a concise overview of the code's purpose.

Let's break down the code snippet to identify its functions:

- **String Conversion:** The code includes logic for converting BigInts to strings (`ToString`, `NoSideEffectsToString`). It handles different radices and optimization for base 10.
- **Number Conversion:**  It provides functions to convert Numbers (including Smis and HeapNumbers) to BigInts (`FromNumber`). It also handles potential range errors.
- **Object Conversion:** It has a function to convert various JavaScript objects to BigInts (`FromObject`), including Booleans, Strings (parsing), and other BigInts. It handles potential SyntaxErrors for invalid string conversions and TypeErrors for incompatible types.
- **BigInt to Number:**  There's a function to convert BigInts to regular JavaScript Numbers (`ToNumber`), handling potential precision loss.
- **Double Conversion:** The code includes detailed logic for converting BigInts to `double` values (`MutableBigInt::ToDouble`), including handling large numbers, rounding, and edge cases like infinity.
- **Arithmetic Operations (Internal Helpers):**  Internal helper functions for basic arithmetic like adding one (`AbsoluteAddOne`) and subtracting one (`AbsoluteSubOne`) are present.
- **Allocation:**  The `Allocate` function manages the creation of BigInt objects from string accumulators.
- **Serialization:** Functions for serializing and deserializing BigInts (`GetBitfieldForSerialization`, `SerializeDigits`, `FromSerializedDigits`) are implemented.
- **Bitwise Operations:** Functions for bitwise operations like `AsIntN` and `AsUintN` are provided.
- **Integer Conversions:** Functions to create BigInts from 64-bit integers (`FromInt64`, `FromUint64`) and from arrays of 64-bit words (`FromWords64`).
- **Word Array Conversion:** Functions to convert BigInts to arrays of 64-bit words (`ToWordsArray64`).
- **Raw Bit Access:** Functions to get the raw bit representation of a BigInt (`MutableBigInt::GetRawBits`) and convert to `int64_t` and `uint64_t` (`AsInt64`, `AsUint64`).
- **Internal C Function Wrappers:**  Wrappers for calling internal bigint arithmetic and bitwise operations like addition, subtraction, multiplication, division, modulo, and, or, and xor. These functions are used in the V8 runtime.

Based on this analysis, I can now construct the response addressing each of the user's requirements.
这是v8源代码文件 `v8/src/objects/bigint.cc` 的第二部分代码，它主要负责 **BigInt 对象的创建、转换以及一些内部操作**。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **BigInt 转换为字符串:**
   - 提供了将 `BigInt` 对象转换为字符串表示的方法 (`ToString`, `NoSideEffectsToString`)。
   - `ToString` 可以指定进制 (radix)，并且处理了性能优化，特别是对于小 `BigInt` 和十进制的情况。
   - `NoSideEffectsToString` 用于生成人类可读的错误消息，对于非常大的 `BigInt` 会截断显示。

2. **从其他类型转换为 BigInt:**
   - `FromNumber`:  将 JavaScript 的 `Number` 类型 (包括 `Smi` 和 `HeapNumber`) 转换为 `BigInt`。如果 `Number` 不是整数或超出安全整数范围，则会抛出 `RangeError`。
   - `FromObject`:  尝试将各种 JavaScript 对象转换为 `BigInt`。这包括：
     - `Boolean`: `true` 转换为 `1n`，`false` 转换为 `0n`。
     - `BigInt`: 直接返回。
     - `String`:  尝试将字符串解析为 `BigInt`。如果解析失败，则抛出 `SyntaxError`。
     - 其他类型会抛出 `TypeError`。

3. **BigInt 转换为 Number:**
   - `ToNumber`: 将 `BigInt` 转换为 JavaScript 的 `Number` 类型。如果 `BigInt` 的值超出 `Number` 的安全整数范围，则可能导致精度损失。

4. **BigInt 转换为 Double:**
   - `MutableBigInt::ToDouble`: 将 `BigInt` 转换为 `double` 类型。这涉及到复杂的舍入逻辑，并处理了 `BigInt` 值超出 `double` 表示范围的情况 (返回 `Infinity` 或 `-Infinity`)。

5. **内部辅助函数:**
   - `MutableBigInt::AbsoluteAddOne`, `MutableBigInt::AbsoluteSubOne`:  用于内部的绝对值加一和减一操作。

6. **序列化和反序列化:**
   - 提供了 `BigInt` 对象的序列化 (`GetBitfieldForSerialization`, `SerializeDigits`) 和反序列化 (`FromSerializedDigits`) 功能，用于在不同 V8 实例之间或持久化存储中传输 `BigInt`。

7. **位操作:**
   - `AsIntN`, `AsUintN`:  模拟 JavaScript 中 `BigInt.asIntN` 和 `BigInt.asUintN` 的行为，将 `BigInt` 截断到指定的位数。

8. **从固定宽度整数创建 BigInt:**
   - `FromInt64`, `FromUint64`:  从 C++ 的 64 位有符号和无符号整数创建 `BigInt`。
   - `FromWords64`: 从 64 位字的数组创建 `BigInt`。

9. **转换为固定宽度整数:**
   - `AsInt64`, `AsUint64`: 将 `BigInt` 转换为 C++ 的 64 位有符号和无符号整数，并提供一个标志指示是否发生精度损失。

10. **内部算术和位运算函数包装器:**
    - 这部分代码定义了一些 C 函数，作为对内部 `bigint` 库的包装器，用于执行底层的算术运算（加、减、乘、除、模）和位运算（与、或、异或）。这些函数在 V8 运行时中被调用。

**如果 v8/src/objects/bigint.cc 以 .tq 结尾:**

如果 `v8/src/objects/bigint.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部函数的领域特定语言，它可以生成高效的 C++ 代码。

**与 JavaScript 功能的关系及示例:**

这部分代码直接关联到 JavaScript 中的 `BigInt` 功能。以下是一些 JavaScript 示例，对应了代码中的功能：

```javascript
// BigInt 转换为字符串
const bigIntToString = 12345678901234567890n.toString(); // "12345678901234567890"
const bigIntToHex = 255n.toString(16); // "ff"

// 从其他类型转换为 BigInt
const numberToBigInt = BigInt(123); // 123n
const stringToBigInt = BigInt("98765432109876543210"); // 98765432109876543210n
const booleanToBigInt = BigInt(true); // 1n

// BigInt 转换为 Number
const bigIntToNumber = Number(100n); // 100
const largeBigIntToNumber = Number(999999999999999999999n); // 1e+20 (精度可能丢失)

// 位操作
const bigIntAsIntN = 0xFFn.asIntN(8); // -1n (截断到 8 位并按有符号处理)
const bigIntAsUintN = (-1n).asUintN(8); // 255n (截断到 8 位并按无符号处理)

// 固定宽度整数转换（JavaScript 中没有直接对应的全局函数，但 BigInt 方法支持）
// 例如，在内部实现中，V8 会使用这里的 FromInt64 等函数。
```

**代码逻辑推理示例:**

假设输入一个 `BigInt` 对象，其内部表示为 `digits = [10, 0]`, `sign = false` (表示十进制的 65536，假设 `kDigitBits = 16`)，调用 `ToString(isolate, bigint, 10, kDontThrow)`。

**假设输入:**
- `bigint`:  内部表示为 `digits = [10, 0]`, `sign = false`
- `radix`: 10
- `should_throw`: `kDontThrow`

**代码逻辑推理:**

1. 由于 `radix` 是 10，并且 `bigint` 的长度大于 0，会进入优化的十进制转换路径。
2. `digit = bigint->digit(0)`，所以 `digit` 为 10。
3. `bit_length` 计算出来会是 4 (10 的二进制表示为 1010)。
4. `chars_allocated` 会根据公式计算出一个预估的字符长度。
5. 进入 `while (digit != 0)` 循环：
   - 第一次循环：`*(--out) = '0' + (10 % 10)`，即 `'0'`，`digit` 变为 1。
   - 第二次循环：`*(--out) = '0' + (1 % 10)`，即 `'1'`，`digit` 变为 0。
6. 因为 `sign` 是 `false`，所以不会添加负号。
7. `chars_written` 会根据实际写入的字符数计算。
8. 最终返回一个字符串对象，内容为 "10"。

**输出:**
- 返回的字符串对象的字符串值为 "10"。

**用户常见的编程错误:**

1. **与 Number 混合运算导致精度丢失:**
   ```javascript
   const big = 9007199254740991n;
   const num = 9007199254740991;
   console.log(big + 1n); // 9007199254740992n
   console.log(num + 1);  // 9007199254740992 (可能存在精度问题)
   console.log(big + num); // TypeError: Cannot mix BigInt and other types, use explicit conversions
   ```
   **错误原因:**  直接将 `BigInt` 和 `Number` 相加会导致类型错误。需要显式地将 `Number` 转换为 `BigInt` 或将 `BigInt` 转换为 `Number` (可能损失精度)。

2. **不理解 BigInt 的除法行为:**
   ```javascript
   console.log(10n / 3n); // 3n
   console.log(10 / 3);   // 3.333...
   ```
   **错误原因:** `BigInt` 的除法会舍弃小数部分，返回一个 `BigInt` 类型的整数结果，与 `Number` 的除法不同。

3. **将可能超出安全整数范围的 Number 隐式转换为 BigInt:**
   ```javascript
   let largeNumber = 9007199254740995; // 注意这个 Number 已经超出了安全整数范围
   const bigFromNumber = BigInt(largeNumber);
   console.log(bigFromNumber); // 9007199254740996n (由于 Number 自身精度问题，转换后的 BigInt 值可能不准确)
   ```
   **错误原因:** 如果先创建了一个超出安全整数范围的 `Number`，然后再将其转换为 `BigInt`，那么由于 `Number` 自身可能已经损失了精度，转换后的 `BigInt` 值可能不是期望的精确值。应该直接使用字符串字面量创建 `BigInt`。

**总结 `v8/src/objects/bigint.cc` (第 2 部分) 的功能:**

这部分代码主要负责 `BigInt` 对象在 V8 引擎中的生命周期管理和与其他 JavaScript 类型的互操作，包括创建、各种类型的转换 (到字符串、数字、布尔值等) 以及一些底层的操作，为 JavaScript 中 `BigInt` 的使用提供了基础支持。它还包含了用于序列化和反序列化 `BigInt` 以及进行位操作的功能。

Prompt: 
```
这是目录为v8/src/objects/bigint.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/bigint.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
dispatch overhead.
    // The logic is the same as what the full implementation does below,
    // just inlined and specialized for the preconditions.
    // Microbenchmarks rejoice!
    digit_t digit = bigint->digit(0);
    uint32_t bit_length = kDigitBits - base::bits::CountLeadingZeros(digit);
    constexpr uint32_t kShift = 7;
    // This is Math.log2(10) * (1 << kShift), scaled just far enough to
    // make the computations below always precise (after rounding).
    constexpr uint32_t kShiftedBitsPerChar = 425;
    chars_allocated = (bit_length << kShift) / kShiftedBitsPerChar + 1 + sign;
    result = isolate->factory()
                 ->NewRawOneByteString(chars_allocated)
                 .ToHandleChecked();
    DisallowGarbageCollection no_gc;
    uint8_t* start = result->GetChars(no_gc);
    uint8_t* out = start + chars_allocated;
    while (digit != 0) {
      *(--out) = '0' + (digit % 10);
      digit /= 10;
    }
    if (sign) *(--out) = '-';
    if (out == start) {
      chars_written = chars_allocated;
    } else {
      DCHECK_LT(start, out);
      // The result is one character shorter than predicted. This is
      // unavoidable, e.g. a 4-bit BigInt can be as big as "10" or as small as
      // "9", so we must allocate 2 characters for it, and will only later find
      // out whether all characters were used.
      chars_written = chars_allocated - static_cast<uint32_t>(out - start);
      std::memmove(start, out, chars_written);
      memset(start + chars_written, 0, chars_allocated - chars_written);
    }
  } else {
    // Generic path, handles anything.
    DCHECK(radix >= 2 && radix <= 36);
    chars_allocated =
        bigint::ToStringResultLength(bigint->digits(), radix, sign);
    if (chars_allocated > String::kMaxLength) {
      if (should_throw == kThrowOnError) {
        THROW_NEW_ERROR(isolate, NewInvalidStringLengthError());
      } else {
        return {};
      }
    }
    result = isolate->factory()
                 ->NewRawOneByteString(chars_allocated)
                 .ToHandleChecked();
    chars_written = chars_allocated;
    DisallowGarbageCollection no_gc;
    char* characters = reinterpret_cast<char*>(result->GetChars(no_gc));
    bigint::Status status = isolate->bigint_processor()->ToString(
        characters, &chars_written, bigint->digits(), radix, sign);
    if (status == bigint::Status::kInterrupted) {
      AllowGarbageCollection terminating_anyway;
      isolate->TerminateExecution();
      return {};
    }
  }

  // Right-trim any over-allocation (which can happen due to conservative
  // estimates).
  RightTrimString(isolate, result, chars_allocated, chars_written);
#if DEBUG
  // Verify that all characters have been written.
  DCHECK(result->length() == chars_written);
  DisallowGarbageCollection no_gc;
  uint8_t* chars = result->GetChars(no_gc);
  for (uint32_t i = 0; i < chars_written; i++) {
    DCHECK_NE(chars[i], bigint::kStringZapValue);
  }
#endif
  return result;
}

Handle<String> BigInt::NoSideEffectsToString(Isolate* isolate,
                                             DirectHandle<BigInt> bigint) {
  if (bigint->is_zero()) {
    return isolate->factory()->zero_string();
  }
  // The threshold is chosen such that the operation will be fast enough to
  // not need interrupt checks. This function is meant for producing human-
  // readable error messages, so super-long results aren't useful anyway.
  if (bigint->length() > 100) {
    return isolate->factory()->NewStringFromStaticChars(
        "<a very large BigInt>");
  }

  uint32_t chars_allocated =
      bigint::ToStringResultLength(bigint->digits(), 10, bigint->sign());
  DCHECK_LE(chars_allocated, String::kMaxLength);
  Handle<SeqOneByteString> result = isolate->factory()
                                        ->NewRawOneByteString(chars_allocated)
                                        .ToHandleChecked();
  uint32_t chars_written = chars_allocated;
  DisallowGarbageCollection no_gc;
  char* characters = reinterpret_cast<char*>(result->GetChars(no_gc));
  std::unique_ptr<bigint::Processor, bigint::Processor::Destroyer>
      non_interruptible_processor(
          bigint::Processor::New(new bigint::Platform()));
  non_interruptible_processor->ToString(characters, &chars_written,
                                        bigint->digits(), 10, bigint->sign());
  RightTrimString(isolate, result, chars_allocated, chars_written);
  return result;
}

MaybeHandle<BigInt> BigInt::FromNumber(Isolate* isolate,
                                       Handle<Object> number) {
  DCHECK(IsNumber(*number));
  if (IsSmi(*number)) {
    return MutableBigInt::NewFromInt(isolate, Smi::ToInt(*number));
  }
  double value = Cast<HeapNumber>(*number)->value();
  if (!std::isfinite(value) || (DoubleToInteger(value) != value)) {
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kBigIntFromNumber, number));
  }
  return MutableBigInt::NewFromDouble(isolate, value);
}

MaybeHandle<BigInt> BigInt::FromObject(Isolate* isolate, Handle<Object> obj) {
  if (IsJSReceiver(*obj)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, obj,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(obj),
                                ToPrimitiveHint::kNumber));
  }

  if (IsBoolean(*obj)) {
    return MutableBigInt::NewFromInt(isolate,
                                     Object::BooleanValue(*obj, isolate));
  }
  if (IsBigInt(*obj)) {
    return Cast<BigInt>(obj);
  }
  if (IsString(*obj)) {
    Handle<BigInt> n;
    if (!StringToBigInt(isolate, Cast<String>(obj)).ToHandle(&n)) {
      if (isolate->has_exception()) {
        return MaybeHandle<BigInt>();
      } else {
        Handle<String> str = Cast<String>(obj);
        constexpr uint32_t kMaxRenderedLength = 1000;
        if (str->length() > kMaxRenderedLength) {
          Factory* factory = isolate->factory();
          Handle<String> prefix =
              factory->NewProperSubString(str, 0, kMaxRenderedLength);
          Handle<SeqTwoByteString> ellipsis =
              factory->NewRawTwoByteString(1).ToHandleChecked();
          ellipsis->SeqTwoByteStringSet(0, 0x2026);
          str = factory->NewConsString(prefix, ellipsis).ToHandleChecked();
        }
        THROW_NEW_ERROR(
            isolate, NewSyntaxError(MessageTemplate::kBigIntFromObject, str));
      }
    }
    return n;
  }

  THROW_NEW_ERROR(isolate,
                  NewTypeError(MessageTemplate::kBigIntFromObject, obj));
}

Handle<Number> BigInt::ToNumber(Isolate* isolate, DirectHandle<BigInt> x) {
  if (x->is_zero()) return Handle<Smi>(Smi::zero(), isolate);
  if (x->length() == 1 && x->digit(0) < Smi::kMaxValue) {
    int value = static_cast<int>(x->digit(0));
    if (x->sign()) value = -value;
    return Handle<Smi>(Smi::FromInt(value), isolate);
  }
  double result = MutableBigInt::ToDouble(x);
  return isolate->factory()->NewHeapNumber(result);
}

double MutableBigInt::ToDouble(DirectHandle<BigIntBase> x) {
  if (x->is_zero()) return 0.0;
  uint32_t x_length = x->length();
  digit_t x_msd = x->digit(x_length - 1);
  uint32_t msd_leading_zeros = base::bits::CountLeadingZeros(x_msd);
  uint32_t x_bitlength = x_length * kDigitBits - msd_leading_zeros;
  if (x_bitlength > 1024) return x->sign() ? -V8_INFINITY : V8_INFINITY;
  uint64_t exponent = x_bitlength - 1;
  // We need the most significant bit shifted to the position of a double's
  // "hidden bit". We also need to hide that MSB, so we shift it out.
  uint64_t current_digit = x_msd;
  uint32_t digit_index = x_length - 1;
  uint32_t shift = msd_leading_zeros + 1 + (64 - kDigitBits);
  DCHECK_LE(1, shift);
  DCHECK_LE(shift, 64);
  uint64_t mantissa = (shift == 64) ? 0 : current_digit << shift;
  mantissa >>= 12;
  int32_t mantissa_bits_unset = shift - 12;
  // If not all mantissa bits are defined yet, get more digits as needed.
  if (mantissa_bits_unset >= static_cast<int32_t>(kDigitBits) &&
      digit_index > 0) {
    digit_index--;
    current_digit = static_cast<uint64_t>(x->digit(digit_index));
    mantissa |= (current_digit << (mantissa_bits_unset - kDigitBits));
    mantissa_bits_unset -= kDigitBits;
  }
  if (mantissa_bits_unset > 0 && digit_index > 0) {
    DCHECK_LT(mantissa_bits_unset, kDigitBits);
    digit_index--;
    current_digit = static_cast<uint64_t>(x->digit(digit_index));
    mantissa |= (current_digit >> (kDigitBits - mantissa_bits_unset));
    mantissa_bits_unset -= kDigitBits;
  }
  // If there are unconsumed digits left, we may have to round.
  Rounding rounding =
      DecideRounding(x, mantissa_bits_unset, digit_index, current_digit);
  if (rounding == kRoundUp || (rounding == kTie && (mantissa & 1) == 1)) {
    mantissa++;
    // Incrementing the mantissa can overflow the mantissa bits. In that case
    // the new mantissa will be all zero (plus hidden bit).
    if ((mantissa >> base::Double::kPhysicalSignificandSize) != 0) {
      mantissa = 0;
      exponent++;
      // Incrementing the exponent can overflow too.
      if (exponent > 1023) {
        return x->sign() ? -V8_INFINITY : V8_INFINITY;
      }
    }
  }
  // Assemble the result.
  uint64_t sign_bit = x->sign() ? (static_cast<uint64_t>(1) << 63) : 0;
  exponent = (exponent + 0x3FF) << base::Double::kPhysicalSignificandSize;
  uint64_t double_bits = sign_bit | exponent | mantissa;
  return base::bit_cast<double>(double_bits);
}

// This is its own function to simplify control flow. The meaning of the
// parameters is defined by {ToDouble}'s local variable usage.
MutableBigInt::Rounding MutableBigInt::DecideRounding(
    DirectHandle<BigIntBase> x, int mantissa_bits_unset, int digit_index,
    uint64_t current_digit) {
  if (mantissa_bits_unset > 0) return kRoundDown;
  int top_unconsumed_bit;
  if (mantissa_bits_unset < 0) {
    // There are unconsumed bits in {current_digit}.
    top_unconsumed_bit = -mantissa_bits_unset - 1;
  } else {
    DCHECK_EQ(mantissa_bits_unset, 0);
    // {current_digit} fit the mantissa exactly; look at the next digit.
    if (digit_index == 0) return kRoundDown;
    digit_index--;
    current_digit = static_cast<uint64_t>(x->digit(digit_index));
    top_unconsumed_bit = kDigitBits - 1;
  }
  // If the most significant remaining bit is 0, round down.
  uint64_t bitmask = static_cast<uint64_t>(1) << top_unconsumed_bit;
  if ((current_digit & bitmask) == 0) {
    return kRoundDown;
  }
  // If any other remaining bit is set, round up.
  bitmask -= 1;
  if ((current_digit & bitmask) != 0) return kRoundUp;
  while (digit_index > 0) {
    digit_index--;
    if (x->digit(digit_index) != 0) return kRoundUp;
  }
  return kTie;
}

void BigInt::BigIntShortPrint(std::ostream& os) {
  if (sign()) os << "-";
  uint32_t len = length();
  if (len == 0) {
    os << "0";
    return;
  }
  if (len > 1) os << "...";
  os << digit(0);
}

// Internal helpers.

// Adds 1 to the absolute value of {x} and sets the result's sign to {sign}.
// {result_storage} is optional; if present, it will be used to store the
// result, otherwise a new BigInt will be allocated for the result.
// {result_storage} and {x} may refer to the same BigInt for in-place
// modification.
MaybeHandle<MutableBigInt> MutableBigInt::AbsoluteAddOne(
    Isolate* isolate, DirectHandle<BigIntBase> x, bool sign,
    Tagged<MutableBigInt> result_storage) {
  uint32_t input_length = x->length();
  // The addition will overflow into a new digit if all existing digits are
  // at maximum.
  bool will_overflow = true;
  for (uint32_t i = 0; i < input_length; i++) {
    if (!digit_ismax(x->digit(i))) {
      will_overflow = false;
      break;
    }
  }
  uint32_t result_length = input_length + will_overflow;
  Handle<MutableBigInt> result(result_storage, isolate);
  if (result_storage.is_null()) {
    if (!New(isolate, result_length).ToHandle(&result)) {
      return MaybeHandle<MutableBigInt>();
    }
  } else {
    DCHECK(result->length() == result_length);
  }
  if (input_length == 0) {
    result->set_digit(0, 1);
  } else if (input_length == 1 && !will_overflow) {
    result->set_digit(0, x->digit(0) + 1);
  } else {
    bigint::AddOne(result->rw_digits(), x->digits());
  }
  result->set_sign(sign);
  return result;
}

// Subtracts 1 from the absolute value of {x}. {x} must not be zero.
Handle<MutableBigInt> MutableBigInt::AbsoluteSubOne(
    Isolate* isolate, DirectHandle<BigIntBase> x) {
  DCHECK(!x->is_zero());
  uint32_t length = x->length();
  Handle<MutableBigInt> result = New(isolate, length).ToHandleChecked();
  if (length == 1) {
    result->set_digit(0, x->digit(0) - 1);
  } else {
    bigint::SubtractOne(result->rw_digits(), x->digits());
  }
  return result;
}

void Terminate(Isolate* isolate) { isolate->TerminateExecution(); }
// {LocalIsolate} doesn't support interruption or termination.
void Terminate(LocalIsolate* isolate) { UNREACHABLE(); }

template <typename IsolateT>
MaybeHandle<BigInt> BigInt::Allocate(IsolateT* isolate,
                                     bigint::FromStringAccumulator* accumulator,
                                     bool negative, AllocationType allocation) {
  uint32_t digits = accumulator->ResultLength();
  DCHECK_LE(digits, kMaxLength);
  Handle<MutableBigInt> result =
      MutableBigInt::New(isolate, digits, allocation).ToHandleChecked();
  bigint::Status status =
      isolate->bigint_processor()->FromString(result->rw_digits(), accumulator);
  if (status == bigint::Status::kInterrupted) {
    Terminate(isolate);
    return {};
  }
  if (digits > 0) result->set_sign(negative);
  return MutableBigInt::MakeImmutable(result);
}
template MaybeHandle<BigInt> BigInt::Allocate(Isolate*,
                                              bigint::FromStringAccumulator*,
                                              bool, AllocationType);
template MaybeHandle<BigInt> BigInt::Allocate(LocalIsolate*,
                                              bigint::FromStringAccumulator*,
                                              bool, AllocationType);

// The serialization format MUST NOT CHANGE without updating the format
// version in value-serializer.cc!
uint32_t BigInt::GetBitfieldForSerialization() const {
  // In order to make the serialization format the same on 32/64 bit builds,
  // we convert the length-in-digits to length-in-bytes for serialization.
  // Being able to do this depends on having enough LengthBits:
  static_assert(kMaxLength * kDigitSize <= LengthBits::kMax);
  uint32_t bytelength = length() * kDigitSize;
  return SignBits::encode(sign()) | LengthBits::encode(bytelength);
}

size_t BigInt::DigitsByteLengthForBitfield(uint32_t bitfield) {
  return LengthBits::decode(bitfield);
}

// The serialization format MUST NOT CHANGE without updating the format
// version in value-serializer.cc!
void BigInt::SerializeDigits(uint8_t* storage, size_t storage_length) {
  size_t num_digits_to_write = storage_length / kDigitSize;
  // {storage_length} should have been computed from {length()}.
  DCHECK_EQ(num_digits_to_write, length());
#if defined(V8_TARGET_LITTLE_ENDIAN)
  memcpy(storage, raw_digits(), num_digits_to_write * kDigitSize);
#elif defined(V8_TARGET_BIG_ENDIAN)
  digit_t* digit_storage = reinterpret_cast<digit_t*>(storage);
  const digit_t* digit = reinterpret_cast<const digit_t*>(raw_digits());
  for (size_t i = 0; i < num_digits_to_write; i++) {
    *digit_storage = ByteReverse(*digit);
    digit_storage++;
    digit++;
  }
#endif  // V8_TARGET_BIG_ENDIAN
}

// The serialization format MUST NOT CHANGE without updating the format
// version in value-serializer.cc!
MaybeHandle<BigInt> BigInt::FromSerializedDigits(
    Isolate* isolate, uint32_t bitfield,
    base::Vector<const uint8_t> digits_storage) {
  uint32_t bytelength = LengthBits::decode(bitfield);
  DCHECK_EQ(static_cast<uint32_t>(digits_storage.length()), bytelength);
  bool sign = SignBits::decode(bitfield);
  uint32_t length = (bytelength + kDigitSize - 1) / kDigitSize;  // Round up.
  // There is no -0n. Reject corrupted serialized data.
  if (length == 0 && sign == true) return {};
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(length));
  result->initialize_bitfield(sign, length);
  UnalignedValueMember<digit_t>* digits = result->raw_digits();
#if defined(V8_TARGET_LITTLE_ENDIAN)
  memcpy(digits, digits_storage.begin(), bytelength);
  void* padding_start =
      reinterpret_cast<void*>(reinterpret_cast<Address>(digits) + bytelength);
  memset(padding_start, 0, length * kDigitSize - bytelength);
#elif defined(V8_TARGET_BIG_ENDIAN)
  digit_t* digit = reinterpret_cast<digit_t*>(digits);
  const digit_t* digit_storage =
      reinterpret_cast<const digit_t*>(digits_storage.begin());
  for (uint32_t i = 0; i < bytelength / kDigitSize; i++) {
    *digit = ByteReverse(*digit_storage);
    digit_storage++;
    digit++;
  }
  if (bytelength % kDigitSize) {
    *digit = 0;
    uint8_t* digit_byte = reinterpret_cast<uint8_t*>(digit);
    digit_byte += sizeof(*digit) - 1;
    const uint8_t* digit_storage_byte =
        reinterpret_cast<const uint8_t*>(digit_storage);
    for (uint32_t i = 0; i < bytelength % kDigitSize; i++) {
      *digit_byte = *digit_storage_byte;
      digit_byte--;
      digit_storage_byte++;
    }
  }
#endif  // V8_TARGET_BIG_ENDIAN
  return MutableBigInt::MakeImmutable(result);
}

Handle<BigInt> BigInt::AsIntN(Isolate* isolate, uint64_t n, Handle<BigInt> x) {
  if (x->is_zero() || n > kMaxLengthBits) return x;
  if (n == 0) return MutableBigInt::Zero(isolate);
  int needed_length =
      bigint::AsIntNResultLength(x->digits(), x->sign(), static_cast<int>(n));
  if (needed_length == -1) return x;
  Handle<MutableBigInt> result =
      MutableBigInt::New(isolate, needed_length).ToHandleChecked();
  bool negative = bigint::AsIntN(result->rw_digits(), x->digits(), x->sign(),
                                 static_cast<int>(n));
  result->set_sign(negative);
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::AsUintN(Isolate* isolate, uint64_t n,
                                    Handle<BigInt> x) {
  if (x->is_zero()) return x;
  if (n == 0) return MutableBigInt::Zero(isolate);
  Handle<MutableBigInt> result;
  if (x->sign()) {
    if (n > kMaxLengthBits) {
      return ThrowBigIntTooBig<BigInt>(isolate);
    }
    int result_length = bigint::AsUintN_Neg_ResultLength(static_cast<int>(n));
    result = MutableBigInt::New(isolate, result_length).ToHandleChecked();
    bigint::AsUintN_Neg(result->rw_digits(), x->digits(), static_cast<int>(n));
  } else {
    if (n >= kMaxLengthBits) return x;
    int result_length =
        bigint::AsUintN_Pos_ResultLength(x->digits(), static_cast<int>(n));
    if (result_length < 0) return x;
    result = MutableBigInt::New(isolate, result_length).ToHandleChecked();
    bigint::AsUintN_Pos(result->rw_digits(), x->digits(), static_cast<int>(n));
  }
  DCHECK(!result->sign());
  return MutableBigInt::MakeImmutable(result);
}

Handle<BigInt> BigInt::FromInt64(Isolate* isolate, int64_t n) {
  if (n == 0) return MutableBigInt::Zero(isolate);
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  uint32_t length = 64 / kDigitBits;
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(length));
  bool sign = n < 0;
  result->initialize_bitfield(sign, length);
  uint64_t absolute;
  if (!sign) {
    absolute = static_cast<uint64_t>(n);
  } else {
    if (n == std::numeric_limits<int64_t>::min()) {
      absolute = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
    } else {
      absolute = static_cast<uint64_t>(-n);
    }
  }
  result->set_64_bits(absolute);
  return MutableBigInt::MakeImmutable(result);
}

Handle<BigInt> BigInt::FromUint64(Isolate* isolate, uint64_t n) {
  if (n == 0) return MutableBigInt::Zero(isolate);
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  uint32_t length = 64 / kDigitBits;
  Handle<MutableBigInt> result =
      Cast<MutableBigInt>(isolate->factory()->NewBigInt(length));
  result->initialize_bitfield(false, length);
  result->set_64_bits(n);
  return MutableBigInt::MakeImmutable(result);
}

MaybeHandle<BigInt> BigInt::FromWords64(Isolate* isolate, int sign_bit,
                                        uint32_t words64_count,
                                        const uint64_t* words) {
  if (words64_count > kMaxLength / (64 / kDigitBits)) {
    return ThrowBigIntTooBig<BigInt>(isolate);
  }
  if (words64_count == 0) return MutableBigInt::Zero(isolate);
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  uint32_t length = (64 / kDigitBits) * words64_count;
  DCHECK_GT(length, 0);
  if (kDigitBits == 32 && words[words64_count - 1] <= (1ULL << 32)) length--;

  Handle<MutableBigInt> result;
  if (!MutableBigInt::New(isolate, length).ToHandle(&result)) {
    return MaybeHandle<BigInt>();
  }

  result->set_sign(sign_bit);
  if (kDigitBits == 64) {
    for (uint32_t i = 0; i < length; ++i) {
      result->set_digit(i, static_cast<digit_t>(words[i]));
    }
  } else {
    for (uint32_t i = 0; i < length; i += 2) {
      digit_t lo = static_cast<digit_t>(words[i / 2]);
      digit_t hi = static_cast<digit_t>(words[i / 2] >> 32);
      result->set_digit(i, lo);
      if (i + 1 < length) result->set_digit(i + 1, hi);
    }
  }

  return MutableBigInt::MakeImmutable(result);
}

uint32_t BigInt::Words64Count() {
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  return length() / (64 / kDigitBits) +
         (kDigitBits == 32 && length() % 2 == 1 ? 1 : 0);
}

void BigInt::ToWordsArray64(int* sign_bit, uint32_t* words64_count,
                            uint64_t* words) {
  DCHECK_NE(sign_bit, nullptr);
  DCHECK_NE(words64_count, nullptr);
  *sign_bit = sign();
  uint32_t available_words = *words64_count;
  *words64_count = Words64Count();
  if (available_words == 0) return;
  DCHECK_NE(words, nullptr);

  uint32_t len = length();
  if (kDigitBits == 64) {
    for (uint32_t i = 0; i < len && i < available_words; ++i)
      words[i] = digit(i);
  } else {
    for (uint32_t i = 0; i < len && available_words > 0; i += 2) {
      uint64_t lo = digit(i);
      uint64_t hi = (i + 1) < len ? digit(i + 1) : 0;
      words[i / 2] = lo | (hi << 32);
      available_words--;
    }
  }
}

uint64_t MutableBigInt::GetRawBits(BigIntBase* x, bool* lossless) {
  if (lossless != nullptr) *lossless = true;
  if (x->is_zero()) return 0;
  uint32_t len = x->length();
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  if (lossless != nullptr && len > 64 / kDigitBits) *lossless = false;
  uint64_t raw = static_cast<uint64_t>(x->digit(0));
  if (kDigitBits == 32 && len > 1) {
    raw |= static_cast<uint64_t>(x->digit(1)) << 32;
  }
  // Simulate two's complement. MSVC dislikes "-raw".
  return x->sign() ? ((~raw) + 1u) : raw;
}

int64_t BigInt::AsInt64(bool* lossless) {
  uint64_t raw = MutableBigInt::GetRawBits(this, lossless);
  int64_t result = static_cast<int64_t>(raw);
  if (lossless != nullptr && (result < 0) != sign()) *lossless = false;
  return result;
}

uint64_t BigInt::AsUint64(bool* lossless) {
  uint64_t result = MutableBigInt::GetRawBits(this, lossless);
  if (lossless != nullptr && sign()) *lossless = false;
  return result;
}

void MutableBigInt::set_64_bits(uint64_t bits) {
  static_assert(kDigitBits == 64 || kDigitBits == 32);
  if (kDigitBits == 64) {
    set_digit(0, static_cast<digit_t>(bits));
  } else {
    set_digit(0, static_cast<digit_t>(bits & 0xFFFFFFFFu));
    set_digit(1, static_cast<digit_t>(bits >> 32));
  }
}

#ifdef OBJECT_PRINT
void BigIntBase::BigIntBasePrint(std::ostream& os) {
  DisallowGarbageCollection no_gc;
  PrintHeader(os, "BigInt");
  uint32_t len = length();
  os << "\n- length: " << len;
  os << "\n- sign: " << sign();
  if (len > 0) {
    os << "\n- digits:";
    for (uint32_t i = 0; i < len; i++) {
      os << "\n    0x" << std::hex << digit(i);
    }
  }
  os << std::dec << "\n";
}
#endif  // OBJECT_PRINT

void MutableBigInt_AbsoluteAddAndCanonicalize(Address result_addr,
                                              Address x_addr, Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::Add(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

int32_t MutableBigInt_AbsoluteCompare(Address x_addr, Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));

  return bigint::Compare(x->digits(), y->digits());
}

void MutableBigInt_AbsoluteSubAndCanonicalize(Address result_addr,
                                              Address x_addr, Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::Subtract(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

// Returns 0 if it succeeded to obtain the result of multiplication.
// Returns 1 if the computation is interrupted.
int32_t MutableBigInt_AbsoluteMulAndCanonicalize(Address result_addr,
                                                 Address x_addr,
                                                 Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  Isolate* isolate;
  if (!GetIsolateFromHeapObject(x, &isolate)) {
    // We should always get the isolate from the BigInt.
    UNREACHABLE();
  }

  bigint::Status status = isolate->bigint_processor()->Multiply(
      result->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    return 1;
  }

  MutableBigInt::Canonicalize(result);
  return 0;
}

int32_t MutableBigInt_AbsoluteDivAndCanonicalize(Address result_addr,
                                                 Address x_addr,
                                                 Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));
  DCHECK_GE(result->length(),
            bigint::DivideResultLength(x->digits(), y->digits()));

  Isolate* isolate;
  if (!GetIsolateFromHeapObject(x, &isolate)) {
    // We should always get the isolate from the BigInt.
    UNREACHABLE();
  }

  bigint::Status status = isolate->bigint_processor()->Divide(
      result->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    return 1;
  }

  MutableBigInt::Canonicalize(result);
  return 0;
}

int32_t MutableBigInt_AbsoluteModAndCanonicalize(Address result_addr,
                                                 Address x_addr,
                                                 Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  Isolate* isolate;
  if (!GetIsolateFromHeapObject(x, &isolate)) {
    // We should always get the isolate from the BigInt.
    UNREACHABLE();
  }

  bigint::Status status = isolate->bigint_processor()->Modulo(
      result->rw_digits(), x->digits(), y->digits());
  if (status == bigint::Status::kInterrupted) {
    return 1;
  }

  MutableBigInt::Canonicalize(result);
  return 0;
}

void MutableBigInt_BitwiseAndPosPosAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseAnd_PosPos(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseAndNegNegAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseAnd_NegNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseAndPosNegAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseAnd_PosNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseOrPosPosAndCanonicalize(Address result_addr,
                                                  Address x_addr,
                                                  Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseOr_PosPos(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseOrNegNegAndCanonicalize(Address result_addr,
                                                  Address x_addr,
                                                  Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseOr_NegNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseOrPosNegAndCanonicalize(Address result_addr,
                                                  Address x_addr,
                                                  Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseOr_PosNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseXorPosPosAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseXor_PosPos(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseXorNegNegAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseXor_NegNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_BitwiseXorPosNegAndCanonicalize(Address result_addr,
                                                   Address x_addr,
                                                   Address y_addr) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<BigInt> y = Cast<BigInt>(Tagged<Object>(y_addr));
  Tagged<MutableBigInt> result =
      Cast<MutableBigInt>(Tagged<Object>(result_addr));

  bigint::BitwiseXor_PosNeg(result->rw_digits(), x->digits(), y->digits());
  MutableBigInt::Canonicalize(result);
}

void MutableBigInt_LeftShiftAndCanonicalize(Address result_addr, Address x_addr,
                                            intptr_t shift) {
  Tagged<BigInt> x = Cast<BigInt>(Tagged<Object>(x_addr));
  Tagged<MutableBigInt> result =
     
"""


```