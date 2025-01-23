Response:
The user wants me to analyze a C++ header file from the V8 JavaScript engine, specifically `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h`.

Here's a breakdown of the request and how I'll address it:

1. **List the functionalities:** I need to go through the provided code snippet and identify what each function (marked with `REDUCE`) does. These functions seem to be related to lowering high-level operations into machine-level instructions within the Turboshaft compiler.

2. **.tq extension:** Check if the file name ends with `.tq`. Based on the provided information, this indicates a Torque source file. In this case, it doesn't, so it's not a Torque file.

3. **Relationship to JavaScript:**  If a function's purpose is related to a JavaScript feature, provide a JavaScript example. This will involve understanding the semantics of the C++ code and mapping them back to JavaScript.

4. **Code logic reasoning (input/output):** For functions with clear logic, I need to provide a hypothetical input and the expected output. This will demonstrate the function's behavior.

5. **Common programming errors:**  Identify potential programming errors that might relate to the functionalities described in the code.

6. **Summary of functionalities:**  Provide a concise summary of the overall purpose of the code snippet.

Let's go through the code and analyze each `REDUCE` function:

*   `FillNonArrayBufferElements`:  Fills elements of a non-array buffer with a specific value (likely `undefined` or `the_hole`).
*   `DoubleArrayMinMax`: Finds the minimum or maximum value in a `Float64Array`.
*   `LoadFieldByIndex`: Loads a field from an object by its index, handling both in-object and out-of-object properties, including mutable double fields.
*   `WordBinopDeoptOnOverflow`: Performs binary operations on word-sized integers, with deoptimization if overflow occurs. It handles various operations like addition, subtraction, multiplication, division, and modulo, considering signed and unsigned variants, and checks for `-0`.
*   `BigIntBinop`: Performs binary operations on BigInts, calling the appropriate built-in functions and handling potential exceptions.
*   `BigIntComparison`: Compares two BigInts using built-in functions.
*   `BigIntUnary`: Performs unary operations on BigInts (currently only negation).
*   `StringAt`: Retrieves a character code or code point from a string at a given position, handling different string representations (SeqString, ExternalString, ConsString, SlicedString, ThinString).
*   `StringLength`: Gets the length of a string.
*   `StringIndexOf`: Finds the index of a substring within a string.
*   `StringFromCodePointAt`: Creates a string from the code point at a given index.
*   `StringToCaseIntl`: Converts a string to lowercase or uppercase using internationalization rules.
*   `StringSubstring`: Extracts a substring from a string.
*   `StringConcat`: Concatenates two strings.
*   `StringComparison`: Compares two strings for equality, less than, or less than or equal to.
*   `ArgumentsLength`: Calculates the length of the arguments object or the rest parameters.

Now, let's formulate the response.
这是 `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` 文件的第三部分代码片段。它定义了一系列 `REDUCE` 函数，这些函数负责将 Turboshaft 图中的高级操作降低到更接近机器级别的操作。这些操作涵盖了数组操作、数值运算、字符串操作、BigInt 操作以及与函数调用参数相关的操作。

**功能列举:**

1. **`FillNonArrayBufferElements`**:  用特定的值（通常是 "the hole"）填充非数组缓冲区的元素。这通常用于初始化或清除数组的某些部分。

2. **`DoubleArrayMinMax`**:  计算 `Float64Array` 中元素的最小值或最大值。

3. **`LoadFieldByIndex`**:  根据索引加载对象的字段。这个函数需要处理内联属性和外部属性，并且还要区分是否是可变的 double 类型字段。

4. **`WordBinopDeoptOnOverflow`**:  执行字长（Word）的二元运算，并在发生溢出时触发反优化（deoptimization）。支持有符号加法、减法、乘法、除法和取模运算，并能检查负零。

5. **`BigIntBinop`**:  执行 BigInt 类型的二元运算，例如加法、减法、按位与、按位异或、左移、算术右移、乘法、除法和取模。它会调用相应的内置函数，并检查可能出现的异常情况（例如 BigInt 过大或除零）。

6. **`BigIntComparison`**:  比较两个 BigInt 类型的值，判断是否相等、小于或小于等于。

7. **`BigIntUnary`**:  执行 BigInt 类型的一元运算，目前只实现了取负运算。

8. **`StringAt`**:  获取字符串在指定位置的字符码或 Unicode 码点。它需要处理多种字符串表示形式（例如 SeqString, ExternalString, ConsString, SlicedString, ThinString）。

9. **`StringLength`**:  获取字符串的长度。

10. **`StringIndexOf`**:  查找子字符串在字符串中的索引。

11. **`StringFromCodePointAt`**:  根据给定的码点创建包含该码点的字符串。

12. **`StringToCaseIntl`**:  使用国际化规则将字符串转换为小写或大写。

13. **`StringSubstring`**:  提取字符串的子字符串。

14. **`StringConcat`**:  连接两个字符串。

15. **`StringComparison`**:  比较两个字符串是否相等、小于或小于等于。

16. **`ArgumentsLength`**:  获取函数调用时 `arguments` 对象的长度或者剩余参数（rest parameters）的长度。

17. **`NewArgum`**:  (代码片段不完整，只显示了函数名的一部分) 可能是用于创建 `arguments` 对象相关的操作。

**v8 torque 源代码判断:**

`v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` 以 `.h` 结尾，因此它不是一个 v8 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 javascript 的功能关系及举例:**

这些 `REDUCE` 函数的功能直接对应了 JavaScript 中的各种操作。以下是一些 JavaScript 示例：

1. **`FillNonArrayBufferElements`**:  虽然不能直接在 JavaScript 中调用，但类似的行为发生在数组的初始化或使用 `Array.prototype.fill()` 方法时：

    ```javascript
    const arr = new Array(5); // 创建一个包含 5 个空位的数组
    arr.fill(undefined);     // 用 undefined 填充所有空位
    ```

2. **`DoubleArrayMinMax`**:

    ```javascript
    const arr = new Float64Array([3.14, 1.59, 2.65]);
    const min = Math.min(...arr); // 1.59
    const max = Math.max(...arr); // 3.14
    ```

3. **`LoadFieldByIndex`**:  访问对象的属性：

    ```javascript
    const obj = { a: 10, b: "hello" };
    const valueOfA = obj.a; // 对应内联属性
    const propertyName = 'b';
    const valueOfB = obj[propertyName]; // 对应外部属性
    ```

4. **`WordBinopDeoptOnOverflow`**:  JavaScript 的数值运算，如果超出安全整数范围，可能会导致精度损失或溢出，在 V8 内部会进行处理和优化。

    ```javascript
    const maxSafeInt = Number.MAX_SAFE_INTEGER;
    const result = maxSafeInt + 1; // 仍然可以表示为一个 Number，但可能超出安全范围
    const overflow = maxSafeInt + maxSafeInt; // 结果会超出 Number 的表示范围，可能导致精度问题
    ```

5. **`BigIntBinop`**:

    ```javascript
    const bigIntA = 9007199254740991n;
    const bigIntB = 1n;
    const sum = bigIntA + bigIntB; // 9007199254740992n
    ```

6. **`BigIntComparison`**:

    ```javascript
    const bigIntX = 10n;
    const bigIntY = 20n;
    const isEqual = bigIntX === bigIntY;       // false
    const isLessThan = bigIntX < bigIntY;    // true
    ```

7. **`BigIntUnary`**:

    ```javascript
    const bigIntZ = 5n;
    const negativeZ = -bigIntZ; // -5n
    ```

8. **`StringAt`**:

    ```javascript
    const str = "hello";
    const charCode = str.charCodeAt(0);   // 104 ('h')
    const codePoint = str.codePointAt(0); // 104 ('h')
    ```

9. **`StringLength`**:

    ```javascript
    const text = "world";
    const length = text.length; // 5
    ```

10. **`StringIndexOf`**:

    ```javascript
    const message = "hello world";
    const index = message.indexOf("world"); // 6
    ```

11. **`StringFromCodePointAt`**:

    ```javascript
    const code = 65;
    const char = String.fromCodePoint(code); // "A"
    ```

12. **`StringToCaseIntl`**:

    ```javascript
    const turkishText = "IZMIR";
    const lowerCase = turkishText.toLocaleLowerCase('tr-TR'); // "izmir" (在土耳其语环境下 'I' 的小写是 'ı')
    ```

13. **`StringSubstring`**:

    ```javascript
    const phrase = "the quick brown fox";
    const sub = phrase.substring(4, 9); // "quick"
    ```

14. **`StringConcat`**:

    ```javascript
    const greeting = "Hello, ";
    const name = "World!";
    const message = greeting + name; // "Hello, World!"
    ```

15. **`StringComparison`**:

    ```javascript
    const str1 = "apple";
    const str2 = "banana";
    const isEqual = str1 === str2;           // false
    const isLessThan = str1 < str2;        // true
    ```

16. **`ArgumentsLength`**:

    ```javascript
    function myFunction(a, b, ...rest) {
      console.log(arguments.length); // 输出调用时传递的参数个数
      console.log(rest.length);      // 输出剩余参数的个数
    }

    myFunction(1, 2, 3, 4, 5); // arguments.length: 5, rest.length: 3
    ```

**代码逻辑推理 (假设输入与输出):**

**`DoubleArrayMinMax` 示例:**

*   **假设输入:**
    *   `array`:  一个 `Float64Array`，例如 `[1.0, 5.0, 2.5, 8.0]`
    *   `kind`: `DoubleArrayMinMaxOp::Kind::kMax` (查找最大值)

*   **预期输出:**  表示数值 `8.0` 的 `OpIndex`。

**`WordBinopDeoptOnOverflow` 示例:**

*   **假设输入:**
    *   `left`: 表示整数 `2147483647` ( `Number.MAX_SAFE_INTEGER` 附近的 32 位有符号整数最大值) 的 `V<Word32>`
    *   `right`: 表示整数 `1` 的 `V<Word32>`
    *   `frame_state`: 当前帧状态
    *   `kind`: `WordBinopDeoptOnOverflowOp::Kind::kSignedAdd`
    *   `rep`: `WordRepresentation::Word32()`
    *   `feedback`:  反馈信息
    *   `mode`: `CheckForMinusZeroMode::kDontCheckForMinusZero`

*   **预期输出:**  由于加法会导致溢出，该函数会触发反优化，不会返回一个正常的计算结果。在 Turboshaft 编译器中，这会改变控制流，而不是直接返回一个值。

**用户常见的编程错误:**

1. **数值溢出:** 在 JavaScript 中进行大数值运算时，可能会超出 `Number` 类型的安全整数范围，导致精度丢失。BigInt 的引入部分解决了这个问题，但旧代码或不使用 BigInt 的场景仍然存在风险。

    ```javascript
    let a = Number.MAX_SAFE_INTEGER;
    let b = a + 1; // b 的值可能不符合预期，因为超出了安全范围
    ```

2. **字符串索引越界:** 访问字符串时，如果索引超出字符串的长度范围，会返回 `undefined`，但不会抛出错误。这可能导致程序行为不符合预期。

    ```javascript
    const text = "hello";
    const char = text[10]; // char 的值为 undefined
    ```

3. **类型错误:**  对预期为特定类型的变量进行错误的操作，例如将字符串传递给需要数字的函数。

    ```javascript
    function add(a, b) {
      return a + b;
    }
    const result = add(5, "10"); // JavaScript 会进行类型转换，结果可能是 "510" 而不是 15
    ```

4. **BigInt 的不当使用:**  BigInt 不能与 Number 类型直接进行算术运算，需要显式转换，否则会抛出 `TypeError`。

    ```javascript
    const big = 10n;
    const num = 5;
    // const sum = big + num; // TypeError: Cannot mix BigInt and other types
    const sum = big + BigInt(num); // 正确的做法
    ```

**功能归纳:**

总而言之，这段代码片段是 V8 Turboshaft 编译器中用于将高级操作转换为更底层的、接近机器级别的操作的关键部分。它定义了针对数组、数值、字符串和 BigInt 等数据类型的各种操作的降低（lowering）逻辑，并且考虑了性能优化和错误处理（如溢出反优化）。这些 `REDUCE` 函数是编译器将 JavaScript 代码翻译成高效机器码过程中的重要组成部分。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
ScopedVar<WordPtr> index(this, 0);

    WHILE(__ UintPtrLessThan(index, length)) {
      __ StoreNonArrayBufferElement(array, access, index, the_hole_value);
      // Advance the {index}.
      index = __ WordPtrAdd(index, 1);
    }

    GOTO(done, array);

    BIND(done, result);
    return result;
  }

  OpIndex REDUCE(DoubleArrayMinMax)(V<Object> array,
                                    DoubleArrayMinMaxOp::Kind kind) {
    DCHECK(kind == DoubleArrayMinMaxOp::Kind::kMin ||
           kind == DoubleArrayMinMaxOp::Kind::kMax);
    const bool is_max = kind == DoubleArrayMinMaxOp::Kind::kMax;

    // Iterate the elements and find the result.
    V<WordPtr> array_length =
        __ ChangeInt32ToIntPtr(__ UntagSmi(__ template LoadField<Smi>(
            array, AccessBuilder::ForJSArrayLength(
                       ElementsKind::PACKED_DOUBLE_ELEMENTS))));
    V<Object> elements = __ template LoadField<Object>(
        array, AccessBuilder::ForJSObjectElements());

    ScopedVar<Float64> result(this, is_max ? -V8_INFINITY : V8_INFINITY);
    ScopedVar<WordPtr> index(this, 0);

    WHILE(__ UintPtrLessThan(index, array_length)) {
      V<Float64> element = __ template LoadNonArrayBufferElement<Float64>(
          elements, AccessBuilder::ForFixedDoubleArrayElement(), index);

      result = is_max ? __ Float64Max(result, element)
                      : __ Float64Min(result, element);
      index = __ WordPtrAdd(index, 1);
    }

    return __ ConvertFloat64ToNumber(result,
                                     CheckForMinusZeroMode::kCheckForMinusZero);
  }

  OpIndex REDUCE(LoadFieldByIndex)(V<Object> object, V<Word32> field_index) {
    // Index encoding (see `src/objects/field-index-inl.h`):
    // For efficiency, the LoadByFieldIndex instruction takes an index that is
    // optimized for quick access. If the property is inline, the index is
    // positive. If it's out-of-line, the encoded index is -raw_index - 1 to
    // disambiguate the zero out-of-line index from the zero inobject case.
    // The index itself is shifted up by one bit, the lower-most bit
    // signifying if the field is a mutable double box (1) or not (0).
    V<WordPtr> index = __ ChangeInt32ToIntPtr(field_index);

    Label<> double_field(this);
    Label<Object> done(this);

    // Check if field is a mutable double field.
    GOTO_IF(
        UNLIKELY(__ Word32Equal(
            __ Word32BitwiseAnd(__ TruncateWordPtrToWord32(index), 0x1), 0x1)),
        double_field);

    {
      // The field is a proper Tagged field on {object}. The {index} is
      // shifted to the left by one in the code below.

      // Check if field is in-object or out-of-object.
      IF (__ IntPtrLessThan(index, 0)) {
        // The field is located in the properties backing store of {object}.
        // The {index} is equal to the negated out of property index plus 1.
        V<Object> properties = __ template LoadField<Object>(
            object, AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer());

        V<WordPtr> out_of_object_index = __ WordPtrSub(0, index);
        V<Object> result =
            __ Load(properties, out_of_object_index,
                    LoadOp::Kind::Aligned(BaseTaggedness::kTaggedBase),
                    MemoryRepresentation::AnyTagged(),
                    OFFSET_OF_DATA_START(FixedArray) - kTaggedSize,
                    kTaggedSizeLog2 - 1);
        GOTO(done, result);
      } ELSE {
        // This field is located in the {object} itself.
        V<Object> result = __ Load(
            object, index, LoadOp::Kind::Aligned(BaseTaggedness::kTaggedBase),
            MemoryRepresentation::AnyTagged(), JSObject::kHeaderSize,
            kTaggedSizeLog2 - 1);
        GOTO(done, result);
      }
    }

    if (BIND(double_field)) {
      // If field is a Double field, either unboxed in the object on 64 bit
      // architectures, or a mutable HeapNumber.
      V<WordPtr> double_index = __ WordPtrShiftRightArithmetic(index, 1);
      Label<Object> loaded_field(this);

      // Check if field is in-object or out-of-object.
      IF (__ IntPtrLessThan(double_index, 0)) {
        V<Object> properties = __ template LoadField<Object>(
            object, AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer());

        V<WordPtr> out_of_object_index = __ WordPtrSub(0, double_index);
        V<Object> result = __ Load(
            properties, out_of_object_index,
            LoadOp::Kind::Aligned(BaseTaggedness::kTaggedBase),
            MemoryRepresentation::AnyTagged(),
            OFFSET_OF_DATA_START(FixedArray) - kTaggedSize, kTaggedSizeLog2);
        GOTO(loaded_field, result);
      } ELSE {
        // The field is located in the {object} itself.
        V<Object> result =
            __ Load(object, double_index,
                    LoadOp::Kind::Aligned(BaseTaggedness::kTaggedBase),
                    MemoryRepresentation::AnyTagged(), JSObject::kHeaderSize,
                    kTaggedSizeLog2);
        GOTO(loaded_field, result);
      }

      if (BIND(loaded_field, field)) {
        // We may have transitioned in-place away from double, so check that
        // this is a HeapNumber -- otherwise the load is fine and we don't need
        // to copy anything anyway.
        GOTO_IF(__ ObjectIsSmi(field), done, field);
        V<Map> map = __ LoadMapField(field);
        GOTO_IF_NOT(
            __ TaggedEqual(map, __ HeapConstant(factory_->heap_number_map())),
            done, field);

        V<Float64> value = __ LoadHeapNumberValue(V<HeapNumber>::Cast(field));
        GOTO(done, AllocateHeapNumber(value));
      }
    }

    BIND(done, result);
    return result;
  }

  V<Word> REDUCE(WordBinopDeoptOnOverflow)(
      V<Word> left, V<Word> right, V<FrameState> frame_state,
      WordBinopDeoptOnOverflowOp::Kind kind, WordRepresentation rep,
      FeedbackSource feedback, CheckForMinusZeroMode mode) {
    switch (kind) {
      case WordBinopDeoptOnOverflowOp::Kind::kSignedAdd: {
        DCHECK_EQ(mode, CheckForMinusZeroMode::kDontCheckForMinusZero);
        V<Tuple<Word, Word32>> result =
            __ IntAddCheckOverflow(left, right, rep);

        V<Word32> overflow = __ template Projection<1>(result);
        __ DeoptimizeIf(overflow, frame_state, DeoptimizeReason::kOverflow,
                        feedback);
        return __ template Projection<0>(result, rep);
      }
      case WordBinopDeoptOnOverflowOp::Kind::kSignedSub: {
        DCHECK_EQ(mode, CheckForMinusZeroMode::kDontCheckForMinusZero);
        V<Tuple<Word, Word32>> result =
            __ IntSubCheckOverflow(left, right, rep);

        V<Word32> overflow = __ template Projection<1>(result);
        __ DeoptimizeIf(overflow, frame_state, DeoptimizeReason::kOverflow,
                        feedback);
        return __ template Projection<0>(result, rep);
      }
      case WordBinopDeoptOnOverflowOp::Kind::kSignedMul:
        if (rep == WordRepresentation::Word32()) {
          V<Word32> left_w32 = V<Word32>::Cast(left);
          V<Word32> right_w32 = V<Word32>::Cast(right);
          V<Tuple<Word32, Word32>> result =
              __ Int32MulCheckOverflow(left_w32, right_w32);
          V<Word32> overflow = __ template Projection<1>(result);
          __ DeoptimizeIf(overflow, frame_state, DeoptimizeReason::kOverflow,
                          feedback);
          V<Word32> value = __ template Projection<0>(result);

          if (mode == CheckForMinusZeroMode::kCheckForMinusZero) {
            IF (__ Word32Equal(value, 0)) {
              __ DeoptimizeIf(
                  __ Int32LessThan(__ Word32BitwiseOr(left_w32, right_w32), 0),
                  frame_state, DeoptimizeReason::kMinusZero, feedback);
            }
          }

          return value;
        } else {
          DCHECK_EQ(rep, WordRepresentation::Word64());
          DCHECK_EQ(mode, CheckForMinusZeroMode::kDontCheckForMinusZero);
          V<Tuple<Word64, Word32>> result = __ Int64MulCheckOverflow(
              V<Word64>::Cast(left), V<Word64>::Cast(right));

          V<Word32> overflow = __ template Projection<1>(result);
          __ DeoptimizeIf(overflow, frame_state, DeoptimizeReason::kOverflow,
                          feedback);
          return __ template Projection<0>(result);
        }
      case WordBinopDeoptOnOverflowOp::Kind::kSignedDiv:
        if (rep == WordRepresentation::Word32()) {
          V<Word32> left_w32 = V<Word32>::Cast(left);
          V<Word32> right_w32 = V<Word32>::Cast(right);
          // Check if the {rhs} is a known power of two.
          int32_t divisor;
          if (__ matcher().MatchPowerOfTwoWord32Constant(right_w32, &divisor)) {
            // Since we know that {rhs} is a power of two, we can perform a fast
            // check to see if the relevant least significant bits of the {lhs}
            // are all zero, and if so we know that we can perform a division
            // safely (and fast by doing an arithmetic - aka sign preserving -
            // right shift on {lhs}).
            V<Word32> check =
                __ Word32Equal(__ Word32BitwiseAnd(left_w32, divisor - 1), 0);
            __ DeoptimizeIfNot(check, frame_state,
                               DeoptimizeReason::kLostPrecision, feedback);
            return __ Word32ShiftRightArithmeticShiftOutZeros(
                left_w32, base::bits::WhichPowerOfTwo(divisor));
          } else {
            Label<Word32> done(this);

            // Check if {rhs} is positive (and not zero).
            IF (__ Int32LessThan(0, right_w32)) {
              GOTO(done, __ Int32Div(left_w32, right_w32));
            } ELSE {
              // Check if {rhs} is zero.
              __ DeoptimizeIf(__ Word32Equal(right_w32, 0), frame_state,
                              DeoptimizeReason::kDivisionByZero, feedback);

              // Check if {lhs} is zero, as that would produce minus zero.
              __ DeoptimizeIf(__ Word32Equal(left_w32, 0), frame_state,
                              DeoptimizeReason::kMinusZero, feedback);

              // Check if {lhs} is kMinInt and {rhs} is -1, in which case we'd
              // have to return -kMinInt, which is not representable as Word32.
              IF (UNLIKELY(__ Word32Equal(left_w32, kMinInt))) {
                __ DeoptimizeIf(__ Word32Equal(right_w32, -1), frame_state,
                                DeoptimizeReason::kOverflow, feedback);
              }

              GOTO(done, __ Int32Div(left_w32, right_w32));
            }

            BIND(done, value);
            V<Word32> lossless =
                __ Word32Equal(left_w32, __ Word32Mul(value, right_w32));
            __ DeoptimizeIfNot(lossless, frame_state,
                               DeoptimizeReason::kLostPrecision, feedback);
            return value;
          }
        } else {
          DCHECK_EQ(rep, WordRepresentation::Word64());
          DCHECK(Is64());
          V<Word64> left_w64 = V<Word64>::Cast(left);
          V<Word64> right_w64 = V<Word64>::Cast(right);

          __ DeoptimizeIf(__ Word64Equal(right_w64, 0), frame_state,
                          DeoptimizeReason::kDivisionByZero, feedback);
          // Check if {lhs} is kMinInt64 and {rhs} is -1, in which case we'd
          // have to return -kMinInt64, which is not representable as Word64.
          IF (UNLIKELY(__ Word64Equal(left_w64,
                                      std::numeric_limits<int64_t>::min()))) {
            __ DeoptimizeIf(__ Word64Equal(right_w64, int64_t{-1}), frame_state,
                            DeoptimizeReason::kOverflow, feedback);
          }

          return __ Int64Div(left_w64, right_w64);
        }
      case WordBinopDeoptOnOverflowOp::Kind::kSignedMod:
        if (rep == WordRepresentation::Word32()) {
          V<Word32> left_w32 = V<Word32>::Cast(left);
          V<Word32> right_w32 = V<Word32>::Cast(right);
          // General case for signed integer modulus, with optimization for
          // (unknown) power of 2 right hand side.
          //
          //   if rhs <= 0 then
          //     rhs = -rhs
          //     deopt if rhs == 0
          //   if lhs < 0 then
          //     let lhs_abs = -lhs in
          //     let res = lhs_abs % rhs in
          //     deopt if res == 0
          //     -res
          //   else
          //     let msk = rhs - 1 in
          //     if rhs & msk == 0 then
          //       lhs & msk
          //     else
          //       lhs % rhs
          //
          Label<Word32> rhs_checked(this);
          Label<Word32> done(this);

          // Check if {rhs} is not strictly positive.
          IF (__ Int32LessThanOrEqual(right_w32, 0)) {
            // Negate {rhs}, might still produce a negative result in case of
            // -2^31, but that is handled safely below.
            V<Word32> temp = __ Word32Sub(0, right_w32);

            // Ensure that {rhs} is not zero, otherwise we'd have to return NaN.
            __ DeoptimizeIfNot(temp, frame_state,
                               DeoptimizeReason::kDivisionByZero, feedback);
            GOTO(rhs_checked, temp);
          } ELSE {
            GOTO(rhs_checked, right_w32);
          }

          BIND(rhs_checked, rhs_value);

          IF (__ Int32LessThan(left_w32, 0)) {
            // The {lhs} is a negative integer. This is very unlikely and
            // we intentionally don't use the BuildUint32Mod() here, which
            // would try to figure out whether {rhs} is a power of two,
            // since this is intended to be a slow-path.
            V<Word32> temp = __ Uint32Mod(__ Word32Sub(0, left_w32), rhs_value);

            // Check if we would have to return -0.
            __ DeoptimizeIf(__ Word32Equal(temp, 0), frame_state,
                            DeoptimizeReason::kMinusZero, feedback);
            GOTO(done, __ Word32Sub(0, temp));
          } ELSE {
            // The {lhs} is a non-negative integer.
            GOTO(done, BuildUint32Mod(left_w32, rhs_value));
          }

          BIND(done, result);
          return result;
        } else {
          DCHECK_EQ(rep, WordRepresentation::Word64());
          DCHECK(Is64());
          V<Word64> left_w64 = V<Word64>::Cast(left);
          V<Word64> right_w64 = V<Word64>::Cast(right);

          __ DeoptimizeIf(__ Word64Equal(right_w64, 0), frame_state,
                          DeoptimizeReason::kDivisionByZero, feedback);

          // While the mod-result cannot overflow, the underlying instruction is
          // `idiv` and will trap when the accompanying div-result overflows.
          IF (UNLIKELY(__ Word64Equal(left_w64,
                                      std::numeric_limits<int64_t>::min()))) {
            __ DeoptimizeIf(__ Word64Equal(right_w64, int64_t{-1}), frame_state,
                            DeoptimizeReason::kOverflow, feedback);
          }

          return __ Int64Mod(left_w64, right_w64);
        }
      case WordBinopDeoptOnOverflowOp::Kind::kUnsignedDiv: {
        DCHECK_EQ(rep, WordRepresentation::Word32());
        V<Word32> left_w32 = V<Word32>::Cast(left);
        V<Word32> right_w32 = V<Word32>::Cast(right);

        // Check if the {rhs} is a known power of two.
        int32_t divisor;
        if (__ matcher().MatchPowerOfTwoWord32Constant(right_w32, &divisor)) {
          // Since we know that {rhs} is a power of two, we can perform a fast
          // check to see if the relevant least significant bits of the {lhs}
          // are all zero, and if so we know that we can perform a division
          // safely (and fast by doing a logical - aka zero extending - right
          // shift on {lhs}).
          V<Word32> check =
              __ Word32Equal(__ Word32BitwiseAnd(left_w32, divisor - 1), 0);
          __ DeoptimizeIfNot(check, frame_state,
                             DeoptimizeReason::kLostPrecision, feedback);
          return __ Word32ShiftRightLogical(
              left_w32, base::bits::WhichPowerOfTwo(divisor));
        } else {
          // Ensure that {rhs} is not zero, otherwise we'd have to return NaN.
          __ DeoptimizeIf(__ Word32Equal(right_w32, 0), frame_state,
                          DeoptimizeReason::kDivisionByZero, feedback);

          // Perform the actual unsigned integer division.
          V<Word32> value = __ Uint32Div(left_w32, right_w32);

          // Check if the remainder is non-zero.
          V<Word32> lossless =
              __ Word32Equal(left_w32, __ Word32Mul(right_w32, value));
          __ DeoptimizeIfNot(lossless, frame_state,
                             DeoptimizeReason::kLostPrecision, feedback);
          return value;
        }
      }
      case WordBinopDeoptOnOverflowOp::Kind::kUnsignedMod: {
        DCHECK_EQ(rep, WordRepresentation::Word32());
        V<Word32> left_w32 = V<Word32>::Cast(left);
        V<Word32> right_w32 = V<Word32>::Cast(right);

        // Ensure that {rhs} is not zero, otherwise we'd have to return NaN.
        __ DeoptimizeIf(__ Word32Equal(right_w32, 0), frame_state,
                        DeoptimizeReason::kDivisionByZero, feedback);

        return BuildUint32Mod(left_w32, right_w32);
      }
    }
  }

  V<BigInt> REDUCE(BigIntBinop)(V<BigInt> left, V<BigInt> right,
                                V<FrameState> frame_state,
                                BigIntBinopOp::Kind kind) {
    const Builtin builtin = GetBuiltinForBigIntBinop(kind);
    switch (kind) {
      case BigIntBinopOp::Kind::kAdd:
      case BigIntBinopOp::Kind::kSub:
      case BigIntBinopOp::Kind::kBitwiseAnd:
      case BigIntBinopOp::Kind::kBitwiseXor:
      case BigIntBinopOp::Kind::kShiftLeft:
      case BigIntBinopOp::Kind::kShiftRightArithmetic: {
        V<Numeric> result = CallBuiltinForBigIntOp(builtin, {left, right});

        // Check for exception sentinel: Smi 0 is returned to signal
        // BigIntTooBig.
        __ DeoptimizeIf(__ ObjectIsSmi(result), frame_state,
                        DeoptimizeReason::kBigIntTooBig, FeedbackSource{});
        return V<BigInt>::Cast(result);
      }
      case BigIntBinopOp::Kind::kMul:
      case BigIntBinopOp::Kind::kDiv:
      case BigIntBinopOp::Kind::kMod: {
        V<Numeric> result = CallBuiltinForBigIntOp(builtin, {left, right});

        // Check for exception sentinel: Smi 1 is returned to signal
        // TerminationRequested.
        IF (UNLIKELY(__ TaggedEqual(result, __ TagSmi(1)))) {
          __ CallRuntime_TerminateExecution(isolate_, frame_state,
                                            __ NoContextConstant());
        }

        // Check for exception sentinel: Smi 0 is returned to signal
        // BigIntTooBig or DivisionByZero.
        __ DeoptimizeIf(__ ObjectIsSmi(result), frame_state,
                        kind == BigIntBinopOp::Kind::kMul
                            ? DeoptimizeReason::kBigIntTooBig
                            : DeoptimizeReason::kDivisionByZero,
                        FeedbackSource{});
        return V<BigInt>::Cast(result);
      }
      case BigIntBinopOp::Kind::kBitwiseOr: {
        return CallBuiltinForBigIntOp(builtin, {left, right});
      }
      default:
        UNIMPLEMENTED();
    }
    UNREACHABLE();
  }

  V<Boolean> REDUCE(BigIntComparison)(V<BigInt> left, V<BigInt> right,
                                      BigIntComparisonOp::Kind kind) {
    switch (kind) {
      case BigIntComparisonOp::Kind::kEqual:
        return CallBuiltinForBigIntOp(Builtin::kBigIntEqual, {left, right});
      case BigIntComparisonOp::Kind::kLessThan:
        return CallBuiltinForBigIntOp(Builtin::kBigIntLessThan, {left, right});
      case BigIntComparisonOp::Kind::kLessThanOrEqual:
        return CallBuiltinForBigIntOp(Builtin::kBigIntLessThanOrEqual,
                                      {left, right});
    }
  }

  V<BigInt> REDUCE(BigIntUnary)(V<BigInt> input, BigIntUnaryOp::Kind kind) {
    DCHECK_EQ(kind, BigIntUnaryOp::Kind::kNegate);
    return CallBuiltinForBigIntOp(Builtin::kBigIntUnaryMinus, {input});
  }

  V<Word32> REDUCE(StringAt)(V<String> string, V<WordPtr> pos,
                             StringAtOp::Kind kind) {
    if (kind == StringAtOp::Kind::kCharCode) {
      Label<Word32> done(this);

      if (const ConstantOp* cst =
              __ matcher().template TryCast<ConstantOp>(string);
          cst && cst->kind == ConstantOp::Kind::kHeapObject) {
        // For constant SeqString, we have a fast-path that doesn't run through
        // the loop. It requires fewer loads (we only load the map once, but not
        // the instance type), uses static 1/2-byte, and only uses a single
        // comparison to check that the string has indeed the correct SeqString
        // map.
        UnparkedScopeIfNeeded unpark(broker_);
        HeapObjectRef ref = MakeRef(broker_, cst->handle());
        if (ref.IsString()) {
          StringRef str = ref.AsString();
          if (str.IsSeqString()) {
            V<Map> dynamic_map = __ LoadMapField(string);
            Handle<Map> expected_map = str.map(broker_).object();
            IF (__ TaggedEqual(dynamic_map, __ HeapConstant(expected_map))) {
              bool one_byte = str.IsOneByteRepresentation();
              GOTO(done,
                   LoadFromSeqString(string, pos, __ Word32Constant(one_byte)));
            }
          }
        }
      }

      Label<> seq_string(this), external_string(this), cons_string(this),
          sliced_string(this), thin_string(this);
      // TODO(dmercadier): the runtime label should be deferred, and because
      // Labels/Blocks don't have deferred annotation, we achieve this by
      // marking all branches to this Label as UNLIKELY, but 1) it's easy to
      // forget one, and 2) it makes the code less clear: `if(x) {} else
      // if(likely(y)) {} else {}` looks like `y` is more likely than `x`, but
      // it just means that `y` is more likely than `!y`.
      Label<> runtime(this);
      // We need a loop here to properly deal with indirect strings
      // (SlicedString, ConsString and ThinString).
      LoopLabel<> loop(this);
      ScopedVar<String> receiver(this, string);
      ScopedVar<WordPtr> position(this, pos);
      GOTO(loop);

      BIND_LOOP(loop) {
        V<Map> map = __ LoadMapField(receiver);
#if V8_STATIC_ROOTS_BOOL
        V<Word32> map_bits =
            __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(map));

        using StringTypeRange =
            InstanceTypeChecker::kUniqueMapRangeOfStringType;
        // Check the string map ranges in dense increasing order, to avoid
        // needing to subtract away the lower bound.
        static_assert(StringTypeRange::kSeqString.first == 0);
        GOTO_IF(__ Uint32LessThanOrEqual(map_bits,
                                         StringTypeRange::kSeqString.second),
                seq_string);

        static_assert(StringTypeRange::kSeqString.second + Map::kSize ==
                      StringTypeRange::kExternalString.first);
        GOTO_IF(__ Uint32LessThanOrEqual(
                    map_bits, StringTypeRange::kExternalString.second),
                external_string);

        static_assert(StringTypeRange::kExternalString.second + Map::kSize ==
                      StringTypeRange::kConsString.first);
        GOTO_IF(__ Uint32LessThanOrEqual(map_bits,
                                         StringTypeRange::kConsString.second),
                cons_string);

        static_assert(StringTypeRange::kConsString.second + Map::kSize ==
                      StringTypeRange::kSlicedString.first);
        GOTO_IF(__ Uint32LessThanOrEqual(map_bits,
                                         StringTypeRange::kSlicedString.second),
                sliced_string);

        static_assert(StringTypeRange::kSlicedString.second + Map::kSize ==
                      StringTypeRange::kThinString.first);
        GOTO_IF(__ Uint32LessThanOrEqual(map_bits,
                                         StringTypeRange::kThinString.second),
                thin_string);
#else
        V<Word32> instance_type = __ LoadInstanceTypeField(map);
        V<Word32> representation =
            __ Word32BitwiseAnd(instance_type, kStringRepresentationMask);

        GOTO_IF(__ Word32Equal(representation, kSeqStringTag), seq_string);
        GOTO_IF(__ Word32Equal(representation, kExternalStringTag),
                external_string);
        GOTO_IF(__ Word32Equal(representation, kConsStringTag), cons_string);
        GOTO_IF(__ Word32Equal(representation, kSlicedStringTag),
                sliced_string);
        GOTO_IF(__ Word32Equal(representation, kThinStringTag), thin_string);
#endif

        __ Unreachable();

        if (BIND(seq_string)) {
#if V8_STATIC_ROOTS_BOOL
          V<Word32> is_one_byte = __ Word32Equal(
              __ Word32BitwiseAnd(map_bits,
                                  InstanceTypeChecker::kStringMapEncodingMask),
              InstanceTypeChecker::kOneByteStringMapBit);
#else
          V<Word32> is_one_byte = __ Word32Equal(
              __ Word32BitwiseAnd(instance_type, kStringEncodingMask),
              kOneByteStringTag);
#endif
          GOTO(done, LoadFromSeqString(receiver, position, is_one_byte));
        }

        if (BIND(external_string)) {
          // We need to bailout to the runtime for uncached external
          // strings.
#if V8_STATIC_ROOTS_BOOL
          V<Word32> is_uncached_external_string = __ Uint32LessThanOrEqual(
              __ Word32Sub(map_bits,
                           StringTypeRange::kUncachedExternalString.first),
              StringTypeRange::kUncachedExternalString.second -
                  StringTypeRange::kUncachedExternalString.first);
#else
          V<Word32> is_uncached_external_string = __ Word32Equal(
              __ Word32BitwiseAnd(instance_type, kUncachedExternalStringMask),
              kUncachedExternalStringTag);
#endif
          GOTO_IF(UNLIKELY(is_uncached_external_string), runtime);

          OpIndex data = __ LoadField(
              receiver, AccessBuilder::ForExternalStringResourceData());
#if V8_STATIC_ROOTS_BOOL
          V<Word32> is_two_byte = __ Word32Equal(
              __ Word32BitwiseAnd(map_bits,
                                  InstanceTypeChecker::kStringMapEncodingMask),
              InstanceTypeChecker::kTwoByteStringMapBit);
#else
          V<Word32> is_two_byte = __ Word32Equal(
              __ Word32BitwiseAnd(instance_type, kStringEncodingMask),
              kTwoByteStringTag);
#endif
          IF (is_two_byte) {
            constexpr uint8_t twobyte_size_log2 = 1;
            V<Word32> value =
                __ Load(data, position,
                        LoadOp::Kind::Aligned(BaseTaggedness::kUntaggedBase),
                        MemoryRepresentation::Uint16(), 0, twobyte_size_log2);
            GOTO(done, value);
          } ELSE {
            constexpr uint8_t onebyte_size_log2 = 0;
            V<Word32> value =
                __ Load(data, position,
                        LoadOp::Kind::Aligned(BaseTaggedness::kUntaggedBase),
                        MemoryRepresentation::Uint8(), 0, onebyte_size_log2);
            GOTO(done, value);
          }
        }

        if (BIND(cons_string)) {
          V<String> second = __ template LoadField<String>(
              receiver, AccessBuilder::ForConsStringSecond());
          GOTO_IF_NOT(LIKELY(__ TaggedEqual(
                          second, __ HeapConstant(factory_->empty_string()))),
                      runtime);
          receiver = __ template LoadField<String>(
              receiver, AccessBuilder::ForConsStringFirst());
          GOTO(loop);
        }

        if (BIND(sliced_string)) {
          V<Smi> offset = __ template LoadField<Smi>(
              receiver, AccessBuilder::ForSlicedStringOffset());
          receiver = __ template LoadField<String>(
              receiver, AccessBuilder::ForSlicedStringParent());
          position = __ WordPtrAdd(position,
                                   __ ChangeInt32ToIntPtr(__ UntagSmi(offset)));
          GOTO(loop);
        }

        if (BIND(thin_string)) {
          receiver = __ template LoadField<String>(
              receiver, AccessBuilder::ForThinStringActual());
          GOTO(loop);
        }

        if (BIND(runtime)) {
          V<Word32> value =
              __ UntagSmi(V<Smi>::Cast(__ CallRuntime_StringCharCodeAt(
                  isolate_, __ NoContextConstant(), receiver,
                  __ TagSmi(__ TruncateWordPtrToWord32(position)))));
          GOTO(done, value);
        }
      }

      BIND(done, result);
      return result;
    } else {
      DCHECK_EQ(kind, StringAtOp::Kind::kCodePoint);
      return LoadSurrogatePairAt(string, {}, pos, UnicodeEncoding::UTF32);
    }

    UNREACHABLE();
  }

  V<Word32> REDUCE(StringLength)(V<String> string) {
    // TODO(dmercadier): Somewhere (maybe not here but instead in a new
    // SimplifiedOptimizationReducer?), constant fold StringLength(Constant).
    return __ template LoadField<Word32>(string,
                                         AccessBuilder::ForStringLength());
  }

  V<Smi> REDUCE(StringIndexOf)(V<String> string, V<String> search,
                               V<Smi> position) {
    return __ CallBuiltin_StringIndexOf(isolate_, string, search, position);
  }

  V<String> REDUCE(StringFromCodePointAt)(V<String> string, V<WordPtr> index) {
    return __ CallBuiltin_StringFromCodePointAt(isolate_, string, index);
  }

#ifdef V8_INTL_SUPPORT
  V<String> REDUCE(StringToCaseIntl)(V<String> string,
                                     StringToCaseIntlOp::Kind kind) {
    if (kind == StringToCaseIntlOp::Kind::kLower) {
      return __ CallBuiltin_StringToLowerCaseIntl(
          isolate_, __ NoContextConstant(), string);
    } else {
      DCHECK_EQ(kind, StringToCaseIntlOp::Kind::kUpper);
      return __ CallRuntime_StringToUpperCaseIntl(
          isolate_, __ NoContextConstant(), string);
    }
  }
#endif  // V8_INTL_SUPPORT

  V<String> REDUCE(StringSubstring)(V<String> string, V<Word32> start,
                                    V<Word32> end) {
    V<WordPtr> s = __ ChangeInt32ToIntPtr(start);
    V<WordPtr> e = __ ChangeInt32ToIntPtr(end);
    return __ CallBuiltin_StringSubstring(isolate_, string, s, e);
  }

  V<String> REDUCE(StringConcat)(V<Smi> length, V<String> left,
                                 V<String> right) {
    // TODO(nicohartmann@): Port StringBuilder once it is stable.
    return __ CallBuiltin_StringAdd_CheckNone(isolate_, __ NoContextConstant(),
                                              left, right);
  }

  V<Boolean> REDUCE(StringComparison)(V<String> left, V<String> right,
                                      StringComparisonOp::Kind kind) {
    switch (kind) {
      case StringComparisonOp::Kind::kEqual: {
        Label<Boolean> done(this);

        GOTO_IF(__ TaggedEqual(left, right), done,
                __ HeapConstant(factory_->true_value()));

        V<Word32> left_length = __ template LoadField<Word32>(
            left, AccessBuilder::ForStringLength());
        V<Word32> right_length = __ template LoadField<Word32>(
            right, AccessBuilder::ForStringLength());
        IF (__ Word32Equal(left_length, right_length)) {
          GOTO(done,
               __ CallBuiltin_StringEqual(isolate_, left, right,
                                          __ ChangeInt32ToIntPtr(left_length)));
        } ELSE {
          GOTO(done, __ HeapConstant(factory_->false_value()));
        }

        BIND(done, result);
        return result;
      }
      case StringComparisonOp::Kind::kLessThan:
        return __ CallBuiltin_StringLessThan(isolate_, left, right);
      case StringComparisonOp::Kind::kLessThanOrEqual:
        return __ CallBuiltin_StringLessThanOrEqual(isolate_, left, right);
    }
  }

  V<Smi> REDUCE(ArgumentsLength)(ArgumentsLengthOp::Kind kind,
                                 int formal_parameter_count) {
    V<WordPtr> count =
        __ LoadOffHeap(__ FramePointer(), StandardFrameConstants::kArgCOffset,
                       MemoryRepresentation::UintPtr());
    V<WordPtr> arguments_length = __ WordPtrSub(count, kJSArgcReceiverSlots);

    if (kind == ArgumentsLengthOp::Kind::kArguments) {
      return __ TagSmi(__ TruncateWordPtrToWord32(arguments_length));
    } else {
      DCHECK_EQ(kind, ArgumentsLengthOp::Kind::kRest);
      V<WordPtr> rest_length =
          __ WordPtrSub(arguments_length, formal_parameter_count);
      Label<WordPtr> done(this);
      IF (__ IntPtrLessThan(rest_length, 0)) {
        GOTO(done, 0);
      } ELSE {
        GOTO(done, rest_length);
      }

      BIND(done, value);
      return __ TagSmi(__ TruncateWordPtrToWord32(value));
    }
  }

  V<Object> REDUCE(NewArgum
```