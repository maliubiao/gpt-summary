Response:
My thought process to analyze the provided C++ code snippet and generate the summary goes like this:

1. **Understand the Context:** The prompt explicitly states the file is `v8/src/codegen/code-stub-assembler.cc`. This immediately tells me it's part of V8's code generation infrastructure and likely deals with low-level operations, potentially closer to machine code generation but with a higher-level abstraction layer. The ".cc" extension confirms it's C++.

2. **Initial Scan for Keywords and Patterns:** I quickly scan the code for recognizable keywords and patterns:
    * `Label`, `BIND`, `Goto`, `Branch`: These are control flow constructs, indicating conditional execution and jumps, common in assembly-like code or code generators.
    * `TNode`, `TVARIABLE`: These suggest a templated or specialized type system, likely used to represent intermediate values during code generation. The `T` prefix often hints at "temporary" or "typed."
    * `LoadMap`, `LoadObjectField`, `Cast`, `SmiToFloat64`: These point to operations on V8's internal object representation, involving maps (which describe object structure), fields, type casting, and conversions. "Smi" refers to small integers, a common optimization in JavaScript engines.
    * `CallBuiltin`, `CallRuntime`: These indicate calls to pre-defined, optimized functions within V8, either built-in or runtime functions.
    * `Float64Equal`, `TaggedEqual`, `TaggedIsSmi`: These are comparison operations at a low level, operating on specific data types or tagged values (where type information is embedded in the value).
    * `if_equal`, `if_notequal`, `if_true`, `if_false`: These are common labels for conditional branches.
    * Comments like `// Check if {lhs} and {rhs} refer to the same object.` provide valuable high-level insights.

3. **Focus on Key Functions:** I notice several prominent function definitions:
    * `GenerateEqual`: This is clearly implementing the strict equality comparison (`===`) in JavaScript. The code handles different types (Smi, HeapNumber, String, BigInt) and special cases (NaN).
    * `BranchIfStringEqual`: This is a specialized function for comparing strings, likely optimized.
    * `BranchIfSameValue`: This implements the `Object.is()` or SameValue algorithm, which differs from strict equality in how it handles NaN and signed zeros.
    * `HasProperty`: This implements the `in` operator or `hasOwnProperty` method, checking if an object has a specific property.
    * `ForInPrepare`: This function seems to set up the iteration for `for...in` loops.
    * `Typeof`: This implements the `typeof` operator.
    * `GetSuperConstructor`, `FindNonDefaultConstructor`: These functions are related to class inheritance and finding the appropriate constructor to call.
    * `SpeciesConstructor`: This implements the logic for the `Symbol.species` well-known symbol, used in subclassing built-in objects.
    * `InstanceOf`: This implements the `instanceof` operator.

4. **Infer Functionality from Code Logic:**  Even without deep knowledge of the V8 internals, I can deduce the purpose of code blocks:
    * The extensive `GenerateEqual` function demonstrates the complexity of strict equality in JavaScript due to its dynamic typing.
    * The `BranchIfSameValue` function explicitly handles the NaN and signed zero cases, highlighting the difference between `===` and `Object.is()`.
    * The `HasProperty` function explores the prototype chain to find properties.
    * The `ForInPrepare` function checks for optimized enumeration caches, indicating a performance consideration for `for...in` loops.
    * The `Typeof` function uses type checks and conditional branches to determine the type string.
    * The constructor-related functions demonstrate the machinery behind JavaScript's class inheritance.
    * `InstanceOf` uses the `@@hasInstance` symbol, showing how the `instanceof` operator can be customized.

5. **Address Specific Instructions in the Prompt:**

    * **Functionality Listing:** Based on the identified functions, I list their core purposes.
    * **`.tq` Extension:** I acknowledge the prompt's information about `.tq` files (Torque) and state that this file is `.cc`, meaning it's C++.
    * **Relationship to JavaScript:** For each identified function, I try to connect it to a corresponding JavaScript feature or operator (e.g., `GenerateEqual` to `===`, `Typeof` to `typeof`). I provide JavaScript examples to illustrate the connection.
    * **Code Logic Reasoning (Hypothetical Inputs/Outputs):** For some functions, particularly comparison functions, I can provide simple examples of inputs and expected boolean outputs based on JavaScript semantics.
    * **Common Programming Errors:** I think about typical mistakes related to the JavaScript features implemented by the code (e.g., misunderstanding `===` vs. `==`, confusion with `Object.is()`,  issues with `instanceof` and prototype chains, unexpected `typeof` results).
    * **Part 19 of 23 Summary:** I synthesize the overall functionality, emphasizing the code's role in implementing core JavaScript semantics at a lower level within V8's code generation pipeline. I highlight the focus on performance through optimizations like enumeration caches and direct built-in calls.

6. **Refine and Organize:**  I structure the information logically, starting with the general functionality and then delving into specific functions. I use clear headings and bullet points to improve readability. I ensure that the language is precise and avoids unnecessary technical jargon where possible while still being accurate.

By following these steps, I can effectively analyze the given C++ code snippet, understand its purpose within the V8 engine, and generate a comprehensive summary that addresses all the requirements of the prompt.


好的，我们来分析一下这段 `v8/src/codegen/code-stub-assembler.cc` 的代码片段。

**功能归纳:**

这段代码是 V8 引擎中 `CodeStubAssembler` 类的一部分，主要负责生成用于执行各种 JavaScript 操作的低级代码片段（code stubs）。 从提供的代码来看，它专注于实现以下核心的 JavaScript 比较和类型检查操作：

1. **严格相等比较 (`===`)**:  `GenerateEqual` 函数实现了 JavaScript 的严格相等比较算法。它处理了不同类型的值（例如，Smi、HeapNumber、String、BigInt）的比较，并考虑了引用相等和值相等。

2. **字符串相等比较**: `BranchIfStringEqual` 函数用于高效地比较两个字符串是否相等，它首先比较长度，然后逐字符比较。

3. **SameValue 比较 (`Object.is()`)**: `BranchIfSameValue` 函数实现了 `Object.is()` 方法的比较逻辑，它与严格相等不同之处在于对 `NaN` 和正负零的处理。

4. **属性判断 (`in` 运算符, `hasOwnProperty`)**: `HasProperty` 函数实现了判断对象是否拥有某个属性的功能，它会查找原型链。

5. **`for...in` 循环准备**: `ForInPrepare` 函数为 `for...in` 循环准备迭代器，它会尝试使用枚举缓存来优化性能。

6. **`typeof` 运算符**: `Typeof` 函数实现了 JavaScript 的 `typeof` 运算符，根据值的类型返回相应的字符串。

7. **获取父类构造函数**: `GetSuperConstructor` 函数用于获取一个函数的父类构造函数。

8. **查找非默认构造函数**: `FindNonDefaultConstructor` 函数用于在继承链上查找非默认的构造函数，这在类继承的场景中很重要。

9. **`Symbol.species` 逻辑**: `SpeciesConstructor` 函数实现了 `Symbol.species` 属性的查找和使用，用于控制派生类构造函数的创建。

10. **`instanceof` 运算符**: `InstanceOf` 函数实现了 JavaScript 的 `instanceof` 运算符，判断一个对象是否是某个构造函数的实例。

**关于文件类型:**

根据您的描述，`v8/src/codegen/code-stub-assembler.cc` 以 `.cc` 结尾，所以它是 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及举例:**

这些 C++ 函数直接对应了 JavaScript 中的操作符和方法：

* **`GenerateEqual`**:  对应 JavaScript 的 `===` 运算符。

   ```javascript
   console.log(1 === 1); // true
   console.log(1 === '1'); // false
   console.log({} === {}); // false (引用不相等)
   ```

* **`BranchIfStringEqual`**: 用于优化字符串的 `===` 比较。

   ```javascript
   console.log("hello" === "hello"); // true
   console.log("hello" === "world"); // false
   ```

* **`BranchIfSameValue`**: 对应 JavaScript 的 `Object.is()` 方法。

   ```javascript
   console.log(Object.is(NaN, NaN));       // true
   console.log(Object.is(-0, 0));         // false
   console.log(-0 === 0);                 // true
   ```

* **`HasProperty`**: 对应 JavaScript 的 `in` 运算符和 `hasOwnProperty` 方法。

   ```javascript
   const obj = { a: 1 };
   console.log('a' in obj); // true
   console.log(obj.hasOwnProperty('a')); // true
   console.log('toString' in obj); // true (原型链上的属性)
   ```

* **`ForInPrepare`**:  为 `for...in` 循环做准备。

   ```javascript
   const obj = { a: 1, b: 2 };
   for (let key in obj) {
     console.log(key); // 输出 "a", "b"
   }
   ```

* **`Typeof`**: 对应 JavaScript 的 `typeof` 运算符。

   ```javascript
   console.log(typeof 42);          // "number"
   console.log(typeof "hello");     // "string"
   console.log(typeof undefined);   // "undefined"
   console.log(typeof {});         // "object"
   console.log(typeof null);       // "object" (历史遗留问题)
   console.log(typeof function() {}); // "function"
   ```

* **`GetSuperConstructor` 和 `FindNonDefaultConstructor`**:  与类的继承相关。

   ```javascript
   class Animal {}
   class Dog extends Animal {}
   const dog = new Dog();
   ```

* **`SpeciesConstructor`**: 与 `Symbol.species` 相关。

   ```javascript
   class MyArray extends Array {
     static get [Symbol.species]() { return Array; }
   }
   const a = new MyArray(1, 2, 3);
   const sliced = a.slice(1);
   console.log(sliced instanceof Array);  // true (因为指定了 species)
   console.log(sliced instanceof MyArray); // false
   ```

* **`InstanceOf`**: 对应 JavaScript 的 `instanceof` 运算符。

   ```javascript
   class MyClass {}
   const obj = new MyClass();
   console.log(obj instanceof MyClass); // true
   console.log(obj instanceof Object);  // true (继承自 Object)
   ```

**代码逻辑推理 (假设输入与输出):**

以 `GenerateEqual` 函数为例，假设我们有以下输入：

* **输入 1:** `lhs` 是数字 `1` (Smi)，`rhs` 是数字 `1` (Smi)
   * **输出:**  `true` (因为值相等且类型相同)

* **输入 2:** `lhs` 是数字 `1` (Smi)，`rhs` 是字符串 `"1"`
   * **输出:** `false` (因为类型不同)

* **输入 3:** `lhs` 是对象 `{ a: 1 }`，`rhs` 是对象 `{ a: 1 }`
   * **输出:** `false` (因为是不同的对象引用)

* **输入 4:** `lhs` 是字符串 `"hello"`，`rhs` 是字符串 `"hello"`
   * **输出:** `true` (因为值相等且类型相同)

**用户常见的编程错误:**

* **使用 `==` 而不是 `===` 进行比较**:  `==` 会进行类型转换，可能导致意想不到的结果。

   ```javascript
   console.log(1 == '1');   // true (进行了类型转换)
   console.log(1 === '1');  // false
   ```

* **误解 `Object.is()` 的行为**: 认为它和 `===` 完全相同，但对 `NaN` 和 `-0`/`+0` 的处理不同。

   ```javascript
   console.log(NaN === NaN);       // false
   console.log(Object.is(NaN, NaN)); // true
   console.log(-0 === 0);         // true
   console.log(Object.is(-0, 0));   // false
   ```

* **对 `instanceof` 的理解偏差**:  `instanceof` 检查的是原型链，而不是简单的类型。

   ```javascript
   function MyConstructor() {}
   const obj = new MyConstructor();
   console.log(obj instanceof MyConstructor); // true
   console.log(obj instanceof Object);      // true
   ```

* **在 `for...in` 循环中意外迭代到原型链上的属性**: 应该使用 `hasOwnProperty` 进行过滤。

   ```javascript
   const obj = { a: 1 };
   Object.prototype.b = 2; // 给 Object 的原型添加属性
   for (let key in obj) {
     console.log(key); // 输出 "a" 和 "b"
   }

   for (let key in obj) {
     if (obj.hasOwnProperty(key)) {
       console.log(key); // 只输出 "a"
     }
   }
   ```

**第 19 部分功能归纳 (结合上下文推测):**

由于这是第 19 部分，并且之前的代码处理了各种比较和类型检查操作，可以推测这一部分可能专注于实现一些**更高级或更特定的语言特性**，例如：

* **更复杂的对象操作**: 例如，属性的 getter/setter、Proxy 对象的处理等。
* **与函数调用相关的逻辑**:  例如，`call`、`apply` 方法的实现。
* **与迭代器和生成器相关的逻辑**。
* **错误处理和异常抛出机制**。

但仅从这段代码本身来看，它主要集中在**基本的比较和类型判断**操作的底层实现。

希望这个详细的分析能够帮助您理解这段 V8 源代码的功能。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第19部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
/           return false;
  //         }
  //       } else if (lhs->IsBigInt()) {
  //         if (rhs->IsBigInt()) {
  //           return %BigIntEqualToBigInt(lhs, rhs);
  //         } else {
  //           return false;
  //         }
  //       } else {
  //         return false;
  //       }
  //     }
  //   }
  // } else {
  //   if (IsSmi(rhs)) {
  //     return false;
  //   } else {
  //     if (rhs->IsHeapNumber()) {
  //       return Smi::ToInt(lhs) == Cast<HeapNumber>(rhs)->value();
  //     } else {
  //       return false;
  //     }
  //   }
  // }

  Label if_equal(this), if_notequal(this), if_not_equivalent_types(this),
      end(this);
  TVARIABLE(Boolean, result);

  OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kNone);

  // Check if {lhs} and {rhs} refer to the same object.
  Label if_same(this), if_notsame(this);
  Branch(TaggedEqual(lhs, rhs), &if_same, &if_notsame);

  BIND(&if_same);
  {
    // The {lhs} and {rhs} reference the exact same value, yet we need special
    // treatment for HeapNumber, as NaN is not equal to NaN.
    GenerateEqual_Same(lhs, &if_equal, &if_notequal, var_type_feedback);
  }

  BIND(&if_notsame);
  {
    // The {lhs} and {rhs} reference different objects, yet for Smi, HeapNumber,
    // BigInt and String they can still be considered equal.

    // Check if {lhs} is a Smi or a HeapObject.
    Label if_lhsissmi(this), if_lhsisnotsmi(this);
    Branch(TaggedIsSmi(lhs), &if_lhsissmi, &if_lhsisnotsmi);

    BIND(&if_lhsisnotsmi);
    {
      // Load the map of {lhs}.
      TNode<Map> lhs_map = LoadMap(CAST(lhs));

      // Check if {lhs} is a HeapNumber.
      Label if_lhsisnumber(this), if_lhsisnotnumber(this);
      Branch(IsHeapNumberMap(lhs_map), &if_lhsisnumber, &if_lhsisnotnumber);

      BIND(&if_lhsisnumber);
      {
        // Check if {rhs} is a Smi or a HeapObject.
        Label if_rhsissmi(this), if_rhsisnotsmi(this);
        Branch(TaggedIsSmi(rhs), &if_rhsissmi, &if_rhsisnotsmi);

        BIND(&if_rhsissmi);
        {
          // Convert {lhs} and {rhs} to floating point values.
          TNode<Float64T> lhs_value = LoadHeapNumberValue(CAST(lhs));
          TNode<Float64T> rhs_value = SmiToFloat64(CAST(rhs));

          CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);

          // Perform a floating point comparison of {lhs} and {rhs}.
          Branch(Float64Equal(lhs_value, rhs_value), &if_equal, &if_notequal);
        }

        BIND(&if_rhsisnotsmi);
        {
          TNode<HeapObject> rhs_ho = CAST(rhs);
          // Load the map of {rhs}.
          TNode<Map> rhs_map = LoadMap(rhs_ho);

          // Check if {rhs} is also a HeapNumber.
          Label if_rhsisnumber(this), if_rhsisnotnumber(this);
          Branch(IsHeapNumberMap(rhs_map), &if_rhsisnumber, &if_rhsisnotnumber);

          BIND(&if_rhsisnumber);
          {
            // Convert {lhs} and {rhs} to floating point values.
            TNode<Float64T> lhs_value = LoadHeapNumberValue(CAST(lhs));
            TNode<Float64T> rhs_value = LoadHeapNumberValue(CAST(rhs));

            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kNumber);

            // Perform a floating point comparison of {lhs} and {rhs}.
            Branch(Float64Equal(lhs_value, rhs_value), &if_equal, &if_notequal);
          }

          BIND(&if_rhsisnotnumber);
          Goto(&if_not_equivalent_types);
        }
      }

      BIND(&if_lhsisnotnumber);
      {
        // Check if {rhs} is a Smi or a HeapObject.
        Label if_rhsissmi(this), if_rhsisnotsmi(this);
        Branch(TaggedIsSmi(rhs), &if_rhsissmi, &if_rhsisnotsmi);

        BIND(&if_rhsissmi);
        Goto(&if_not_equivalent_types);

        BIND(&if_rhsisnotsmi);
        {
          // Load the instance type of {lhs}.
          TNode<Uint16T> lhs_instance_type = LoadMapInstanceType(lhs_map);

          // Check if {lhs} is a String.
          Label if_lhsisstring(this, Label::kDeferred), if_lhsisnotstring(this);
          Branch(IsStringInstanceType(lhs_instance_type), &if_lhsisstring,
                 &if_lhsisnotstring);

          BIND(&if_lhsisstring);
          {
            // Load the instance type of {rhs}.
            TNode<Uint16T> rhs_instance_type = LoadInstanceType(CAST(rhs));

            // Check if {rhs} is also a String.
            Label if_rhsisstring(this, Label::kDeferred),
                if_rhsisnotstring(this);
            Branch(IsStringInstanceType(rhs_instance_type), &if_rhsisstring,
                   &if_rhsisnotstring);

            BIND(&if_rhsisstring);
            {
              if (var_type_feedback != nullptr) {
                TNode<Smi> lhs_feedback =
                    CollectFeedbackForString(lhs_instance_type);
                TNode<Smi> rhs_feedback =
                    CollectFeedbackForString(rhs_instance_type);
                *var_type_feedback = SmiOr(lhs_feedback, rhs_feedback);
              }
              BranchIfStringEqual(CAST(lhs), CAST(rhs), &end, &end, &result);
            }

            BIND(&if_rhsisnotstring);
            Goto(&if_not_equivalent_types);
          }

          BIND(&if_lhsisnotstring);
          {
            // Check if {lhs} is a BigInt.
            Label if_lhsisbigint(this), if_lhsisnotbigint(this);
            Branch(IsBigIntInstanceType(lhs_instance_type), &if_lhsisbigint,
                   &if_lhsisnotbigint);

            BIND(&if_lhsisbigint);
            {
              // Load the instance type of {rhs}.
              TNode<Uint16T> rhs_instance_type = LoadInstanceType(CAST(rhs));

              // Check if {rhs} is also a BigInt.
              Label if_rhsisbigint(this, Label::kDeferred),
                  if_rhsisnotbigint(this);
              Branch(IsBigIntInstanceType(rhs_instance_type), &if_rhsisbigint,
                     &if_rhsisnotbigint);

              BIND(&if_rhsisbigint);
              {
                if (Is64()) {
                  Label if_both_bigint(this);
                  GotoIfLargeBigInt(CAST(lhs), &if_both_bigint);
                  GotoIfLargeBigInt(CAST(rhs), &if_both_bigint);

                  OverwriteFeedback(var_type_feedback,
                                    CompareOperationFeedback::kBigInt64);
                  BigInt64Comparison(Operation::kStrictEqual, lhs, rhs,
                                     &if_equal, &if_notequal);
                  BIND(&if_both_bigint);
                }

                CombineFeedback(var_type_feedback,
                                CompareOperationFeedback::kBigInt);
                result = CAST(CallBuiltin(Builtin::kBigIntEqual,
                                          NoContextConstant(), lhs, rhs));
                Goto(&end);
              }

              BIND(&if_rhsisnotbigint);
              Goto(&if_not_equivalent_types);
            }

            BIND(&if_lhsisnotbigint);
            if (var_type_feedback != nullptr) {
              // Load the instance type of {rhs}.
              TNode<Map> rhs_map = LoadMap(CAST(rhs));
              TNode<Uint16T> rhs_instance_type = LoadMapInstanceType(rhs_map);

              Label if_lhsissymbol(this), if_lhsisreceiver(this),
                  if_lhsisoddball(this);
              GotoIf(IsJSReceiverInstanceType(lhs_instance_type),
                     &if_lhsisreceiver);
              GotoIf(IsBooleanMap(lhs_map), &if_not_equivalent_types);
              GotoIf(IsOddballInstanceType(lhs_instance_type),
                     &if_lhsisoddball);
              Branch(IsSymbolInstanceType(lhs_instance_type), &if_lhsissymbol,
                     &if_not_equivalent_types);

              BIND(&if_lhsisreceiver);
              {
                GotoIf(IsBooleanMap(rhs_map), &if_not_equivalent_types);
                OverwriteFeedback(var_type_feedback,
                                  CompareOperationFeedback::kReceiver);
                GotoIf(IsJSReceiverInstanceType(rhs_instance_type),
                       &if_notequal);
                OverwriteFeedback(
                    var_type_feedback,
                    CompareOperationFeedback::kReceiverOrNullOrUndefined);
                GotoIf(IsOddballInstanceType(rhs_instance_type), &if_notequal);
                Goto(&if_not_equivalent_types);
              }

              BIND(&if_lhsisoddball);
              {
                  static_assert(LAST_PRIMITIVE_HEAP_OBJECT_TYPE ==
                                ODDBALL_TYPE);
                  GotoIf(Int32LessThan(rhs_instance_type,
                                       Int32Constant(ODDBALL_TYPE)),
                         &if_not_equivalent_types);

                  // TODO(marja): This is wrong, since null == true will be
                  // detected as ReceiverOrNullOrUndefined, but true is not
                  // receiver or null or undefined.
                  OverwriteFeedback(
                      var_type_feedback,
                      CompareOperationFeedback::kReceiverOrNullOrUndefined);
                  Goto(&if_notequal);
              }

              BIND(&if_lhsissymbol);
              {
                GotoIfNot(IsSymbolInstanceType(rhs_instance_type),
                          &if_not_equivalent_types);
                OverwriteFeedback(var_type_feedback,
                                  CompareOperationFeedback::kSymbol);
                Goto(&if_notequal);
              }
            } else {
              Goto(&if_notequal);
            }
          }
        }
      }
    }

    BIND(&if_lhsissmi);
    {
      // We already know that {lhs} and {rhs} are not reference equal, and {lhs}
      // is a Smi; so {lhs} and {rhs} can only be strictly equal if {rhs} is a
      // HeapNumber with an equal floating point value.

      // Check if {rhs} is a Smi or a HeapObject.
      Label if_rhsissmi(this), if_rhsisnotsmi(this);
      Branch(TaggedIsSmi(rhs), &if_rhsissmi, &if_rhsisnotsmi);

      BIND(&if_rhsissmi);
      CombineFeedback(var_type_feedback,
                      CompareOperationFeedback::kSignedSmall);
      Goto(&if_notequal);

      BIND(&if_rhsisnotsmi);
      {
        // Load the map of the {rhs}.
        TNode<Map> rhs_map = LoadMap(CAST(rhs));

        // The {rhs} could be a HeapNumber with the same value as {lhs}.
        GotoIfNot(IsHeapNumberMap(rhs_map), &if_not_equivalent_types);

        // Convert {lhs} and {rhs} to floating point values.
        TNode<Float64T> lhs_value = SmiToFloat64(CAST(lhs));
        TNode<Float64T> rhs_value = LoadHeapNumberValue(CAST(rhs));

        CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);

        // Perform a floating point comparison of {lhs} and {rhs}.
        Branch(Float64Equal(lhs_value, rhs_value), &if_equal, &if_notequal);
      }
    }
  }

  BIND(&if_equal);
  {
    result = TrueConstant();
    Goto(&end);
  }

  BIND(&if_not_equivalent_types);
  {
    OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kAny);
    Goto(&if_notequal);
  }

  BIND(&if_notequal);
  {
    result = FalseConstant();
    Goto(&end);
  }

  BIND(&end);
  return result.value();
}

void CodeStubAssembler::BranchIfStringEqual(TNode<String> lhs,
                                            TNode<IntPtrT> lhs_length,
                                            TNode<String> rhs,
                                            TNode<IntPtrT> rhs_length,
                                            Label* if_true, Label* if_false,
                                            TVariable<Boolean>* result) {
  // Callers must handle the case where {lhs} and {rhs} refer to the same
  // String object.
  CSA_DCHECK(this, TaggedNotEqual(lhs, rhs));

  Label length_equal(this), length_not_equal(this);
  Branch(IntPtrEqual(lhs_length, rhs_length), &length_equal, &length_not_equal);

  BIND(&length_not_equal);
  {
    if (result != nullptr) *result = FalseConstant();
    Goto(if_false);
  }

  BIND(&length_equal);
  {
    TNode<Boolean> value = CAST(CallBuiltin(
        Builtin::kStringEqual, NoContextConstant(), lhs, rhs, lhs_length));
    if (result != nullptr) {
      *result = value;
    }
    if (if_true == if_false) {
      Goto(if_true);
    } else {
      Branch(TaggedEqual(value, TrueConstant()), if_true, if_false);
    }
  }
}

// ECMA#sec-samevalue
// This algorithm differs from the Strict Equality Comparison Algorithm in its
// treatment of signed zeroes and NaNs.
void CodeStubAssembler::BranchIfSameValue(TNode<Object> lhs, TNode<Object> rhs,
                                          Label* if_true, Label* if_false,
                                          SameValueMode mode) {
  TVARIABLE(Float64T, var_lhs_value);
  TVARIABLE(Float64T, var_rhs_value);
  Label do_fcmp(this);

  // Immediately jump to {if_true} if {lhs} == {rhs}, because - unlike
  // StrictEqual - SameValue considers two NaNs to be equal.
  GotoIf(TaggedEqual(lhs, rhs), if_true);

  // Check if the {lhs} is a Smi.
  Label if_lhsissmi(this), if_lhsisheapobject(this);
  Branch(TaggedIsSmi(lhs), &if_lhsissmi, &if_lhsisheapobject);

  BIND(&if_lhsissmi);
  {
    // Since {lhs} is a Smi, the comparison can only yield true
    // iff the {rhs} is a HeapNumber with the same float64 value.
    Branch(TaggedIsSmi(rhs), if_false, [&] {
      GotoIfNot(IsHeapNumber(CAST(rhs)), if_false);
      var_lhs_value = SmiToFloat64(CAST(lhs));
      var_rhs_value = LoadHeapNumberValue(CAST(rhs));
      Goto(&do_fcmp);
    });
  }

  BIND(&if_lhsisheapobject);
  {
    // Check if the {rhs} is a Smi.
    Branch(
        TaggedIsSmi(rhs),
        [&] {
          // Since {rhs} is a Smi, the comparison can only yield true
          // iff the {lhs} is a HeapNumber with the same float64 value.
          GotoIfNot(IsHeapNumber(CAST(lhs)), if_false);
          var_lhs_value = LoadHeapNumberValue(CAST(lhs));
          var_rhs_value = SmiToFloat64(CAST(rhs));
          Goto(&do_fcmp);
        },
        [&] {
          // Now this can only yield true if either both {lhs} and {rhs} are
          // HeapNumbers with the same value, or both are Strings with the
          // same character sequence, or both are BigInts with the same
          // value.
          Label if_lhsisheapnumber(this), if_lhsisstring(this),
              if_lhsisbigint(this);
          const TNode<Map> lhs_map = LoadMap(CAST(lhs));
          GotoIf(IsHeapNumberMap(lhs_map), &if_lhsisheapnumber);
          if (mode != SameValueMode::kNumbersOnly) {
            const TNode<Uint16T> lhs_instance_type =
                LoadMapInstanceType(lhs_map);
            GotoIf(IsStringInstanceType(lhs_instance_type), &if_lhsisstring);
            GotoIf(IsBigIntInstanceType(lhs_instance_type), &if_lhsisbigint);
          }
          Goto(if_false);

          BIND(&if_lhsisheapnumber);
          {
            GotoIfNot(IsHeapNumber(CAST(rhs)), if_false);
            var_lhs_value = LoadHeapNumberValue(CAST(lhs));
            var_rhs_value = LoadHeapNumberValue(CAST(rhs));
            Goto(&do_fcmp);
          }

          if (mode != SameValueMode::kNumbersOnly) {
            BIND(&if_lhsisstring);
            {
              // Now we can only yield true if {rhs} is also a String
              // with the same sequence of characters.
              GotoIfNot(IsString(CAST(rhs)), if_false);
              BranchIfStringEqual(CAST(lhs), CAST(rhs), if_true, if_false);
            }

            BIND(&if_lhsisbigint);
            {
              GotoIfNot(IsBigInt(CAST(rhs)), if_false);
              const TNode<Object> result = CallRuntime(
                  Runtime::kBigIntEqualToBigInt, NoContextConstant(), lhs, rhs);
              Branch(IsTrue(result), if_true, if_false);
            }
          }
        });
  }

  BIND(&do_fcmp);
  {
    TNode<Float64T> lhs_value = UncheckedCast<Float64T>(var_lhs_value.value());
    TNode<Float64T> rhs_value = UncheckedCast<Float64T>(var_rhs_value.value());
    BranchIfSameNumberValue(lhs_value, rhs_value, if_true, if_false);
  }
}

void CodeStubAssembler::BranchIfSameNumberValue(TNode<Float64T> lhs_value,
                                                TNode<Float64T> rhs_value,
                                                Label* if_true,
                                                Label* if_false) {
  Label if_equal(this), if_notequal(this);
  Branch(Float64Equal(lhs_value, rhs_value), &if_equal, &if_notequal);

  BIND(&if_equal);
  {
    // We still need to handle the case when {lhs} and {rhs} are -0.0 and
    // 0.0 (or vice versa). Compare the high word to
    // distinguish between the two.
    const TNode<Uint32T> lhs_hi_word = Float64ExtractHighWord32(lhs_value);
    const TNode<Uint32T> rhs_hi_word = Float64ExtractHighWord32(rhs_value);

    // If x is +0 and y is -0, return false.
    // If x is -0 and y is +0, return false.
    Branch(Word32Equal(lhs_hi_word, rhs_hi_word), if_true, if_false);
  }

  BIND(&if_notequal);
  {
    // Return true iff both {rhs} and {lhs} are NaN.
    GotoIf(Float64Equal(lhs_value, lhs_value), if_false);
    Branch(Float64Equal(rhs_value, rhs_value), if_false, if_true);
  }
}

TNode<Boolean> CodeStubAssembler::HasProperty(TNode<Context> context,
                                              TNode<Object> object,
                                              TNode<Object> key,
                                              HasPropertyLookupMode mode) {
  Label call_runtime(this, Label::kDeferred), return_true(this),
      return_false(this), end(this), if_proxy(this, Label::kDeferred);

  CodeStubAssembler::LookupPropertyInHolder lookup_property_in_holder =
      [this, &return_true](
          TNode<HeapObject> receiver, TNode<HeapObject> holder,
          TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
          TNode<Name> unique_name, Label* next_holder, Label* if_bailout) {
        TryHasOwnProperty(holder, holder_map, holder_instance_type, unique_name,
                          &return_true, next_holder, if_bailout);
      };

  CodeStubAssembler::LookupElementInHolder lookup_element_in_holder =
      [this, &return_true, &return_false](
          TNode<HeapObject> receiver, TNode<HeapObject> holder,
          TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
          TNode<IntPtrT> index, Label* next_holder, Label* if_bailout) {
        TryLookupElement(holder, holder_map, holder_instance_type, index,
                         &return_true, &return_false, next_holder, if_bailout);
      };

  const bool kHandlePrivateNames = mode == HasPropertyLookupMode::kHasProperty;
  TryPrototypeChainLookup(object, object, key, lookup_property_in_holder,
                          lookup_element_in_holder, &return_false,
                          &call_runtime, &if_proxy, kHandlePrivateNames);

  TVARIABLE(Boolean, result);

  BIND(&if_proxy);
  {
    TNode<Name> name = CAST(CallBuiltin(Builtin::kToName, context, key));
    switch (mode) {
      case kHasProperty:
        GotoIf(IsPrivateSymbol(name), &call_runtime);

        result = CAST(
            CallBuiltin(Builtin::kProxyHasProperty, context, object, name));
        Goto(&end);
        break;
      case kForInHasProperty:
        Goto(&call_runtime);
        break;
    }
  }

  BIND(&return_true);
  {
    result = TrueConstant();
    Goto(&end);
  }

  BIND(&return_false);
  {
    result = FalseConstant();
    Goto(&end);
  }

  BIND(&call_runtime);
  {
    Runtime::FunctionId fallback_runtime_function_id;
    switch (mode) {
      case kHasProperty:
        fallback_runtime_function_id = Runtime::kHasProperty;
        break;
      case kForInHasProperty:
        fallback_runtime_function_id = Runtime::kForInHasProperty;
        break;
    }

    result =
        CAST(CallRuntime(fallback_runtime_function_id, context, object, key));
    Goto(&end);
  }

  BIND(&end);
  CSA_DCHECK(this, IsBoolean(result.value()));
  return result.value();
}

void CodeStubAssembler::ForInPrepare(TNode<HeapObject> enumerator,
                                     TNode<UintPtrT> slot,
                                     TNode<HeapObject> maybe_feedback_vector,
                                     TNode<FixedArray>* cache_array_out,
                                     TNode<Smi>* cache_length_out,
                                     UpdateFeedbackMode update_feedback_mode) {
  // Check if we're using an enum cache.
  TVARIABLE(FixedArray, cache_array);
  TVARIABLE(Smi, cache_length);
  Label if_fast(this), if_slow(this, Label::kDeferred), out(this);
  Branch(IsMap(enumerator), &if_fast, &if_slow);

  BIND(&if_fast);
  {
    // Load the enumeration length and cache from the {enumerator}.
    TNode<Map> map_enumerator = CAST(enumerator);
    TNode<Uint32T> enum_length = LoadMapEnumLength(map_enumerator);
    CSA_DCHECK(this, Word32NotEqual(enum_length,
                                    Uint32Constant(kInvalidEnumCacheSentinel)));
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(map_enumerator);
    TNode<EnumCache> enum_cache = LoadObjectField<EnumCache>(
        descriptors, DescriptorArray::kEnumCacheOffset);
    TNode<FixedArray> enum_keys =
        LoadObjectField<FixedArray>(enum_cache, EnumCache::kKeysOffset);

    // Check if we have enum indices available.
    TNode<FixedArray> enum_indices =
        LoadObjectField<FixedArray>(enum_cache, EnumCache::kIndicesOffset);
    TNode<Uint32T> enum_indices_length =
        LoadAndUntagFixedArrayBaseLengthAsUint32(enum_indices);
    TNode<Smi> feedback = SelectSmiConstant(
        Uint32LessThanOrEqual(enum_length, enum_indices_length),
        static_cast<int>(ForInFeedback::kEnumCacheKeysAndIndices),
        static_cast<int>(ForInFeedback::kEnumCacheKeys));
    UpdateFeedback(feedback, maybe_feedback_vector, slot, update_feedback_mode);

    cache_array = enum_keys;
    cache_length = SmiFromUint32(enum_length);
    Goto(&out);
  }

  BIND(&if_slow);
  {
    // The {enumerator} is a FixedArray with all the keys to iterate.
    TNode<FixedArray> array_enumerator = CAST(enumerator);

    // Record the fact that we hit the for-in slow-path.
    UpdateFeedback(SmiConstant(ForInFeedback::kAny), maybe_feedback_vector,
                   slot, update_feedback_mode);

    cache_array = array_enumerator;
    cache_length = LoadFixedArrayBaseLength(array_enumerator);
    Goto(&out);
  }

  BIND(&out);
  *cache_array_out = cache_array.value();
  *cache_length_out = cache_length.value();
}

TNode<String> CodeStubAssembler::Typeof(
    TNode<Object> value, std::optional<TNode<UintPtrT>> slot_id,
    std::optional<TNode<HeapObject>> maybe_feedback_vector) {
  TVARIABLE(String, result_var);

  Label return_number(this, Label::kDeferred), if_oddball(this),
      return_function(this), return_undefined(this), return_object(this),
      return_string(this), return_bigint(this), return_symbol(this),
      return_result(this);

  GotoIf(TaggedIsSmi(value), &return_number);

  TNode<HeapObject> value_heap_object = CAST(value);
  TNode<Map> map = LoadMap(value_heap_object);

  GotoIf(IsHeapNumberMap(map), &return_number);

  TNode<Uint16T> instance_type = LoadMapInstanceType(map);

  GotoIf(InstanceTypeEqual(instance_type, ODDBALL_TYPE), &if_oddball);

  TNode<Int32T> callable_or_undetectable_mask =
      Word32And(LoadMapBitField(map),
                Int32Constant(Map::Bits1::IsCallableBit::kMask |
                              Map::Bits1::IsUndetectableBit::kMask));

  GotoIf(Word32Equal(callable_or_undetectable_mask,
                     Int32Constant(Map::Bits1::IsCallableBit::kMask)),
         &return_function);

  GotoIfNot(Word32Equal(callable_or_undetectable_mask, Int32Constant(0)),
            &return_undefined);

  GotoIf(IsJSReceiverInstanceType(instance_type), &return_object);

  GotoIf(IsStringInstanceType(instance_type), &return_string);

  GotoIf(IsBigIntInstanceType(instance_type), &return_bigint);

  GotoIf(IsSymbolInstanceType(instance_type), &return_symbol);

  Abort(AbortReason::kUnexpectedInstanceType);

  auto UpdateFeedback = [&](TypeOfFeedback::Result feedback) {
    if (maybe_feedback_vector.has_value()) {
      MaybeUpdateFeedback(SmiConstant(feedback), *maybe_feedback_vector,
                          *slot_id);
    }
  };
  BIND(&return_number);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->number_string());
    UpdateFeedback(TypeOfFeedback::kNumber);
    Goto(&return_result);
  }

  BIND(&if_oddball);
  {
    TNode<String> type =
        CAST(LoadObjectField(value_heap_object, offsetof(Oddball, type_of_)));
    result_var = type;
    UpdateFeedback(TypeOfFeedback::kAny);
    Goto(&return_result);
  }

  BIND(&return_function);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->function_string());
    UpdateFeedback(TypeOfFeedback::kFunction);
    Goto(&return_result);
  }

  BIND(&return_undefined);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->undefined_string());
    UpdateFeedback(TypeOfFeedback::kAny);
    Goto(&return_result);
  }

  BIND(&return_object);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->object_string());
    UpdateFeedback(TypeOfFeedback::kAny);
    Goto(&return_result);
  }

  BIND(&return_string);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->string_string());
    UpdateFeedback(TypeOfFeedback::kString);
    Goto(&return_result);
  }

  BIND(&return_bigint);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->bigint_string());
    UpdateFeedback(TypeOfFeedback::kAny);
    Goto(&return_result);
  }

  BIND(&return_symbol);
  {
    result_var = HeapConstantNoHole(isolate()->factory()->symbol_string());
    UpdateFeedback(TypeOfFeedback::kAny);
    Goto(&return_result);
  }

  BIND(&return_result);
  return result_var.value();
}

TNode<HeapObject> CodeStubAssembler::GetSuperConstructor(
    TNode<JSFunction> active_function) {
  TNode<Map> map = LoadMap(active_function);
  return LoadMapPrototype(map);
}

void CodeStubAssembler::FindNonDefaultConstructor(
    TNode<JSFunction> this_function, TVariable<Object>& constructor,
    Label* found_default_base_ctor, Label* found_something_else) {
  Label loop(this, &constructor);

  constructor = GetSuperConstructor(this_function);

  // Disable the optimization if the debugger is active, so that we can still
  // put breakpoints into default constructors.
  GotoIf(IsDebugActive(), found_something_else);

  // Disable the optimization if the array iterator has been changed. V8 uses
  // the array iterator for the spread in default ctors, even though it
  // shouldn't, according to the spec. This ensures that omitting default ctors
  // doesn't change the behavior. See crbug.com/v8/13249.
  GotoIf(IsArrayIteratorProtectorCellInvalid(), found_something_else);

  Goto(&loop);

  BIND(&loop);
  {
    // We know constructor can't be a SMI, since it's a prototype. If it's not a
    // JSFunction, the error will be thrown by the ThrowIfNotSuperConstructor
    // which follows this bytecode.
    GotoIfNot(IsJSFunction(CAST(constructor.value())), found_something_else);

    // If there are class fields, bail out. TODO(v8:13091): Handle them here.
    const TNode<SharedFunctionInfo> shared_function_info =
        LoadObjectField<SharedFunctionInfo>(
            CAST(constructor.value()), JSFunction::kSharedFunctionInfoOffset);
    const TNode<Uint32T> has_class_fields =
        DecodeWord32<SharedFunctionInfo::RequiresInstanceMembersInitializerBit>(
            LoadObjectField<Uint32T>(shared_function_info,
                                     SharedFunctionInfo::kFlagsOffset));

    GotoIf(Word32NotEqual(has_class_fields, Int32Constant(0)),
           found_something_else);

    // If there are private methods, bail out. TODO(v8:13091): Handle them here.
    TNode<Context> function_context =
        LoadJSFunctionContext(CAST(constructor.value()));
    TNode<ScopeInfo> scope_info = LoadScopeInfo(function_context);
    GotoIf(LoadScopeInfoClassScopeHasPrivateBrand(scope_info),
           found_something_else);

    const TNode<Uint32T> function_kind =
        LoadFunctionKind(CAST(constructor.value()));
    // A default base ctor -> stop the search.
    GotoIf(Word32Equal(
               function_kind,
               static_cast<uint32_t>(FunctionKind::kDefaultBaseConstructor)),
           found_default_base_ctor);

    // Something else than a default derived ctor (e.g., a non-default base
    // ctor, a non-default derived ctor, or a normal function) -> stop the
    // search.
    GotoIfNot(Word32Equal(function_kind,
                          static_cast<uint32_t>(
                              FunctionKind::kDefaultDerivedConstructor)),
              found_something_else);

    constructor = GetSuperConstructor(CAST(constructor.value()));

    Goto(&loop);
  }
  // We don't need to re-check the proctector, since the loop cannot call into
  // user code. Even if GetSuperConstructor returns a Proxy, we will throw since
  // it's not a constructor, and not invoke [[GetPrototypeOf]] on it.
  // TODO(v8:13091): make sure this is still valid after we handle class fields.
}

TNode<JSReceiver> CodeStubAssembler::SpeciesConstructor(
    TNode<Context> context, TNode<Object> object,
    TNode<JSReceiver> default_constructor) {
  Isolate* isolate = this->isolate();
  TVARIABLE(JSReceiver, var_result, default_constructor);

  // 2. Let C be ? Get(O, "constructor").
  TNode<Object> constructor =
      GetProperty(context, object, isolate->factory()->constructor_string());

  // 3. If C is undefined, return defaultConstructor.
  Label out(this);
  GotoIf(IsUndefined(constructor), &out);

  // 4. If Type(C) is not Object, throw a TypeError exception.
  ThrowIfNotJSReceiver(context, constructor,
                       MessageTemplate::kConstructorNotReceiver, "");

  // 5. Let S be ? Get(C, @@species).
  TNode<Object> species =
      GetProperty(context, constructor, isolate->factory()->species_symbol());

  // 6. If S is either undefined or null, return defaultConstructor.
  GotoIf(IsNullOrUndefined(species), &out);

  // 7. If IsConstructor(S) is true, return S.
  Label throw_error(this);
  GotoIf(TaggedIsSmi(species), &throw_error);
  GotoIfNot(IsConstructorMap(LoadMap(CAST(species))), &throw_error);
  var_result = CAST(species);
  Goto(&out);

  // 8. Throw a TypeError exception.
  BIND(&throw_error);
  ThrowTypeError(context, MessageTemplate::kSpeciesNotConstructor);

  BIND(&out);
  return var_result.value();
}

TNode<Boolean> CodeStubAssembler::InstanceOf(TNode<Object> object,
                                             TNode<Object> callable,
                                             TNode<Context> context) {
  TVARIABLE(Boolean, var_result);
  Label if_notcallable(this, Label::kDeferred),
      if_notreceiver(this, Label::kDeferred), if_otherhandler(this),
      if_nohandler(this, Label::kDeferred), return_true(this),
      return_false(this), return_result(this, &var_result);

  // Ensure that the {callable} is actually a JSReceiver.
  GotoIf(TaggedIsSmi(callable), &if_notreceiver);
  GotoIfNot(IsJSReceiver(CAST(callable)), &if_notreceiver);

  // Load the @@hasInstance property from {callable}.
  TNode<Object> inst_of_handler =
      GetProperty(context, callable, HasInstanceSymbolConstant());

  // Optimize for the likely case where {inst_of_handler} is the builtin
  // Function.prototype[@@hasInstance] method, and emit a direct call in
  // that case without any additional checking.
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSFunction> function_has_instance = CAST(
      LoadContextElement(native_context, Context::FUNCTION_HAS_INSTANCE_INDEX));
  GotoIfNot(TaggedEqual(inst_of_handler, function_has_instance),
            &if_otherhandler);
  {
    // Call to Function.prototype[@@hasInstance] directly without using the
    // Builtins::Call().
    var_result = CAST(CallJSBuiltin(Builtin::kFunctionPrototypeHasInstance,
                                    context, inst_of_handler,
                                    UndefinedConstant(),  // new_target
                                    callable, object));
    Goto(&return_result);
  }

  BIND(&if_otherhandler);
  {
    // Check if there's actually an {inst_of_handler}.
    GotoIf(IsNull(inst_of_handler), &if_nohandler);
    GotoIf(IsUndefined(inst_of_handler), &if_nohandler);

    // Call the {inst_of_handler} for {callable} and {object}.
    TNode<Object> result =
        Call(context, inst_of_handler, ConvertReceiverMode::kNotNullOrUndefined,
             callable, object);

    // Convert the {result} to a Boolean.
    BranchIfToBooleanIsTrue(result, &return_true, &return_false);
  }

  BIND(&if_nohandler);
  {
    // Ensure that the {callable} is actually Callable.
```