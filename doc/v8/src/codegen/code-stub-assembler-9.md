Response: My thought process to answer the request goes like this:

1. **Understand the Goal:** The user wants a summary of the C++ code's functionality and examples in JavaScript if applicable. The user also specified this is part 10 of 12. This implies a focus on specific functionalities likely related to the stage of code generation this part represents.

2. **Initial Scan for Keywords and Structure:** I quickly scan the code for recurring keywords, function names, and the overall structure. I see things like:
    * `CodeStubAssembler` (prominent class name)
    * `BranchIf...`, `GotoIf...`, `CallBuiltin`, `CallRuntime` (control flow and function calls)
    * `TaggedIsSmi`, `IsHeapNumber`, `IsString`, `IsBigInt` (type checking)
    * `Float64Equal`, `Word32Equal` (low-level comparisons)
    * `HasProperty`, `Typeof`, `InstanceOf` (JavaScript operators)
    * `ForInPrepare` (related to `for...in` loops)
    * `Allocate...` (object creation)
    * Code related to `ArrayBuffer`, `TypedArray` (typed arrays in JavaScript)
    * `CodeStubArguments` (handling function arguments)
    * Lots of comparisons and branching based on object types.

3. **Identify Core Functionalities (High-Level):** Based on the initial scan, I can infer that this code is responsible for implementing various JavaScript operations at a low level, likely within the V8 engine's code generation phase. It handles:
    * **Equality comparisons:** Strict equality (`===`), SameValue, potentially abstract equality (`==`) although less explicit here.
    * **Type checking:** Determining the type of JavaScript values.
    * **Property access checks:**  `HasProperty` (the `in` operator).
    * **`typeof` operator.**
    * **`instanceof` operator.**
    * **`for...in` loop preparation.**
    * **Arithmetic and bitwise operations.**
    * **Iterator handling.**
    * **Promise related operations.**
    * **Array and Typed Array operations.**
    * **Function argument handling.**

4. **Focus on the Provided Snippet's Details:** Now, I look closer at the provided code snippet. I see a large function `GenerateEqual` which strongly suggests this section heavily deals with **strict equality (`===`)**. The code branches extensively based on the types of the operands (`lhs` and `rhs`). It handles:
    * **Identity comparison:** `TaggedEqual` (are they the exact same object?).
    * **Smi (small integer) comparisons.**
    * **HeapNumber (double) comparisons.**
    * **String comparisons.**
    * **BigInt comparisons.**
    * **Handling of special cases like NaN.**
    * **Type feedback (optimization hints).**

5. **Connect to JavaScript:**  The operations implemented in this C++ code directly correspond to JavaScript language features. I need to provide concrete JavaScript examples. For the `GenerateEqual` function, the most obvious connection is the `===` operator.

6. **Construct the Summary:** I start writing the summary, focusing on the identified core functionalities. I emphasize the role of `CodeStubAssembler` in low-level code generation. I highlight the key JavaScript operations being implemented.

7. **Create JavaScript Examples:**  I create JavaScript code snippets that directly demonstrate the functionality of the C++ code. For example, for `GenerateEqual`, I show comparisons between different types using `===` to illustrate the various branches in the C++ code. I ensure the examples are clear and directly relate to the C++ logic.

8. **Address the "Part 10 of 12" Context:**  Since the user mentioned this is part of a larger sequence, I try to infer if there's anything specific to this stage. The presence of type feedback mechanisms suggests this part of the code generation process is concerned with optimization based on runtime type information. I add a sentence reflecting this.

9. **Review and Refine:** I reread my summary and examples to ensure they are accurate, clear, and concise. I check for any inconsistencies or areas that could be explained better. I make sure the JavaScript examples are correct and effectively illustrate the C++ functionality. I also make sure I've addressed all parts of the user's request.

This iterative process of scanning, identifying, connecting, and refining allows me to generate a comprehensive and accurate summary of the C++ code's functionality and its relationship to JavaScript. The "part 10 of 12" hint helps to slightly contextualize the role of this specific code within the larger code generation pipeline.Based on the provided C++ source code snippet from `v8/src/codegen/code-stub-assembler.cc`, which is part 10 of 12, we can infer the following functionalities:

**Core Functionality:**

This part of the `CodeStubAssembler` focuses on implementing fundamental **comparison and type-related operations** used within the V8 JavaScript engine's code generation process. It provides building blocks for generating machine code that performs tasks like:

* **Strict Equality Comparison (`===`):** The large `GenerateEqual` function is a central piece, meticulously handling strict equality comparisons between various JavaScript value types (Smi, HeapNumber, String, BigInt, etc.). It considers object identity, value equality for primitives, and the special case of NaN. It also incorporates type feedback mechanisms for optimization.
* **SameValue Comparison:** The `BranchIfSameValue` function implements the ECMAScript "SameValue" algorithm, which is similar to strict equality but treats NaN as equal to itself and distinguishes between +0 and -0.
* **Property Existence Check (`in` operator):** The `HasProperty` function implements the logic for checking if an object has a specific property (either own or inherited). It handles different lookup modes and potential Proxy objects.
* **`typeof` Operator:** The `Typeof` function determines the JavaScript type of a given value, returning a string like "number", "string", "object", etc. It also integrates type feedback.
* **`instanceof` Operator:** The `InstanceOf` function implements the logic for the `instanceof` operator, checking if an object is an instance of a constructor.
* **Arithmetic Operations:**  Functions like `NumberInc`, `NumberDec`, `NumberAdd`, and `NumberSub` implement basic arithmetic operations on JavaScript numbers, handling both Smis and HeapNumbers.
* **Bitwise Operations:**  Functions like `BitwiseOp` and `BitwiseSmiOp` implement bitwise operations.
* **Iterator Result Creation:** Functions like `AllocateJSIteratorResult` and `AllocateJSIteratorResultForEntry` are used to create the standard JavaScript iterator result objects (`{ value: ..., done: ... }`).
* **Promise Handling:** The `AllocatePromiseWithResolversResult` function creates objects used in the `Promise.withResolvers` proposal.
* **Array and Typed Array Utilities:** Several functions (`ArraySpeciesCreate`, `ThrowIfArrayBufferIsDetached`, `LoadJSArrayBufferByteLength`, etc.) provide utilities for working with JavaScript Arrays and Typed Arrays, including checking for detached buffers and accessing their properties.
* **Function Argument Handling:** The `CodeStubArguments` class provides a way to access and manipulate the arguments passed to a JavaScript function within the generated code.
* **Elements Kind Checks:**  Functions like `IsFastElementsKind`, `IsFastPackedElementsKind`, etc., are used to check the internal representation of array elements for optimization purposes.

**Relationship to JavaScript with Examples:**

The code in this file directly implements the underlying behavior of various JavaScript language features. Here are some examples:

**1. Strict Equality (`===`)**

The `GenerateEqual` function directly corresponds to how the `===` operator works in JavaScript:

```javascript
// JavaScript examples that would trigger the logic in GenerateEqual

console.log(5 === 5);       // true (Smi comparison)
console.log(5 === 5.0);     // true (Smi and HeapNumber comparison)
console.log("hello" === "hello"); // true (String comparison)
console.log({} === {});     // false (Object identity)
console.log(NaN === NaN);     // false (Special NaN handling)
console.log(1n === 1n);     // true (BigInt comparison)
console.log(1 === 1n);      // false (Different types)
```

**2. `typeof` Operator**

The `Typeof` function is the engine's implementation of the `typeof` operator:

```javascript
// JavaScript examples that would trigger the logic in Typeof

console.log(typeof 42);         // "number"
console.log(typeof "hello");    // "string"
console.log(typeof {});          // "object"
console.log(typeof null);        // "object" (historical quirk)
console.log(typeof undefined);   // "undefined"
console.log(typeof function(){}); // "function"
console.log(typeof Symbol());     // "symbol"
console.log(typeof 10n);        // "bigint"
```

**3. `instanceof` Operator**

The `InstanceOf` function underlies the `instanceof` operator:

```javascript
// JavaScript examples that would trigger the logic in InstanceOf

class MyClass {}
const myInstance = new MyClass();
console.log(myInstance instanceof MyClass);   // true
console.log([] instanceof Array);           // true
console.log(42 instanceof Number);          // false
console.log(new Number(42) instanceof Number); // true
```

**4. `for...in` Loop Preparation**

The `ForInPrepare` function is involved when a `for...in` loop is encountered:

```javascript
const obj = { a: 1, b: 2, c: 3 };
for (let key in obj) {
  console.log(key); // "a", "b", "c" (order not guaranteed)
}
```

**In Summary for Part 10:**

This specific part of `code-stub-assembler.cc` is heavily focused on implementing the core logic for fundamental JavaScript operations related to **comparison, type checking, and basic arithmetic**. It provides the low-level building blocks that the V8 engine uses during code generation to execute these operations efficiently. Being part 10 of 12 suggests it's dealing with the core operational semantics after some initial setup and before final code emission or optimization stages.

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第10部分，共12部分，请归纳一下它的功能
```

### 源代码
```
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
    GotoIfNot(IsCallable(CAST(callable)), &if_notcallable);

    // Use the OrdinaryHasInstance algorithm.
    var_result = CAST(
        CallBuiltin(Builtin::kOrdinaryHasInstance, context, callable, object));
    Goto(&return_result);
  }

  BIND(&if_notcallable);
  { ThrowTypeError(context, MessageTemplate::kNonCallableInInstanceOfCheck); }

  BIND(&if_notreceiver);
  { ThrowTypeError(context, MessageTemplate::kNonObjectInInstanceOfCheck); }

  BIND(&return_true);
  var_result = TrueConstant();
  Goto(&return_result);

  BIND(&return_false);
  var_result = FalseConstant();
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberInc(TNode<Number> value) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_finc_value);
  Label if_issmi(this), if_isnotsmi(this), do_finc(this), end(this);
  Branch(TaggedIsSmi(value), &if_issmi, &if_isnotsmi);

  BIND(&if_issmi);
  {
    Label if_overflow(this);
    TNode<Smi> smi_value = CAST(value);
    TNode<Smi> one = SmiConstant(1);
    var_result = TrySmiAdd(smi_value, one, &if_overflow);
    Goto(&end);

    BIND(&if_overflow);
    {
      var_finc_value = SmiToFloat64(smi_value);
      Goto(&do_finc);
    }
  }

  BIND(&if_isnotsmi);
  {
    TNode<HeapNumber> heap_number_value = CAST(value);

    // Load the HeapNumber value.
    var_finc_value = LoadHeapNumberValue(heap_number_value);
    Goto(&do_finc);
  }

  BIND(&do_finc);
  {
    TNode<Float64T> finc_value = var_finc_value.value();
    TNode<Float64T> one = Float64Constant(1.0);
    TNode<Float64T> finc_result = Float64Add(finc_value, one);
    var_result = AllocateHeapNumberWithValue(finc_result);
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberDec(TNode<Number> value) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_fdec_value);
  Label if_issmi(this), if_isnotsmi(this), do_fdec(this), end(this);
  Branch(TaggedIsSmi(value), &if_issmi, &if_isnotsmi);

  BIND(&if_issmi);
  {
    TNode<Smi> smi_value = CAST(value);
    TNode<Smi> one = SmiConstant(1);
    Label if_overflow(this);
    var_result = TrySmiSub(smi_value, one, &if_overflow);
    Goto(&end);

    BIND(&if_overflow);
    {
      var_fdec_value = SmiToFloat64(smi_value);
      Goto(&do_fdec);
    }
  }

  BIND(&if_isnotsmi);
  {
    TNode<HeapNumber> heap_number_value = CAST(value);

    // Load the HeapNumber value.
    var_fdec_value = LoadHeapNumberValue(heap_number_value);
    Goto(&do_fdec);
  }

  BIND(&do_fdec);
  {
    TNode<Float64T> fdec_value = var_fdec_value.value();
    TNode<Float64T> minus_one = Float64Constant(-1.0);
    TNode<Float64T> fdec_result = Float64Add(fdec_value, minus_one);
    var_result = AllocateHeapNumberWithValue(fdec_result);
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberAdd(TNode<Number> a, TNode<Number> b) {
  TVARIABLE(Number, var_result);
  Label float_add(this, Label::kDeferred), end(this);
  GotoIf(TaggedIsNotSmi(a), &float_add);
  GotoIf(TaggedIsNotSmi(b), &float_add);

  // Try fast Smi addition first.
  var_result = TrySmiAdd(CAST(a), CAST(b), &float_add);
  Goto(&end);

  BIND(&float_add);
  {
    var_result = ChangeFloat64ToTagged(
        Float64Add(ChangeNumberToFloat64(a), ChangeNumberToFloat64(b)));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NumberSub(TNode<Number> a, TNode<Number> b) {
  TVARIABLE(Number, var_result);
  Label float_sub(this, Label::kDeferred), end(this);
  GotoIf(TaggedIsNotSmi(a), &float_sub);
  GotoIf(TaggedIsNotSmi(b), &float_sub);

  // Try fast Smi subtraction first.
  var_result = TrySmiSub(CAST(a), CAST(b), &float_sub);
  Goto(&end);

  BIND(&float_sub);
  {
    var_result = ChangeFloat64ToTagged(
        Float64Sub(ChangeNumberToFloat64(a), ChangeNumberToFloat64(b)));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

void CodeStubAssembler::GotoIfNotNumber(TNode<Object> input,
                                        Label* is_not_number) {
  Label is_number(this);
  GotoIf(TaggedIsSmi(input), &is_number);
  Branch(IsHeapNumber(CAST(input)), &is_number, is_not_number);
  BIND(&is_number);
}

void CodeStubAssembler::GotoIfNumber(TNode<Object> input, Label* is_number) {
  GotoIf(TaggedIsSmi(input), is_number);
  GotoIf(IsHeapNumber(CAST(input)), is_number);
}

TNode<Word32T> CodeStubAssembler::NormalizeShift32OperandIfNecessary(
    TNode<Word32T> right32) {
  TVARIABLE(Word32T, result, right32);
  Label done(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIf(UniqueInt32Constant(Word32ShiftIsSafe()), &done);
  {
    result = Word32And(right32, Int32Constant(0x1F));
    Goto(&done);
  }
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::BitwiseOp(TNode<Word32T> left32,
                                           TNode<Word32T> right32,
                                           Operation bitwise_op) {
  switch (bitwise_op) {
    case Operation::kBitwiseAnd:
      return ChangeInt32ToTagged(Signed(Word32And(left32, right32)));
    case Operation::kBitwiseOr:
      return ChangeInt32ToTagged(Signed(Word32Or(left32, right32)));
    case Operation::kBitwiseXor:
      return ChangeInt32ToTagged(Signed(Word32Xor(left32, right32)));
    case Operation::kShiftLeft:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeInt32ToTagged(Signed(Word32Shl(left32, right32)));
    case Operation::kShiftRight:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeInt32ToTagged(Signed(Word32Sar(left32, right32)));
    case Operation::kShiftRightLogical:
      right32 = NormalizeShift32OperandIfNecessary(right32);
      return ChangeUint32ToTagged(Unsigned(Word32Shr(left32, right32)));
    default:
      break;
  }
  UNREACHABLE();
}

TNode<Number> CodeStubAssembler::BitwiseSmiOp(TNode<Smi> left, TNode<Smi> right,
                                              Operation bitwise_op) {
  switch (bitwise_op) {
    case Operation::kBitwiseAnd:
      return SmiAnd(left, right);
    case Operation::kBitwiseOr:
      return SmiOr(left, right);
    case Operation::kBitwiseXor:
      return SmiXor(left, right);
    // Smi shift left and logical shift rihgt can have (Heap)Number output, so
    // perform int32 operation.
    case Operation::kShiftLeft:
    case Operation::kShiftRightLogical:
      return BitwiseOp(SmiToInt32(left), SmiToInt32(right), bitwise_op);
    // Arithmetic shift right of a Smi can't overflow to the heap number, so
    // perform int32 operation but don't check for overflow.
    case Operation::kShiftRight: {
      TNode<Int32T> left32 = SmiToInt32(left);
      TNode<Int32T> right32 =
          Signed(NormalizeShift32OperandIfNecessary(SmiToInt32(right)));
      return ChangeInt32ToTaggedNoOverflow(Word32Sar(left32, right32));
    }
    default:
      break;
  }
  UNREACHABLE();
}

TNode<JSObject> CodeStubAssembler::AllocateJSIteratorResult(
    TNode<Context> context, TNode<Object> value, TNode<Boolean> done) {
  CSA_DCHECK(this, IsBoolean(done));
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSIteratorResult::kSize);
  StoreMapNoWriteBarrier(result, map);
  StoreObjectFieldRoot(result, JSIteratorResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSIteratorResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kValueOffset, value);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kDoneOffset, done);
  return CAST(result);
}

TNode<JSObject> CodeStubAssembler::AllocateJSIteratorResultForEntry(
    TNode<Context> context, TNode<Object> key, TNode<Object> value) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Smi> length = SmiConstant(2);
  int const elements_size = FixedArray::SizeFor(2);
  TNode<FixedArray> elements =
      UncheckedCast<FixedArray>(Allocate(elements_size));
  StoreObjectFieldRoot(elements, offsetof(FixedArray, map_),
                       RootIndex::kFixedArrayMap);
  StoreObjectFieldNoWriteBarrier(elements, offsetof(FixedArray, length_),
                                 length);
  StoreFixedArrayElement(elements, 0, key);
  StoreFixedArrayElement(elements, 1, value);
  TNode<Map> array_map = CAST(LoadContextElement(
      native_context, Context::JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX));
  TNode<HeapObject> array =
      Allocate(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize));
  StoreMapNoWriteBarrier(array, array_map);
  StoreObjectFieldRoot(array, JSArray::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(array, JSArray::kElementsOffset, elements);
  StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
  TNode<Map> iterator_map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSIteratorResult::kSize);
  StoreMapNoWriteBarrier(result, iterator_map);
  StoreObjectFieldRoot(result, JSIteratorResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSIteratorResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kValueOffset, array);
  StoreObjectFieldRoot(result, JSIteratorResult::kDoneOffset,
                       RootIndex::kFalseValue);
  return CAST(result);
}

TNode<JSObject> CodeStubAssembler::AllocatePromiseWithResolversResult(
    TNode<Context> context, TNode<Object> promise, TNode<Object> resolve,
    TNode<Object> reject) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::PROMISE_WITHRESOLVERS_RESULT_MAP_INDEX));
  TNode<HeapObject> result = Allocate(JSPromiseWithResolversResult::kSize);
  StoreMapNoWriteBarrier(result, map);
  StoreObjectFieldRoot(result,
                       JSPromiseWithResolversResult::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(result, JSPromiseWithResolversResult::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kPromiseOffset, promise);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kResolveOffset, resolve);
  StoreObjectFieldNoWriteBarrier(
      result, JSPromiseWithResolversResult::kRejectOffset, reject);
  return CAST(result);
}

TNode<JSReceiver> CodeStubAssembler::ArraySpeciesCreate(TNode<Context> context,
                                                        TNode<Object> o,
                                                        TNode<Number> len) {
  TNode<JSReceiver> constructor =
      CAST(CallRuntime(Runtime::kArraySpeciesConstructor, context, o));
  return Construct(context, constructor, len);
}

void CodeStubAssembler::ThrowIfArrayBufferIsDetached(
    TNode<Context> context, TNode<JSArrayBuffer> array_buffer,
    const char* method_name) {
  Label if_detached(this, Label::kDeferred), if_not_detached(this);
  Branch(IsDetachedBuffer(array_buffer), &if_detached, &if_not_detached);
  BIND(&if_detached);
  ThrowTypeError(context, MessageTemplate::kDetachedOperation, method_name);
  BIND(&if_not_detached);
}

void CodeStubAssembler::ThrowIfArrayBufferViewBufferIsDetached(
    TNode<Context> context, TNode<JSArrayBufferView> array_buffer_view,
    const char* method_name) {
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array_buffer_view);
  ThrowIfArrayBufferIsDetached(context, buffer, method_name);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferByteLength(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadBoundedSizeFromObject(array_buffer,
                                   JSArrayBuffer::kRawByteLengthOffset);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferMaxByteLength(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadBoundedSizeFromObject(array_buffer,
                                   JSArrayBuffer::kRawMaxByteLengthOffset);
}

TNode<RawPtrT> CodeStubAssembler::LoadJSArrayBufferBackingStorePtr(
    TNode<JSArrayBuffer> array_buffer) {
  return LoadSandboxedPointerFromObject(array_buffer,
                                        JSArrayBuffer::kBackingStoreOffset);
}

TNode<JSArrayBuffer> CodeStubAssembler::LoadJSArrayBufferViewBuffer(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadObjectField<JSArrayBuffer>(array_buffer_view,
                                        JSArrayBufferView::kBufferOffset);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadBoundedSizeFromObject(array_buffer_view,
                                   JSArrayBufferView::kRawByteLengthOffset);
}

void CodeStubAssembler::StoreJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(array_buffer_view,
                           JSArrayBufferView::kRawByteLengthOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSArrayBufferViewByteOffset(
    TNode<JSArrayBufferView> array_buffer_view) {
  return LoadBoundedSizeFromObject(array_buffer_view,
                                   JSArrayBufferView::kRawByteOffsetOffset);
}

void CodeStubAssembler::StoreJSArrayBufferViewByteOffset(
    TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(array_buffer_view,
                           JSArrayBufferView::kRawByteOffsetOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSTypedArrayLength(
    TNode<JSTypedArray> typed_array) {
  return LoadBoundedSizeFromObject(typed_array, JSTypedArray::kRawLengthOffset);
}

void CodeStubAssembler::StoreJSTypedArrayLength(TNode<JSTypedArray> typed_array,
                                                TNode<UintPtrT> value) {
  StoreBoundedSizeToObject(typed_array, JSTypedArray::kRawLengthOffset, value);
}

TNode<UintPtrT> CodeStubAssembler::LoadJSTypedArrayLengthAndCheckDetached(
    TNode<JSTypedArray> typed_array, Label* detached) {
  TVARIABLE(UintPtrT, result);
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(typed_array);

  Label variable_length(this), fixed_length(this), end(this);
  Branch(IsVariableLengthJSArrayBufferView(typed_array), &variable_length,
         &fixed_length);
  BIND(&variable_length);
  {
    result =
        LoadVariableLengthJSTypedArrayLength(typed_array, buffer, detached);
    Goto(&end);
  }

  BIND(&fixed_length);
  {
    Label not_detached(this);
    Branch(IsDetachedBuffer(buffer), detached, &not_detached);
    BIND(&not_detached);
    result = LoadJSTypedArrayLength(typed_array);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

// ES #sec-integerindexedobjectlength
TNode<UintPtrT> CodeStubAssembler::LoadVariableLengthJSTypedArrayLength(
    TNode<JSTypedArray> array, TNode<JSArrayBuffer> buffer,
    Label* detached_or_out_of_bounds) {
  // byte_length already takes array's offset into account.
  TNode<UintPtrT> byte_length = LoadVariableLengthJSArrayBufferViewByteLength(
      array, buffer, detached_or_out_of_bounds);
  TNode<IntPtrT> element_size =
      RabGsabElementsKindToElementByteSize(LoadElementsKind(array));
  return Unsigned(IntPtrDiv(Signed(byte_length), element_size));
}

TNode<UintPtrT>
CodeStubAssembler::LoadVariableLengthJSArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array, TNode<JSArrayBuffer> buffer,
    Label* detached_or_out_of_bounds) {
  Label is_gsab(this), is_rab(this), end(this);
  TVARIABLE(UintPtrT, result);
  TNode<UintPtrT> array_byte_offset = LoadJSArrayBufferViewByteOffset(array);

  Branch(IsSharedArrayBuffer(buffer), &is_gsab, &is_rab);
  BIND(&is_gsab);
  {
    // Non-length-tracking GSAB-backed ArrayBufferViews shouldn't end up here.
    CSA_DCHECK(this, IsLengthTrackingJSArrayBufferView(array));
    // Read the byte length from the BackingStore.
    const TNode<ExternalReference> byte_length_function =
        ExternalConstant(ExternalReference::gsab_byte_length());
    TNode<ExternalReference> isolate_ptr =
        ExternalConstant(ExternalReference::isolate_address());
    TNode<UintPtrT> buffer_byte_length = UncheckedCast<UintPtrT>(
        CallCFunction(byte_length_function, MachineType::UintPtr(),
                      std::make_pair(MachineType::Pointer(), isolate_ptr),
                      std::make_pair(MachineType::AnyTagged(), buffer)));
    // Since the SharedArrayBuffer can't shrink, and we've managed to create
    // this JSArrayBufferDataView without throwing an exception, we know that
    // buffer_byte_length >= array_byte_offset.
    CSA_CHECK(this,
              UintPtrGreaterThanOrEqual(buffer_byte_length, array_byte_offset));
    result = UintPtrSub(buffer_byte_length, array_byte_offset);
    Goto(&end);
  }

  BIND(&is_rab);
  {
    GotoIf(IsDetachedBuffer(buffer), detached_or_out_of_bounds);

    TNode<UintPtrT> buffer_byte_length = LoadJSArrayBufferByteLength(buffer);

    Label is_length_tracking(this), not_length_tracking(this);
    Branch(IsLengthTrackingJSArrayBufferView(array), &is_length_tracking,
           &not_length_tracking);

    BIND(&is_length_tracking);
    {
      // The backing RAB might have been shrunk so that the start of the
      // TypedArray is already out of bounds.
      GotoIfNot(UintPtrLessThanOrEqual(array_byte_offset, buffer_byte_length),
                detached_or_out_of_bounds);
      result = UintPtrSub(buffer_byte_length, array_byte_offset);
      Goto(&end);
    }

    BIND(&not_length_tracking);
    {
      // Check if the backing RAB has shrunk so that the buffer is out of
      // bounds.
      TNode<UintPtrT> array_byte_length =
          LoadJSArrayBufferViewByteLength(array);
      GotoIfNot(UintPtrGreaterThanOrEqual(
                    buffer_byte_length,
                    UintPtrAdd(array_byte_offset, array_byte_length)),
                detached_or_out_of_bounds);
      result = array_byte_length;
      Goto(&end);
    }
  }
  BIND(&end);
  return result.value();
}

void CodeStubAssembler::IsJSArrayBufferViewDetachedOrOutOfBounds(
    TNode<JSArrayBufferView> array_buffer_view, Label* detached_or_oob,
    Label* not_detached_nor_oob) {
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array_buffer_view);

  GotoIf(IsDetachedBuffer(buffer), detached_or_oob);
  GotoIfNot(IsVariableLengthJSArrayBufferView(array_buffer_view),
            not_detached_nor_oob);
  GotoIf(IsSharedArrayBuffer(buffer), not_detached_nor_oob);

  {
    TNode<UintPtrT> buffer_byte_length = LoadJSArrayBufferByteLength(buffer);
    TNode<UintPtrT> array_byte_offset =
        LoadJSArrayBufferViewByteOffset(array_buffer_view);

    Label length_tracking(this), not_length_tracking(this);
    Branch(IsLengthTrackingJSArrayBufferView(array_buffer_view),
           &length_tracking, &not_length_tracking);

    BIND(&length_tracking);
    {
      // The backing RAB might have been shrunk so that the start of the
      // TypedArray is already out of bounds.
      Branch(UintPtrLessThanOrEqual(array_byte_offset, buffer_byte_length),
             not_detached_nor_oob, detached_or_oob);
    }

    BIND(&not_length_tracking);
    {
      // Check if the backing RAB has shrunk so that the buffer is out of
      // bounds.
      TNode<UintPtrT> array_byte_length =
          LoadJSArrayBufferViewByteLength(array_buffer_view);
      Branch(UintPtrGreaterThanOrEqual(
                 buffer_byte_length,
                 UintPtrAdd(array_byte_offset, array_byte_length)),
             not_detached_nor_oob, detached_or_oob);
    }
  }
}

TNode<BoolT> CodeStubAssembler::IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(
    TNode<JSArrayBufferView> array_buffer_view) {
  Label is_detached_or_out_of_bounds(this),
      not_detached_nor_out_of_bounds(this), end(this);
  TVARIABLE(BoolT, result);

  IsJSArrayBufferViewDetachedOrOutOfBounds(array_buffer_view,
                                           &is_detached_or_out_of_bounds,
                                           &not_detached_nor_out_of_bounds);
  BIND(&is_detached_or_out_of_bounds);
  {
    result = BoolConstant(true);
    Goto(&end);
  }
  BIND(&not_detached_nor_out_of_bounds);
  {
    result = BoolConstant(false);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

void CodeStubAssembler::CheckJSTypedArrayIndex(
    TNode<JSTypedArray> typed_array, TNode<UintPtrT> index,
    Label* detached_or_out_of_bounds) {
  TNode<UintPtrT> len = LoadJSTypedArrayLengthAndCheckDetached(
      typed_array, detached_or_out_of_bounds);

  GotoIf(UintPtrGreaterThanOrEqual(index, len), detached_or_out_of_bounds);
}

// ES #sec-integerindexedobjectbytelength
TNode<UintPtrT> CodeStubAssembler::LoadVariableLengthJSTypedArrayByteLength(
    TNode<Context> context, TNode<JSTypedArray> array,
    TNode<JSArrayBuffer> buffer) {
  Label miss(this), end(this);
  TVARIABLE(UintPtrT, result);

  TNode<UintPtrT> length =
      LoadVariableLengthJSTypedArrayLength(array, buffer, &miss);
  TNode<IntPtrT> element_size =
      RabGsabElementsKindToElementByteSize(LoadElementsKind(array));
  // Conversion to signed is OK since length < JSArrayBuffer::kMaxByteLength.
  TNode<IntPtrT> byte_length = IntPtrMul(Signed(length), element_size);
  result = Unsigned(byte_length);
  Goto(&end);
  BIND(&miss);
  {
    result = UintPtrConstant(0);
    Goto(&end);
  }
  BIND(&end);
  return result.value();
}

TNode<IntPtrT> CodeStubAssembler::RabGsabElementsKindToElementByteSize(
    TNode<Int32T> elements_kind) {
  TVARIABLE(IntPtrT, result);
  Label elements_8(this), elements_16(this), elements_32(this),
      elements_64(this), not_found(this), end(this);
  int32_t elements_kinds[] = {
      RAB_GSAB_UINT8_ELEMENTS,    RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
      RAB_GSAB_INT8_ELEMENTS,     RAB_GSAB_UINT16_ELEMENTS,
      RAB_GSAB_INT16_ELEMENTS,    RAB_GSAB_FLOAT16_ELEMENTS,
      RAB_GSAB_UINT32_ELEMENTS,   RAB_GSAB_INT32_ELEMENTS,
      RAB_GSAB_FLOAT32_ELEMENTS,  RAB_GSAB_FLOAT64_ELEMENTS,
      RAB_GSAB_BIGINT64_ELEMENTS, RAB_GSAB_BIGUINT64_ELEMENTS};
  Label* elements_kind_labels[] = {&elements_8,  &elements_8,  &elements_8,
                                   &elements_16, &elements_16, &elements_16,
                                   &elements_32, &elements_32, &elements_32,
                                   &elements_64, &elements_64, &elements_64};
  const size_t kTypedElementsKindCount =
      LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND -
      FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1;
  DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kinds));
  DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kind_labels));
  Switch(elements_kind, &not_found, elements_kinds, elements_kind_labels,
         kTypedElementsKindCount);
  BIND(&elements_8);
  {
    result = IntPtrConstant(1);
    Goto(&end);
  }
  BIND(&elements_16);
  {
    result = IntPtrConstant(2);
    Goto(&end);
  }
  BIND(&elements_32);
  {
    result = IntPtrConstant(4);
    Goto(&end);
  }
  BIND(&elements_64);
  {
    result = IntPtrConstant(8);
    Goto(&end);
  }
  BIND(&not_found);
  { Unreachable(); }
  BIND(&end);
  return result.value();
}

TNode<JSArrayBuffer> CodeStubAssembler::GetTypedArrayBuffer(
    TNode<Context> context, TNode<JSTypedArray> array) {
  Label call_runtime(this), done(this);
  TVARIABLE(Object, var_result);

  GotoIf(IsOnHeapTypedArray(array), &call_runtime);

  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array);
  GotoIf(IsDetachedBuffer(buffer), &call_runtime);
  var_result = buffer;
  Goto(&done);

  BIND(&call_runtime);
  {
    var_result = CallRuntime(Runtime::kTypedArrayGetBuffer, context, array);
    Goto(&done);
  }

  BIND(&done);
  return CAST(var_result.value());
}

CodeStubArguments::CodeStubArguments(CodeStubAssembler* assembler,
                                     TNode<IntPtrT> argc, TNode<RawPtrT> fp)
    : assembler_(assembler),
      argc_(argc),
      base_(),
      fp_(fp != nullptr ? fp : assembler_->LoadFramePointer()) {
  TNode<IntPtrT> offset = assembler_->IntPtrConstant(
      (StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
      kSystemPointerSize);
  DCHECK_NOT_NULL(argc_);
  // base_ points to the first argument, not the receiver
  // whether present or not.
  base_ = assembler_->RawPtrAdd(fp_, offset);
}

bool CodeStubArguments::MayHavePaddingArguments() const {
  // If we're using a dynamic parameter count, then there may be additional
  // padding arguments on the stack pushed by the caller.
  return assembler_->HasDynamicJSParameterCount();
}

TNode<Object> CodeStubArguments::GetReceiver() const {
  intptr_t offset = -kSystemPointerSize;
  return assembler_->LoadFullTagged(base_, assembler_->IntPtrConstant(offset));
}

void CodeStubArguments::SetReceiver(TNode<Object> object) const {
  intptr_t offset = -kSystemPointerSize;
  assembler_->StoreFullTaggedNoWriteBarrier(
      base_, assembler_->IntPtrConstant(offset), object);
}

TNode<RawPtrT> CodeStubArguments::AtIndexPtr(TNode<IntPtrT> index) const {
  TNode<IntPtrT> offset =
      assembler_->ElementOffsetFromIndex(index, SYSTEM_POINTER_ELEMENTS, 0);
  return assembler_->RawPtrAdd(base_, offset);
}

TNode<Object> CodeStubArguments::AtIndex(TNode<IntPtrT> index) const {
  CSA_DCHECK(assembler_, assembler_->UintPtrOrSmiLessThan(
                             index, GetLengthWithoutReceiver()));
  return assembler_->LoadFullTagged(AtIndexPtr(index));
}

TNode<Object> CodeStubArguments::AtIndex(int index) const {
  return AtIndex(assembler_->IntPtrConstant(index));
}

TNode<IntPtrT> CodeStubArguments::GetLengthWithoutReceiver() const {
  return assembler_->IntPtrSub(
      argc_, assembler_->IntPtrConstant(kJSArgcReceiverSlots));
}

TNode<IntPtrT> CodeStubArguments::GetLengthWithReceiver() const {
  return argc_;
}

TNode<Object> CodeStubArguments::GetOptionalArgumentValue(
    TNode<IntPtrT> index, TNode<Object> default_value) {
  CodeStubAssembler::TVariable<Object> result(assembler_);
  CodeStubAssembler::Label argument_missing(assembler_),
      argument_done(assembler_, &result);

  assembler_->GotoIf(
      assembler_->UintPtrGreaterThanOrEqual(index, GetLengthWithoutReceiver()),
      &argument_missing);
  result = AtIndex(index);
  assembler_->Goto(&argument_done);

  assembler_->BIND(&argument_missing);
  result = default_value;
  assembler_->Goto(&argument_done);

  assembler_->BIND(&argument_done);
  return result.value();
}

void CodeStubArguments::SetArgumentValue(TNode<IntPtrT> index,
                                         TNode<Object> value) {
  TNode<RawPtrT> slot = AtIndexPtr(index);
  assembler_->StoreFullTaggedNoWriteBarrier(slot, value);
}

void CodeStubArguments::ForEach(
    const CodeStubAssembler::VariableList& vars,
    const CodeStubArguments::ForEachBodyFunction& body, TNode<IntPtrT> first,
    TNode<IntPtrT> last) const {
  assembler_->Comment("CodeStubArguments::ForEach");
  if (first == nullptr) {
    first = assembler_->IntPtrConstant(0);
  }
  if (last == nullptr) {
    last = GetLengthWithoutReceiver();
  }
  TNode<RawPtrT> start = AtIndexPtr(first);
  TNode<RawPtrT> end = AtIndexPtr(last);
  const int increment = kSystemPointerSize;
  assembler_->BuildFastLoop<RawPtrT>(
      vars, start, end,
      [&](TNode<RawPtrT> current) {
        TNode<Object> arg = assembler_->LoadFullTagged(current);
        body(arg);
      },
      increment, CodeStubAssembler::LoopUnrollingMode::kNo,
      CodeStubAssembler::IndexAdvanceMode::kPost);
}

void CodeStubArguments::PopAndReturn(TNode<Object> value) {
  TNode<IntPtrT> argument_count = GetLengthWithReceiver();
  if (MayHavePaddingArguments()) {
    // If there may be padding arguments, we need to remove the maximum of the
    // parameter count and the actual argument count.
    // TODO(saelo): it would probably be nicer to have this logic in the
    // low-level assembler instead, where we also keep the parameter count
    // value. It's not even clear why we need this PopAndReturn method at all
    // in the higher-level CodeStubAssembler class, as the lower-level
    // assemblers should have all the necessary information.
    TNode<IntPtrT> parameter_count =
        assembler_->ChangeInt32ToIntPtr(assembler_->DynamicJSParameterCount());
    CodeStubAssembler::Label pop_parameter_count(assembler_),
        pop_argument_count(assembler_);
    assembler_->Branch(
        assembler_->IntPtrLessThan(argument_count, parameter_count),
        &pop_parameter_count, &pop_argument_count);
    assembler_->BIND(&pop_parameter_count);
    assembler_->PopAndReturn(parameter_count, value);
    assembler_->BIND(&pop_argument_count);
    assembler_->PopAndReturn(argument_count, value);
  } else {
    assembler_->PopAndReturn(argument_count, value);
  }
}

TNode<BoolT> CodeStubAssembler::IsFastElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(LAST_FAST_ELEMENTS_KIND));
}

TNode<BoolT> CodeStubAssembler::IsFastPackedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  // ElementsKind values that are even are packed. See
  // internal::IsFastPackedElementsKind.
  static_assert((~PACKED_SMI_ELEMENTS & 1) == 1);
  static_assert((~PACKED_ELEMENTS & 1) == 1);
  static_assert((~PACKED_DOUBLE_ELEMENTS & 1) == 1);
  return Word32And(IsNotSetWord32(elements_kind, 1),
                   IsFastElementsKind(elements_kind));
}

TNode<BoolT> CodeStubAssembler::IsFastOrNonExtensibleOrSealedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert(LAST_FAST_ELEMENTS_KIND + 1 == PACKED_NONEXTENSIBLE_ELEMENTS);
  static_assert(PACKED_NONEXTENSIBLE_ELEMENTS + 1 ==
                HOLEY_NONEXTENSIBLE_ELEMENTS);
  static_assert(HOLEY_NONEXTENSIBLE_ELEMENTS + 1 == PACKED_SEALED_ELEMENTS);
  static_assert(PACKED_SEALED_ELEMENTS + 1 == HOLEY_SEALED_ELEMENTS);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(HOLEY_SEALED_ELEMENTS));
}

TNode<BoolT> CodeStubAssembler::IsDoubleElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert((PACKED_DOUBLE_ELEMENTS & 1) == 0);
  static_assert(PACKED_DOUBLE_ELEMENTS + 1 == HOLEY_DOUBLE_ELEMENTS);
  return Word32Equal(Word32Shr(elements_kind, Int32Constant(1)),
                     Int32Constant(PACKED_DOUBLE_ELEMENTS / 2));
}

TNode<BoolT> CodeStubAssembler::IsFastSmiOrTaggedElementsKind(
    TNode<Int32T> elements_kind) {
  static_assert(FIRST_ELEMENTS_KIND == FIRST_FAST_ELEMENTS_KIND);
  static_assert(PACKED_DOUBLE_ELEMENTS > TERMINAL_FAST_ELEMENTS_KIND);
  static_assert(HOLEY_DOUBLE_ELEMENTS > TERMINAL_FAST_ELEMENTS_KIND);
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(TERMINAL_FAST_ELEMENTS_KIND));
}

TNode<BoolT> CodeStubAssembler::IsFastSmiElementsKind(
    TNode<Int32T> elements_kind) {
  return Uint32LessThanOrEqual(elements_kind,
                               Int32Constant(HOLEY_SMI_ELEMENTS));
}

TNode<BoolT> CodeStubAssembler::IsHoleyFastElementsKind(
    TNode<Int32T> elements_kind) {
  CSA_DCHECK(this, IsFastElementsKind(elements_kind));

  static_assert(HOLEY_SMI_ELEMENTS == (PACKED_SMI_ELEMENTS | 1));
  static_assert(HOLEY_ELEMENTS == (PACKED_ELEMENTS | 1));
  static_assert(HOLEY_DOUBLE_ELEMENTS == (PACKED_DOUBLE_ELEMENTS | 1));
  return IsSetWord32(elements_kind, 1);
}

TNode<BoolT> CodeStubAssembler::IsHoleyFastElementsKindForRead(
    TNode<Int32T> elements_kind) {
  CSA_DCHECK(this, Uint32LessThanOrEqual(
                       elements_kind,
                       Int32Constant(LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)));

  static_assert(HOLEY_SMI_ELEMENTS == (PACKED_SMI_ELEMENTS | 1));
  static_assert(HOLEY_ELEMENTS == (PACKED_ELEMENTS | 1));
  static_assert(HOLEY_DOUBLE_ELEMENTS == (PACKED_DOUBLE_ELEMENTS | 1));
  static_assert(HOLEY_NONEXTENSIBLE_ELEMENTS ==
```