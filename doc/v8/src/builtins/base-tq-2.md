Response:
Let's break down the thought process for analyzing the provided Torque code and generating the explanation.

**1. Initial Understanding of the Request:**

The request asks for an explanation of the provided Torque code (`v8/src/builtins/base.tq`). Key constraints and requests include:

* **Functionality Listing:**  Identify what the code does.
* **Torque Source:** Confirm it's Torque based on the `.tq` extension.
* **JavaScript Relation:** If relevant, show how it relates to JavaScript.
* **Logic Reasoning:** Provide input/output examples for code with logic.
* **Common Errors:**  Highlight potential user mistakes related to the code.
* **Part 3/3:**  Summarize the overall function of the snippet.

**2. High-Level Analysis (Skimming and Keyword Spotting):**

I'd start by quickly scanning the code for keywords and patterns that indicate functionality:

* **`macro`:**  This is the core building block of Torque. It defines reusable pieces of code. I'd look for descriptive macro names.
* **`extern macro` and `extern builtin`:** These signify calls to lower-level C++ code or built-in V8 functions. These are important for understanding the underlying operations.
* **`transitioning macro` and `transitioning builtin`:** These mark macros and builtins that can potentially trigger garbage collection or other significant state changes.
* **Type Annotations (`JSAny`, `Number`, `uintptr`, `string`, `bool`):** These provide crucial information about the data being processed.
* **Control Flow (`if`, `goto`, `try`, `typeswitch`):**  These show the decision-making and branching logic within the code.
* **Error Handling (`labels`, `ThrowTypeError`):** This indicates how the code handles exceptional situations.
* **Constants (`constexpr`):** These define compile-time values.
* **Specific Function Names (like `ToInteger_Inline`, `GetLengthProperty`, `GetMethod`, `ToIndex`):**  These often correspond to well-known JavaScript operations.

**3. Categorizing Functionality (Iterative Process):**

As I read through the code in more detail, I'd start grouping related macros based on their apparent purpose. This is an iterative process; initial groupings might change as I learn more.

* **Type Checking/Conversion:** Macros like `IsNullOrUndefined`, `SameValue`, `TryNumberToUintPtr`, `ChangeUintPtrNumberToUintPtr`, `ChangeSafeIntegerNumberToUintPtr`, `ToUintPtr`, `ToIndex`. These are clearly about handling different JavaScript data types and converting them.
* **Arithmetic/Overflow Handling:** `CheckIntegerIndexAdditionOverflow`. This stands out as related to index calculations and preventing overflow.
* **Property Access:** `GetLengthProperty`, `GetMethod`, `GetInterestingMethod`. These deal with retrieving properties from JavaScript objects.
* **Index Manipulation:** `ConvertAndClampRelativeIndex`, `ClampToIndexRange`. These seem related to manipulating array indices.
* **Array Specific:** `IsFastJSArray`, `BranchIfFastJSArray`, `FastCreateDataProperty`. These are specific to handling optimized JavaScript arrays.
* **General Utilities:** `VerifiedUnreachable`, `Float64IsSomeInfinity`, `IsIntegerOrSomeInfinity`, `NumberIsSomeInfinity`, `ReplaceTheHoleWithUndefined`, `ConstantIterator`. These are helper functions for various tasks.
* **Low-Level Access:** Macros loading data from memory (`LoadWeakFixedArrayElement`, `LoadUint8Ptr`, `LoadUint64Ptr`, `LoadSimd128`). These suggest interaction with V8's internal memory structures.
* **Hashing:** Macros related to `HashFieldType` and `LoadNameHash`.
* **Name Conversion:** `ToName`.

**4. Detailing Functionality and Providing Examples:**

Once I have a general understanding of the categories, I'd go back and analyze each macro in more detail, explaining its purpose. For those with clear JavaScript equivalents or implications, I'd provide JavaScript examples:

* **`IsNullOrUndefined`:**  Directly relates to `value == null`.
* **`SameValue`:** Corresponds to `Object.is(a, b)`.
* **`ToIndex`:**  Linked to array indexing and the `ToInteger` abstract operation in JavaScript.
* **`GetLengthProperty`:**  Equivalent to accessing the `length` property of an object.
* **`GetMethod`:**  Relates to accessing methods on objects.
* **`ConvertAndClampRelativeIndex`:**  Similar to how array methods like `slice` handle negative indices.

For code with logic (like `CheckIntegerIndexAdditionOverflow` and `ConvertRelativeIndex`), I would construct simple input and output scenarios to illustrate its behavior.

**5. Identifying Common Programming Errors:**

I'd look for macros that address potential pitfalls in JavaScript programming:

* **`IsNullOrUndefined`:**  Relates to the common error of calling methods on `null` or `undefined`.
* **`CheckIntegerIndexAdditionOverflow`:** Addresses the issue of integer overflow when calculating array indices.
* **`ToIndex`:**  Connects to `RangeError` when array indices are out of bounds.
* **`GetMethod`:** Highlights the error of trying to call a non-function property as a method.

**6. Structuring the Explanation:**

I'd organize the explanation logically, grouping related functionalities together. Using headings, bullet points, and code blocks helps improve readability.

**7. Writing the Summary (Part 3):**

For the final summary, I'd synthesize the individual functionalities into a concise overview of the file's purpose. I would highlight the core themes, such as type handling, error prevention, and optimization.

**Self-Correction/Refinement during the process:**

* **Initial misinterpretations:**  If I initially misunderstood the purpose of a macro, I'd correct my understanding as I encountered related macros or more details.
* **Clarity and conciseness:** I'd review my explanations to ensure they are clear, accurate, and avoid unnecessary jargon.
* **Completeness:** I'd double-check that I've addressed all the explicit requests in the prompt.

By following this structured approach, I can systematically analyze the Torque code and generate a comprehensive and informative explanation. The key is to combine high-level understanding with detailed analysis of individual code elements.
This is part 3 of the analysis of the `v8/src/builtins/base.tq` file. Let's summarize the functionalities covered in this final part of the code.

Based on the provided code snippet, here's a breakdown of its functionalities:

**Core Functionalities Covered in Part 3:**

* **Array Optimization and Type Checking:** This section focuses on optimizations for fast JavaScript arrays, including checks for fast array types and mechanisms for efficiently adding elements.
* **Handling of Infinity:**  Provides macros to check if a number is positive or negative infinity.
* **Handling of `TheHole`:** Offers a macro to replace the special `TheHole` value (used internally by V8 to represent uninitialized array elements) with `undefined`.
* **Scope Information Decoding:** Includes a macro to decode information from scope information, likely related to variable resolution.
* **Constant Iteration:** Defines a simple structure and macros for creating constant iterators, which yield the same value repeatedly.
* **Feedback Vector Access:** Provides macros for accessing entries in feedback vectors, which V8 uses for runtime type feedback and optimization.
* **Raw Memory Access:** Offers macros for directly loading data from raw memory pointers (e.g., `LoadUint8Ptr`, `LoadUint64Ptr`). This is a low-level capability for interacting with memory.
* **Name Hashing:** Defines an enum for hash field types and a macro to check equality between them. It also includes a macro to load the hash value of a `Name` object.
* **String/Name Conversion:** Includes an external built-in declaration for converting a `JSAny` value to an `AnyName` (which can be a String or Symbol).
* **SIMD (Single Instruction, Multiple Data) Operations:** Provides macros for loading SIMD128 values and performing bitmask and equality comparisons on I8x16 (16 lanes of 8-bit integers) SIMD vectors.

**JavaScript Relationship and Examples:**

Many of the functionalities in this section are related to V8's internal optimizations and low-level operations. While there aren't always direct, simple JavaScript equivalents, we can see the *impact* of these optimizations in how JavaScript code behaves:

* **Fast Array Operations:** The `IsFastJSArray`, `BranchIfFastJSArray`, and `FastCreateDataProperty` macros are crucial for the performance of common array operations like `push`. When V8 detects that an array meets certain criteria (e.g., it has a simple element structure), it can use these optimized paths.

   ```javascript
   // Example where fast array optimization might apply:
   const arr = [1, 2, 3];
   arr.push(4); // V8 might use optimized code here if 'arr' is a fast array.
   ```

* **Handling of `TheHole`:** While you don't directly interact with `TheHole` in JavaScript, it's related to how sparse arrays are implemented.

   ```javascript
   const sparseArray = new Array(5); // Creates an array with 5 "holes"
   console.log(sparseArray[0]); // Output: undefined (internally, these might initially be represented by TheHole)
   ```

**Code Logic Reasoning and Examples:**

* **`FastCreateDataProperty`:** This macro attempts to add a property to a `FastJSArray` in an optimized way.

   **Assumptions:**
   * `receiver`: A `FastJSArray`.
   * `key`: A `Smi` (small integer) representing the index.
   * `value`: Any `JSAny` value to be added.

   **Logic:**
   1. Checks if the `receiver` is indeed a `FastJSArray`. If not, it goes to the `Slow` path (using the regular `CreateDataProperty`).
   2. Checks if the `key` is a valid `Smi` index within the array bounds.
   3. If appending (`index == array.length`), it ensures the array is pushable and appends the value based on the array's element kind (Smi, Double, or Tagged).
   4. If not appending, it directly stores the value in the array's elements based on the element kind.

   **Example (simplified):**

   ```javascript
   // Hypothetical scenario showing the effect of fast property creation
   const fastArray = [1, 2, 3]; // Assume V8 recognizes this as a fast array
   const indexToAdd = 3;
   const valueToAdd = 4;

   // Internally, V8's FastCreateDataProperty might be used if conditions are met.
   fastArray[indexToAdd] = valueToAdd; // This is the JavaScript operation.
   console.log(fastArray); // Output: [1, 2, 3, 4]
   ```

* **`ReplaceTheHoleWithUndefined`:**

   **Assumptions:**
   * `o`: Either `TheHole` or any other `JSAny` value.

   **Logic:**
   1. If `o` is `TheHole`, it returns `Undefined`.
   2. Otherwise, it returns the original value `o`.

   **Example:**

   ```javascript
   // In a scenario where V8 internally uses TheHole:
   let internalValue = /* ... might be TheHole in some internal representation ... */;
   let jsValue = ReplaceTheHoleWithUndefined(internalValue);
   console.log(jsValue); // Output: undefined (if internalValue was TheHole)
   ```

**Common Programming Errors:**

While these macros are mostly internal to V8, understanding their purpose can shed light on why certain JavaScript operations are faster or slower:

* **Triggering Slow Array Paths:** Performing operations that invalidate the "fast" nature of an array (e.g., adding non-numeric properties, deleting elements in the middle) can cause V8 to fall back to slower, more generic array handling mechanisms. The `FastCreateDataProperty` macro explicitly shows the "Slow" path being taken when conditions for optimization aren't met.

   ```javascript
   const arr = [1, 2, 3]; // Likely a fast array initially
   arr.x = 4;             // Adding a non-index property can make it a "dictionary-mode" array.
   arr.push(5);           // This might now be slower because the array is no longer strictly a "fast" array.
   ```

* **Relying on Specific Internal Representations:**  It's crucial to remember that internal representations like `TheHole` are implementation details of V8. JavaScript code should not directly try to interact with or depend on these internal mechanisms.

**Summary of `v8/src/builtins/base.tq` Functionality (Overall):**

The `v8/src/builtins/base.tq` file serves as a foundational library of Torque macros and built-in declarations used throughout the V8 codebase. It provides:

* **Fundamental Type Handling and Conversion:** Macros for checking types, converting between them, and ensuring values are in the expected format.
* **Error Handling Primitives:** Mechanisms for throwing common JavaScript errors like `TypeError` and `RangeError`.
* **Optimized Property and Method Access:**  Macros that facilitate efficient retrieval of properties and methods from JavaScript objects, including optimizations for common cases.
* **Array Optimization Building Blocks:** Core logic for optimizing operations on fast JavaScript arrays.
* **Low-Level Memory and Internal State Access:** Macros for interacting with V8's internal memory structures and state (e.g., feedback vectors).
* **Mathematical and Logical Operations:** Basic arithmetic and comparison operations tailored for V8's internal types.

Essentially, this file encapsulates common, low-level operations and checks that are used by higher-level built-in functions and compiler optimizations within V8. It promotes code reuse and consistency across the V8 implementation. The focus is on providing efficient and type-safe operations at the heart of the JavaScript engine.

### 提示词
```
这是目录为v8/src/builtins/base.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/base.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
it context: Context)(value: JSAny, name: constexpr string): JSAny {
  if (IsNullOrUndefined(value)) {
    ThrowTypeError(MessageTemplate::kCalledOnNullOrUndefined, name);
  }
  return value;
}

extern macro BranchIfSameValue(
    JSAny|TaggedWithIdentity, JSAny|TaggedWithIdentity): never labels Taken,
    NotTaken;
macro SameValue(
    a: JSAny|TaggedWithIdentity, b: JSAny|TaggedWithIdentity): bool {
  BranchIfSameValue(a, b) otherwise return true, return false;
}

// Does "if (index1 + index2 > limit) goto IfOverflow" in an uintptr overflow
// friendly way where index1 and index2 are in [0, kMaxSafeInteger] range.
macro CheckIntegerIndexAdditionOverflow(
    index1: uintptr, index2: uintptr, limit: uintptr): void labels IfOverflow {
  if constexpr (Is64()) {
    dcheck(index1 <= kMaxSafeIntegerUint64);
    dcheck(index2 <= kMaxSafeIntegerUint64);
    // Given that both index1 and index2 are in a safe integer range the
    // addition can't overflow.
    if (index1 + index2 > limit) goto IfOverflow;
  } else {
    // Uintptr range is "smaller" than [0, kMaxSafeInteger] range, so
    // "index1 + index2" may overflow, so we check the condition in the
    // following way "if (index1 > limit - index2) goto IfOverflow" and check
    // that "limit - index2" does not underflow.
    const index1Limit = limit - index2;
    if (index1 > index1Limit) goto IfOverflow;
    // Handle potential index1Limit underflow.
    if (index1Limit > limit) goto IfOverflow;
  }
}

// TODO(turbofan): Define enum here once they appear in Torque.
//
// The value is a SafeInteger that fits into uintptr range, so no bounds checks
// are necessary.
const kModeValueIsSafeIntegerUintPtr: constexpr int31 = 0;
// The value is a SafeInteger that may not fit into uintptr range, so only
// uintptr bounds check is necessary.
const kModeValueIsSafeInteger: constexpr int31 = 1;
// The value is can be whatever non-NaN number, all checks are necessary.
const kModeValueIsAnyNumber: constexpr int31 = 2;

macro TryNumberToUintPtr(valueNumber: Number, kMode: constexpr int31):
    uintptr labels IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow {
  typeswitch (valueNumber) {
    case (valueSmi: Smi): {
      if (kMode == kModeValueIsAnyNumber) {
        if (valueSmi < 0) goto IfLessThanZero;
      } else {
        dcheck(valueSmi >= 0);
      }
      const value: uintptr = Unsigned(Convert<intptr>(valueSmi));
      // Positive Smi values definitely fit into both [0, kMaxSafeInteger] and
      // [0, kMaxUintPtr] ranges.
      return value;
    }
    case (valueHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(valueHeapNumber));
      const valueDouble: float64 = Convert<float64>(valueHeapNumber);
      // NaNs must be handled outside.
      dcheck(!Float64IsNaN(valueDouble));
      if (kMode == kModeValueIsAnyNumber) {
        if (valueDouble < 0) goto IfLessThanZero;
      } else {
        dcheck(valueDouble >= 0);
      }

      if constexpr (Is64()) {
        // On 64-bit architectures uintptr range is bigger than safe integer
        // range.
        if (kMode == kModeValueIsAnyNumber) {
          if (valueDouble > kMaxSafeInteger) goto IfSafeIntegerOverflow;
        } else {
          dcheck(valueDouble <= kMaxSafeInteger);
        }
      } else {
        // On 32-bit architectures uintptr range is smaller than safe integer
        // range.
        if (kMode == kModeValueIsAnyNumber ||
            kMode == kModeValueIsSafeInteger) {
          if (valueDouble > kMaxUInt32Double) goto IfUIntPtrOverflow;
        } else {
          dcheck(valueDouble <= kMaxUInt32Double);
        }
      }
      return ChangeFloat64ToUintPtr(valueDouble);
    }
  }
}

@export
macro ChangeUintPtrNumberToUintPtr(value: Number): uintptr {
  try {
    return TryNumberToUintPtr(value, kModeValueIsSafeIntegerUintPtr)
        otherwise InvalidValue, InvalidValue, InvalidValue;
  } label InvalidValue {
    unreachable;
  }
}

@export
macro ChangeSafeIntegerNumberToUintPtr(value: Number):
    uintptr labels IfUIntPtrOverflow {
  try {
    return TryNumberToUintPtr(value, kModeValueIsSafeInteger)
        otherwise InvalidValue, IfUIntPtrOverflow, InvalidValue;
  } label InvalidValue {
    unreachable;
  }
}

transitioning macro ToUintPtr(implicit context: Context)(value: JSAny):
    uintptr labels IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow {
  if (value == Undefined) return 0;
  const indexNumber = ToInteger_Inline(value);
  return TryNumberToUintPtr(indexNumber, kModeValueIsAnyNumber)
      otherwise IfLessThanZero, IfUIntPtrOverflow, IfSafeIntegerOverflow;
}

// https://tc39.github.io/ecma262/#sec-toindex
// Unlike ToIndex from the spec this implementation triggers IfRangeError if
// the result is bigger than min(kMaxUIntPtr, kMaxSafeInteger).
// We can do this because all callers do a range checks against uintptr length
// anyway and throw a RangeError in case of out-of-bounds index.
@export
transitioning macro ToIndex(
    implicit context: Context)(value: JSAny): uintptr labels IfRangeError {
  if (value == Undefined) return 0;
  const indexNumber = ToInteger_Inline(value);
  // Less than 0 case, uintptr range overflow and safe integer range overflow
  // imply IfRangeError.
  return TryNumberToUintPtr(indexNumber, kModeValueIsAnyNumber)
      otherwise IfRangeError, IfRangeError, IfRangeError;
}

transitioning macro GetLengthProperty(
    implicit context: Context)(o: JSAny): Number {
  try {
    typeswitch (o) {
      case (a: JSArray): {
        return a.length;
      }
      case (a: JSStrictArgumentsObject): {
        goto ToLength(a.length);
      }
      case (a: JSSloppyArgumentsObject): {
        goto ToLength(a.length);
      }
      case (JSAny): deferred {
        goto ToLength(GetProperty(o, kLengthString));
      }
    }
  } label ToLength(length: JSAny) deferred {
    return ToLength_Inline(length);
  }
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny, name: AnyName):
    Callable labels IfNullOrUndefined,
    IfMethodNotCallable(JSAny) {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(name));
  const value = GetProperty(o, name);
  // TODO(v8:9933): Consider checking for null/undefined after checking for
  // callable because the latter seems to be more common.
  if (value == Undefined || value == Null) goto IfNullOrUndefined;
  return Cast<Callable>(value)
      otherwise goto IfMethodNotCallable(value);
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    name: String): Callable labels IfNullOrUndefined {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(name));
  try {
    return GetMethod(o, name) otherwise IfNullOrUndefined, IfMethodNotCallable;
  } label IfMethodNotCallable(value: JSAny) deferred {
    ThrowTypeError(MessageTemplate::kPropertyNotFunction, value, name, o);
  }
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    name: constexpr string): Callable labels IfNullOrUndefined {
  return GetMethod(o, StringConstant(name)) otherwise IfNullOrUndefined;
}

transitioning macro GetMethod(
    implicit context: Context)(o: JSAny,
    symbol: Symbol): Callable labels IfNullOrUndefined {
  // Use GetInterestingMethod - a version of GetMethod optimized for interesting
  // properties.
  dcheck(!IsInterestingProperty(symbol));
  const value = GetProperty(o, symbol);
  if (value == Undefined || value == Null) goto IfNullOrUndefined;
  return Cast<Callable>(value)
      otherwise ThrowTypeError(
      MessageTemplate::kPropertyNotFunction, value, symbol, o);
}

transitioning macro GetInterestingMethod(
    implicit context: Context)(o: JSReceiver,
    name: String): Callable labels IfNullOrUndefined {
  dcheck(IsInterestingProperty(name));
  try {
    const value = GetInterestingProperty(context, o, name)
        otherwise goto IfNullOrUndefined;
    if (value == Undefined || value == Null) goto IfNullOrUndefined;
    return Cast<Callable>(value)
        otherwise goto IfMethodNotCallable(value);
  } label IfMethodNotCallable(value: JSAny) deferred {
    ThrowTypeError(MessageTemplate::kPropertyNotFunction, value, name, o);
  }
}

extern macro IsOneByteStringMap(Map): bool;
extern macro IsOneByteStringInstanceType(InstanceType): bool;

// After converting an index to an integer, calculate a relative index:
// return index < 0 ? max(length + index, 0) : min(index, length)
@export
transitioning macro ConvertAndClampRelativeIndex(
    implicit context: Context)(index: JSAny, length: uintptr): uintptr {
  const indexNumber: Number = ToInteger_Inline(index);
  return ConvertAndClampRelativeIndex(indexNumber, length);
}

// Calculate a relative index:
// return index < 0 ? max(length + index, 0) : min(index, length)
@export
macro ConvertAndClampRelativeIndex(
    indexNumber: Number, length: uintptr): uintptr {
  try {
    return ConvertRelativeIndex(indexNumber, length) otherwise OutOfBoundsLow,
           OutOfBoundsHigh;
  } label OutOfBoundsLow {
    return 0;
  } label OutOfBoundsHigh {
    return length;
  }
}

// Calculate a relative index with explicit out-of-bounds labels.
macro ConvertRelativeIndex(indexNumber: Number, length: uintptr):
    uintptr labels OutOfBoundsLow, OutOfBoundsHigh {
  typeswitch (indexNumber) {
    case (indexSmi: Smi): {
      const indexIntPtr: intptr = Convert<intptr>(indexSmi);
      // The logic is implemented using unsigned types.
      if (indexIntPtr < 0) {
        const relativeIndex: uintptr = Unsigned(indexIntPtr) + length;
        if (relativeIndex < length) return relativeIndex;
        goto OutOfBoundsLow;

      } else {
        const relativeIndex: uintptr = Unsigned(indexIntPtr);
        if (relativeIndex < length) return relativeIndex;
        goto OutOfBoundsHigh;
      }
    }
    case (indexHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(indexHeapNumber));
      const indexDouble: float64 = Convert<float64>(indexHeapNumber);
      // NaNs must already be handled by ConvertAndClampRelativeIndex() version
      // above accepting JSAny indices.
      dcheck(!Float64IsNaN(indexDouble));
      const lengthDouble: float64 = Convert<float64>(length);
      dcheck(lengthDouble <= kMaxSafeInteger);
      if (indexDouble < 0) {
        const relativeIndex: float64 = lengthDouble + indexDouble;
        if (relativeIndex > 0) {
          return ChangeFloat64ToUintPtr(relativeIndex);
        }
        goto OutOfBoundsLow;

      } else {
        if (indexDouble < lengthDouble) {
          return ChangeFloat64ToUintPtr(indexDouble);
        }
        goto OutOfBoundsHigh;
      }
    }
  }
}

// After converting an index to a signed integer, clamps it to the provided
// range [0, limit]:
// return min(max(index, 0), limit)
@export
transitioning macro ClampToIndexRange(
    implicit context: Context)(index: JSAny, limit: uintptr): uintptr {
  const indexNumber: Number = ToInteger_Inline(index);
  return ClampToIndexRange(indexNumber, limit);
}

// Clamps given signed indexNumber to the provided range [0, limit]:
// return min(max(index, 0), limit)
@export
macro ClampToIndexRange(indexNumber: Number, limit: uintptr): uintptr {
  typeswitch (indexNumber) {
    case (indexSmi: Smi): {
      if (indexSmi < 0) return 0;
      const index: uintptr = Unsigned(Convert<intptr>(indexSmi));
      if (index >= limit) return limit;
      return index;
    }
    case (indexHeapNumber: HeapNumber): {
      dcheck(IsNumberNormalized(indexHeapNumber));
      const indexDouble: float64 = Convert<float64>(indexHeapNumber);
      // NaNs must already be handled by ClampToIndexRange() version
      // above accepting JSAny indices.
      dcheck(!Float64IsNaN(indexDouble));
      if (indexDouble <= 0) return 0;

      const maxIndexDouble: float64 = Convert<float64>(limit);
      dcheck(maxIndexDouble <= kMaxSafeInteger);
      if (indexDouble >= maxIndexDouble) return limit;

      return ChangeFloat64ToUintPtr(indexDouble);
    }
  }
}

extern builtin ObjectToString(Context, JSAny): String;
extern builtin StringRepeat(Context, String, Number): String;

@export
struct KeyValuePair {
  key: JSAny;
  value: JSAny;
}

// Macro definitions for compatibility that expose functionality to the CSA
// using "legacy" APIs. In Torque code, these should not be used.
@export
macro IsFastJSArray(o: Object, context: Context): bool {
  // Long-term, it's likely not a good idea to have this slow-path test here,
  // since it fundamentally breaks the type system.
  if (IsForceSlowPath()) return false;
  return Is<FastJSArray>(o);
}

@export
macro BranchIfFastJSArray(o: Object, context: Context): never labels True,
    False {
  if (IsFastJSArray(o, context)) {
    goto True;
  } else {
    goto False;
  }
}

@export
macro BranchIfFastJSArrayForRead(o: Object, context: Context):
    never labels True, False {
  // Long-term, it's likely not a good idea to have this slow-path test here,
  // since it fundamentally breaks the type system.
  if (IsForceSlowPath()) goto False;
  if (Is<FastJSArrayForRead>(o)) {
    goto True;
  } else {
    goto False;
  }
}

@export
macro IsFastJSArrayWithNoCustomIteration(context: Context, o: Object): bool {
  return Is<FastJSArrayWithNoCustomIteration>(o);
}

@export
macro IsFastJSArrayForReadWithNoCustomIteration(
    context: Context, o: Object): bool {
  return Is<FastJSArrayForReadWithNoCustomIteration>(o);
}

extern transitioning runtime CreateDataProperty(
    implicit context: Context)(JSReceiver, JSAny, JSAny): void;

extern transitioning runtime SetOwnPropertyIgnoreAttributes(
    implicit context: Context)(JSObject, String, JSAny, Smi): void;

namespace runtime {
extern runtime GetDerivedMap(Context, JSFunction, JSReceiver, JSAny): Map;
}
extern macro IsDeprecatedMap(Map): bool;

extern macro LoadSlowObjectWithNullPrototypeMap(NativeContext): Map;

transitioning builtin FastCreateDataProperty(
    implicit context: Context)(receiver: JSReceiver, key: JSAny,
    value: JSAny): Object {
  try {
    const array = Cast<FastJSArray>(receiver) otherwise Slow;
    const index: Smi = Cast<Smi>(key) otherwise goto Slow;
    if (index < 0 || index > array.length) goto Slow;
    const isAppend = index == array.length;

    if (isAppend) {
      // Fast append only works on fast elements kind and with writable length.
      const kind = EnsureArrayPushable(array.map) otherwise Slow;
      array::EnsureWriteableFastElements(array);

      // We may have to transition a.
      // For now, if transition is required, jump away to slow.
      if (IsFastSmiElementsKind(kind)) {
        BuildAppendJSArray(ElementsKind::HOLEY_SMI_ELEMENTS, array, value)
            otherwise Slow;
      } else if (IsDoubleElementsKind(kind)) {
        BuildAppendJSArray(ElementsKind::HOLEY_DOUBLE_ELEMENTS, array, value)
            otherwise Slow;
      } else {
        dcheck(IsFastSmiOrTaggedElementsKind(kind));
        BuildAppendJSArray(ElementsKind::HOLEY_ELEMENTS, array, value)
            otherwise Slow;
      }
    } else {
      // Non-appending element store.
      const kind = array.map.elements_kind;
      array::EnsureWriteableFastElements(array);

      // We may have to transition a.
      // For now, if transition is required, jump away to slow.
      if (IsFastSmiElementsKind(kind)) {
        const smiValue = Cast<Smi>(value) otherwise Slow;
        const elements = Cast<FixedArray>(array.elements) otherwise unreachable;
        elements[index] = smiValue;
      } else if (IsDoubleElementsKind(kind)) {
        const numberValue = Cast<Number>(value) otherwise Slow;
        const doubleElements = Cast<FixedDoubleArray>(array.elements)
            otherwise unreachable;
        doubleElements[index] = numberValue;
      } else {
        dcheck(IsFastSmiOrTaggedElementsKind(kind));
        const elements = Cast<FixedArray>(array.elements) otherwise unreachable;
        elements[index] = value;
      }
    }
  } label Slow {
    CreateDataProperty(receiver, key, value);
  }
  return Undefined;
}

macro VerifiedUnreachable(): never {
  static_assert(false);
  unreachable;
}

macro Float64IsSomeInfinity(value: float64): bool {
  if (value == V8_INFINITY) {
    return true;
  }
  return value == (Convert<float64>(0) - V8_INFINITY);
}

macro IsIntegerOrSomeInfinity(o: Object): bool {
  typeswitch (o) {
    case (Smi): {
      return true;
    }
    case (hn: HeapNumber): {
      if (Float64IsSomeInfinity(Convert<float64>(hn))) {
        return true;
      }
      return IsInteger(hn);
    }
    case (Object): {
      return false;
    }
  }
}

macro NumberIsSomeInfinity(n: Number): bool {
  typeswitch (n) {
    case (Smi): {
      return false;
    }
    case (hn: HeapNumber): {
      return Float64IsSomeInfinity(Convert<float64>(hn));
    }
  }
}

macro ReplaceTheHoleWithUndefined(o: JSAny|TheHole): JSAny {
  typeswitch (o) {
    case (TheHole): {
      return Undefined;
    }
    case (a: JSAny): {
      return a;
    }
  }
}

extern macro DecodeScopeInfoHasContextExtension(intptr): intptr;

struct ConstantIterator<T: type> {
  macro Empty(): bool {
    return false;
  }
  macro Next(): T labels _NoMore {
    return this.value;
  }

  value: T;
}
macro ConstantIterator<T: type>(value: T): ConstantIterator<T> {
  return ConstantIterator{value};
}

extern macro FeedbackIteratorEntrySize(): intptr;
extern macro FeedbackIteratorHandlerOffset(): intptr;
extern operator '[]' macro LoadWeakFixedArrayElement(
    WeakFixedArray, intptr): MaybeObject;

extern operator '[]' macro LoadUint8Ptr(RawPtr<uint8>, intptr): uint8;
extern operator '[]' macro LoadUint64Ptr(RawPtr<uint64>, intptr): uint64;

extern enum HashFieldType extends uint32 constexpr 'Name::HashFieldType' {
  kHash,
  kIntegerIndex,
  kForwardingIndex,
  kEmpty
}

operator '==' macro HashFieldTypeEquals(
    s1: HashFieldType, s2: HashFieldType): bool {
  return Word32Equal(s1, s2);
}

const kNoHashSentinel:
    constexpr int32 generates 'PropertyArray::kNoHashSentinel';
extern macro LoadNameHash(Name): uint32;

extern transitioning builtin ToName(implicit context: Context)(JSAny): AnyName;

extern macro LoadSimd128(intptr): Simd128;
extern macro I8x16BitMask(I8X16): int32;
extern macro I8x16Eq(I8X16, I8X16): I8X16;
extern macro I8x16Splat(int32): I8X16;
```