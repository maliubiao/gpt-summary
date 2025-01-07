Response:
The user wants to understand the functionality of a C++ header file `v8/src/codegen/code-stub-assembler.h` from the V8 JavaScript engine.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose:** The filename `code-stub-assembler.h` strongly suggests it's related to code generation and assembly within V8. "Code stubs" are small pieces of pre-compiled code used for common operations. The "assembler" part indicates it provides tools to generate machine code.

2. **Scan for key functionalities:**  Go through the provided code snippet, looking for groups of related functions and data structures. Keywords like `Allocate`, `Fill`, `Copy`, `Grow`, `Change`, `ToThis`, `Throw`, `Is` are good indicators of function categories.

3. **Categorize the functionalities:** Based on the scan, group the functions into logical categories. This helps in organizing the explanation. Some initial categories that emerge are:
    * Memory Allocation (FixedArrays, etc.)
    * Array Manipulation (Filling, Copying, Growing)
    * Type Conversions (Tagged pointers to primitives, etc.)
    * Type Checks (IsJSArray, IsCallable, etc.)
    * Error Handling (ThrowTypeError, ThrowRangeError)
    * Utilities (System pointer size, tagged size calculations)

4. **Explain each category:**  For each category, summarize the purpose and provide specific examples of the functions it contains.

5. **Address the `.tq` question:** Explain that if the file ended in `.tq`, it would be a Torque file, a higher-level language used within V8 for generating code. Since it's `.h`, it's C++.

6. **Connect to JavaScript (if applicable):** For functionalities that have a direct correspondence in JavaScript, provide simple examples. For instance, array allocation and manipulation are fundamental JavaScript concepts. Type conversions also happen implicitly or explicitly in JavaScript.

7. **Illustrate with input/output (where possible):** For functions that perform logical transformations, provide hypothetical input and expected output. This is easier for simpler functions like `GetInstanceTypeMap`.

8. **Highlight common programming errors:** Think about how the functionalities could be misused or lead to errors in a higher-level language like JavaScript. For example, incorrect type assumptions can lead to errors when using these low-level functions.

9. **Address the "Part 4 of 8" aspect:** Acknowledge this and state that the focus is on the functionalities present in *this* part of the file.

10. **Summarize the overall functionality:** Combine the individual category explanations into a concise summary. Emphasize the role of `CodeStubAssembler` in generating efficient, low-level code for V8.

11. **Review and refine:** Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any redundant information or areas that could be explained more effectively. For instance, initially, I might have listed every single function. Refinement involves grouping them by purpose for better readability. Also, ensure the tone is informative and helpful.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the C++ specifics. The prompt asks about the *functionality* and its relation to JavaScript. So, I shifted the focus to explaining *what* these functions do and how that relates to higher-level concepts.
* For the input/output examples, I initially thought about very low-level inputs and outputs. I realized it's more helpful to use inputs and outputs that are understandable in the context of V8's object model (like `InstanceType` and `Map`).
*  I initially missed the nuance of how allocation flags influence array creation. I added that detail to the explanation of allocation functions.
* I made sure to clearly distinguish between the C++ nature of the header file and its relevance to JavaScript's underlying implementation.

By following these steps, the generated response accurately and comprehensively addresses the user's request.
Based on the provided code snippet from `v8/src/codegen/code-stub-assembler.h`, here's a breakdown of its functionalities:

**Core Functionality: Low-Level Code Generation for V8**

This header file defines parts of the `CodeStubAssembler` class in V8. The `CodeStubAssembler` is a powerful tool within V8 that allows developers to generate machine code directly for specific, often performance-critical, operations. Think of it as a way to write assembly-like code but with a higher level of abstraction, still very close to the metal.

**Specific Functionalities in this Snippet:**

1. **Object Allocation:**
   - `AllocateUninitializedFixedArray`, `AllocateZeroedFixedArray`, `AllocateZeroedFixedDoubleArray`, `AllocateFixedArrayWithHoles`, `AllocateFixedDoubleArrayWithHoles`:  These functions provide ways to allocate different types of fixed-size arrays (used internally by V8) with various initialization states (uninitialized, filled with zeros, filled with holes).
   - `AllocatePropertyArray`:  Allocates a `PropertyArray`, which is used to store object properties.
   - `AllocateJSIteratorResult`, `AllocateJSIteratorResultForEntry`, `AllocatePromiseWithResolversResult`: Allocate specific JavaScript objects related to iterators and promises.
   - `ArraySpeciesCreate`:  Implements the logic for creating a new array object based on the species constructor of an existing array.
   - `AllocateArrayList`: Allocates a dynamically sized array list (internal to V8).

2. **Array Manipulation (Filling and Copying):**
   - `FillFixedArrayWithValue`:  Fills a portion of a `FixedArray` with a specific value.
   - `FillFixedArrayWithSmiZero`, `FillEntireFixedArrayWithSmiZero`: Fills a `FixedArray` with the Smi representation of zero.
   - `FillFixedDoubleArrayWithZero`, `FillEntireFixedDoubleArrayWithZero`: Fills a `FixedDoubleArray` with the floating-point representation of zero.
   - `FillPropertyArrayWithUndefined`: Fills a portion of a `PropertyArray` with the `undefined` value.
   - `CopyPropertyArrayValues`: Copies values from one property array to another.
   - `CopyFixedArrayElements`: Copies elements between `FixedArrayBase` instances (which can be `FixedArray` or `FixedDoubleArray`), handling different element kinds and potential holes.
   - `MoveElements`:  Efficiently moves elements within the same array.
   - `CopyElements`: Efficiently copies elements between arrays.
   - `CopyRange`: Copies a range of bytes between heap objects.
   - `ExtractFixedArray`, `ExtractToFixedArray`, `ExtractFixedDoubleArrayFillingHoles`:  Create new arrays by extracting portions of existing arrays, handling cases like empty arrays, copy-on-write arrays, and converting holes to `undefined`.
   - `CloneFixedArray`: Creates a copy of an existing `FixedArray` or `FixedDoubleArray`.
   - `LoadElementAndPrepareForStore`: Loads an element from an array, potentially performing a hole check and converting the value for storage in another array.

3. **Array Capacity Management:**
   - `CalculateNewElementsCapacity`: Calculates a new capacity when growing an array.
   - `TryGrowElementsCapacity`, `GrowElementsCapacity`, `PossiblyGrowElementsCapacity`: Functions related to increasing the capacity of arrays when more space is needed.

4. **Feedback Vector Handling:**
   - `IncrementCallCount`: Increments the call count in a feedback vector, used for optimizing function calls.

5. **Allocation Memento:**
   - `InitializeAllocationMemento`:  Initializes an allocation memento, which tracks allocation sites for optimization purposes.

6. **Type Conversions (Tagged Values to Primitives):**
   - `TryTaggedToInt32AsIntPtr`, `TryTaggedToFloat64`, `TruncateTaggedToFloat64`, `TruncateTaggedToWord32`, `TaggedToWord32OrBigInt`, `TaggedToWord32OrBigIntWithFeedback`, `TaggedPointerToWord32OrBigIntWithFeedback`:  These functions attempt to convert V8's tagged pointer representation of values (which can be Smis, HeapObjects, etc.) into primitive types like integers and floating-point numbers. They often include checks for validity and potential bailout points.
   - `TruncateNumberToWord32`, `TruncateHeapNumberValueToWord32`: Specifically truncate Number values to 32-bit integers.
   - `TryHeapNumberToSmi`, `TryFloat32ToSmi`, `TryFloat64ToSmi`: Attempt to convert HeapNumbers and floats to Smis (small integers).
   - Functions for bitcasting and changing between different floating-point representations (`BitcastFloat16ToUint32`, `ChangeFloat16ToFloat64`, etc.).
   - `ChangeTaggedNonSmiToInt32`, `ChangeTaggedToFloat64`: Convert tagged values to `int32_t` and `double` respectively.
   - `ChangeBoolToInt32`: Converts a boolean to an integer (0 or 1).
   - `TaggedToBigInt`: Attempts to convert a tagged value to a BigInt.

7. **Shared Value Handling:**
   - `SharedValueBarrier`: Ensures that a value is shareable across different V8 Isolates.

8. **Size Calculations:**
   - `TimesSystemPointerSize`, `TimesTaggedSize`, `TimesDoubleSize`: Helper functions to calculate sizes based on pointer size and tagged value size.

9. **Type Conversions (JavaScript Semantics):**
   - `ToThisString`, `ToThisValue`: Implement JavaScript's `ToString` and `ToValue` abstract operations, potentially throwing TypeErrors.

10. **Type Checking and Assertions:**
    - `ThrowIfNotInstanceType`, `ThrowIfNotJSReceiver`, `ThrowIfNotCallable`:  Functions to enforce type constraints, throwing TypeErrors if the conditions are not met.

11. **Error Handling:**
    - `ThrowRangeError`, `ThrowTypeError`:  Functions to throw JavaScript `RangeError` and `TypeError` exceptions.
    - `TerminateExecution`:  Halts the execution of the current JavaScript context.
    - `GetPendingMessage`, `SetPendingMessage`:  Get and set the pending exception message.
    - `IsExecutionTerminating`: Checks if the execution is being terminated due to an error.

12. **Embedder Data:**
    - `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`:  Manage embedder-specific data that needs to be preserved across continuations.

13. **Detailed Type Checks (using `InstanceType` and Maps):**
    - A large number of `Is...` functions (e.g., `IsNoElementsProtectorCellInvalid`, `IsMegaDOMProtectorCellInvalid`, `IsArrayIteratorProtectorCellInvalid`, `IsBigInt`, `IsCallable`, `IsCode`, `IsConsStringInstanceType`, `IsConstructor`, `IsDeprecatedMap`, `IsPropertyDictionary`, `IsOrderedNameDictionary`, `IsGlobalDictionary`, `IsExtensibleMap`, `IsExtensibleNonPrototypeMap`, `IsExternalStringInstanceType`, `IsFixedArray`, `IsFixedArraySubclass`, `IsFixedArrayWithKind`, `IsFixedArrayWithKindOrEmpty`, `IsFunctionWithPrototypeSlotMap`, `IsHashTable`, `IsEphemeronHashTable`, `IsHeapNumberInstanceType`, `IsNotAnyHole`, `IsHoleInstanceType`, `IsOddball`, `IsOddballInstanceType`, `IsIndirectStringInstanceType`, `IsJSArrayBuffer`, `IsJSDataView`, `IsJSRabGsabDataView`, `IsJSArrayInstanceType`, `IsJSArrayMap`, `IsJSArray`, `IsJSArrayIterator`, `IsJSAsyncGeneratorObject`, `IsFunctionInstanceType`, `IsJSFunctionInstanceType`, `IsJSFunctionMap`, `IsJSFunction`, `IsJSBoundFunction`, `IsJSGeneratorObject`, `IsJSGlobalProxyInstanceType`, `IsJSGlobalProxyMap`, `IsJSGlobalProxy`, `IsJSObjectInstanceType`, `IsJSObjectMap`, `IsJSObject`, `IsJSApiObjectInstanceType`, `IsJSApiObjectMap`, `IsJSApiObject`, `IsJSFinalizationRegistryMap`, `IsJSFinalizationRegistry`, `IsJSPromiseMap`, `IsJSPromise`, `IsJSProxy`, `IsJSStringIterator`, `IsJSShadowRealm`, `IsJSRegExpStringIterator`, `IsJSReceiverInstanceType`, `IsJSReceiverMap`, `IsJSReceiver`, `JSAnyIsNotPrimitiveMap`, `JSAnyIsNotPrimitive`, `IsJSRegExp`): These functions perform checks on the type of V8 objects, often by examining their `InstanceType` or `Map`. These are crucial for ensuring the correctness of operations.

**Is `v8/src/codegen/code-stub-assembler.h` a Torque file?**

No, the file extension is `.h`, which indicates a C++ header file. If it were a Torque source file, it would typically end with `.tq`.

**Relationship to JavaScript Functionality with Examples:**

Many of the functionalities in this header file are the *underlying implementations* of JavaScript features. Here are some examples:

* **Array Allocation and Manipulation:**
   ```javascript
   const arr1 = []; //  Might involve calls to allocation functions internally
   const arr2 = new Array(10); //  Allocation with a specific size
   arr1.push(5); // Might trigger array growth internally
   arr2[0] = 10;
   const arr3 = arr2.slice(2, 5); // Likely uses efficient copying mechanisms
   ```

* **Type Conversions:**
   ```javascript
   const numStr = "123";
   const num = Number(numStr); //  Internally uses routines to convert strings to numbers
   const boolValue = !!0; //  Implicit conversion to boolean
   const str = 10 + ""; // Implicit conversion of number to string
   ```

* **Error Handling:**
   ```javascript
   function mightThrow() {
     if (Math.random() < 0.5) {
       throw new TypeError("Something went wrong!"); //  Corresponds to `ThrowTypeError`
     }
   }
   ```

* **Object and Function Creation:**
   ```javascript
   const obj = {}; //  Internal allocation of JSObject
   function myFunction() {} //  Internal allocation of JSFunction
   ```

* **Iterators:**
   ```javascript
   const iterable = [1, 2, 3];
   const iterator = iterable[Symbol.iterator]();
   const result = iterator.next(); //  Uses `AllocateJSIteratorResult` internally
   ```

**Code Logic Inference with Assumptions:**

Let's take the `AllocateZeroedFixedArray` function as an example:

**Assumption:** We want to allocate a `FixedArray` that can hold 5 elements (represented as `IntPtrT`).

**Input:** `capacity` = 5 (as a `TNode<IntPtrT>`)

**Code Logic:**
1. `AllocateFixedArray(PACKED_ELEMENTS, capacity)` is called. This likely allocates raw memory for a `FixedArray` of the given capacity, along with header information.
2. `FillEntireFixedArrayWithSmiZero(PACKED_ELEMENTS, result, capacity)` is called. This function then iterates over the allocated memory and fills each element slot with the Smi representation of zero.

**Output:** A `TNode<FixedArray>` pointing to a newly allocated `FixedArray` in memory. The contents of this array will be `[0, 0, 0, 0, 0]` (represented as Smis).

**Common Programming Errors (from a JavaScript perspective):**

While developers don't directly interact with these C++ functions, understanding their purpose can shed light on potential issues in JavaScript:

* **Incorrect Type Assumptions:**  JavaScript's dynamic typing means you can often assign values of different types to variables. However, at the V8 level, there are strict type distinctions. For example, if V8 expects a Smi and encounters a HeapObject, it might lead to deoptimization or errors. This is why the `Is...` functions and type conversion routines are so crucial.
* **Array Index Out of Bounds:** While JavaScript prevents direct memory access, exceeding array bounds can still lead to errors or unexpected behavior. The underlying array manipulation functions need to handle these cases carefully.
* **Performance Implications of Array Growth:**  Repeatedly pushing elements onto an array might trigger `TryGrowElementsCapacity` multiple times. Understanding this can help developers write more performant code by pre-allocating array sizes when possible.
* **Understanding "Holes" in Arrays:**  Sparse arrays in JavaScript (where some indices are not explicitly set) have "holes." The functions dealing with holes demonstrate how V8 represents and handles these, which can have performance implications.

**Summary of Functionality (Part 4 of 8):**

This specific part of `v8/src/codegen/code-stub-assembler.h` focuses heavily on **memory management and low-level array manipulation** within the V8 engine. It provides the building blocks for allocating, initializing, copying, and growing various types of arrays (FixedArrays, PropertyArrays, etc.) that are fundamental to V8's internal representation of JavaScript objects and data structures. It also includes functions for basic type conversions between tagged values and primitive types, essential for operating on JavaScript values at a low level. The inclusion of feedback vector manipulation highlights its role in optimizing runtime performance.

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
                       TVariable<Object>& constructor,
                                 Label* found_default_base_ctor,
                                 Label* found_something_else);

  TNode<Map> GetInstanceTypeMap(InstanceType instance_type);

  TNode<FixedArray> AllocateUninitializedFixedArray(intptr_t capacity) {
    return UncheckedCast<FixedArray>(AllocateFixedArray(
        PACKED_ELEMENTS, IntPtrConstant(capacity), AllocationFlag::kNone));
  }

  TNode<FixedArray> AllocateZeroedFixedArray(TNode<IntPtrT> capacity) {
    TNode<FixedArray> result = UncheckedCast<FixedArray>(
        AllocateFixedArray(PACKED_ELEMENTS, capacity));
    FillEntireFixedArrayWithSmiZero(PACKED_ELEMENTS, result, capacity);
    return result;
  }

  TNode<FixedDoubleArray> AllocateZeroedFixedDoubleArray(
      TNode<IntPtrT> capacity) {
    TNode<FixedDoubleArray> result = UncheckedCast<FixedDoubleArray>(
        AllocateFixedArray(PACKED_DOUBLE_ELEMENTS, capacity));
    FillEntireFixedDoubleArrayWithZero(result, capacity);
    return result;
  }

  TNode<FixedArray> AllocateFixedArrayWithHoles(
      TNode<IntPtrT> capacity, AllocationFlags flags = AllocationFlag::kNone) {
    TNode<FixedArray> result = UncheckedCast<FixedArray>(
        AllocateFixedArray(PACKED_ELEMENTS, capacity, flags));
    FillFixedArrayWithValue(PACKED_ELEMENTS, result, IntPtrConstant(0),
                            capacity, RootIndex::kTheHoleValue);
    return result;
  }

  TNode<FixedDoubleArray> AllocateFixedDoubleArrayWithHoles(
      TNode<IntPtrT> capacity, AllocationFlags flags = AllocationFlag::kNone) {
    TNode<FixedDoubleArray> result = UncheckedCast<FixedDoubleArray>(
        AllocateFixedArray(PACKED_DOUBLE_ELEMENTS, capacity, flags));
    FillFixedArrayWithValue(PACKED_DOUBLE_ELEMENTS, result, IntPtrConstant(0),
                            capacity, RootIndex::kTheHoleValue);
    return result;
  }

  TNode<PropertyArray> AllocatePropertyArray(TNode<IntPtrT> capacity);

  // TODO(v8:9722): Return type should be JSIteratorResult
  TNode<JSObject> AllocateJSIteratorResult(TNode<Context> context,
                                           TNode<Object> value,
                                           TNode<Boolean> done);

  // TODO(v8:9722): Return type should be JSIteratorResult
  TNode<JSObject> AllocateJSIteratorResultForEntry(TNode<Context> context,
                                                   TNode<Object> key,
                                                   TNode<Object> value);

  TNode<JSObject> AllocatePromiseWithResolversResult(TNode<Context> context,
                                                     TNode<Object> promise,
                                                     TNode<Object> resolve,
                                                     TNode<Object> reject);

  TNode<JSReceiver> ArraySpeciesCreate(TNode<Context> context,
                                       TNode<Object> originalArray,
                                       TNode<Number> len);

  template <typename TIndex>
  void FillFixedArrayWithValue(ElementsKind kind, TNode<FixedArrayBase> array,
                               TNode<TIndex> from_index, TNode<TIndex> to_index,
                               RootIndex value_root_index);
  template <typename TIndex>
  void FillFixedArrayWithValue(ElementsKind kind, TNode<FixedArray> array,
                               TNode<TIndex> from_index, TNode<TIndex> to_index,
                               RootIndex value_root_index) {
    FillFixedArrayWithValue(kind, UncheckedCast<FixedArrayBase>(array),
                            from_index, to_index, value_root_index);
  }

  // Uses memset to effectively initialize the given FixedArray with zeroes.
  void FillFixedArrayWithSmiZero(ElementsKind kind, TNode<FixedArray> array,
                                 TNode<IntPtrT> start, TNode<IntPtrT> length);
  void FillEntireFixedArrayWithSmiZero(ElementsKind kind,
                                       TNode<FixedArray> array,
                                       TNode<IntPtrT> length) {
    CSA_DCHECK(this,
               WordEqual(length, LoadAndUntagFixedArrayBaseLength(array)));
    FillFixedArrayWithSmiZero(kind, array, IntPtrConstant(0), length);
  }

  void FillFixedDoubleArrayWithZero(TNode<FixedDoubleArray> array,
                                    TNode<IntPtrT> start,
                                    TNode<IntPtrT> length);
  void FillEntireFixedDoubleArrayWithZero(TNode<FixedDoubleArray> array,
                                          TNode<IntPtrT> length) {
    CSA_DCHECK(this,
               WordEqual(length, LoadAndUntagFixedArrayBaseLength(array)));
    FillFixedDoubleArrayWithZero(array, IntPtrConstant(0), length);
  }

  void FillPropertyArrayWithUndefined(TNode<PropertyArray> array,
                                      TNode<IntPtrT> from_index,
                                      TNode<IntPtrT> to_index);

  enum class DestroySource { kNo, kYes };

  // Increment the call count for a CALL_IC or construct call.
  // The call count is located at feedback_vector[slot_id + 1].
  void IncrementCallCount(TNode<FeedbackVector> feedback_vector,
                          TNode<UintPtrT> slot_id);

  // Specify DestroySource::kYes if {from_array} is being supplanted by
  // {to_array}. This offers a slight performance benefit by simply copying the
  // array word by word. The source may be destroyed at the end of this macro.
  //
  // Otherwise, specify DestroySource::kNo for operations where an Object is
  // being cloned, to ensure that mutable HeapNumbers are unique between the
  // source and cloned object.
  void CopyPropertyArrayValues(TNode<HeapObject> from_array,
                               TNode<PropertyArray> to_array,
                               TNode<IntPtrT> length,
                               WriteBarrierMode barrier_mode,
                               DestroySource destroy_source);

  // Copies all elements from |from_array| of |length| size to
  // |to_array| of the same size respecting the elements kind.
  template <typename TIndex>
  void CopyFixedArrayElements(
      ElementsKind kind, TNode<FixedArrayBase> from_array,
      TNode<FixedArrayBase> to_array, TNode<TIndex> length,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER) {
    CopyFixedArrayElements(kind, from_array, kind, to_array,
                           IntPtrOrSmiConstant<TIndex>(0), length, length,
                           barrier_mode);
  }

  // Copies |element_count| elements from |from_array| starting from element
  // zero to |to_array| of |capacity| size respecting both array's elements
  // kinds.
  template <typename TIndex>
  void CopyFixedArrayElements(
      ElementsKind from_kind, TNode<FixedArrayBase> from_array,
      ElementsKind to_kind, TNode<FixedArrayBase> to_array,
      TNode<TIndex> element_count, TNode<TIndex> capacity,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER) {
    CopyFixedArrayElements(from_kind, from_array, to_kind, to_array,
                           IntPtrOrSmiConstant<TIndex>(0), element_count,
                           capacity, barrier_mode);
  }

  // Copies |element_count| elements from |from_array| starting from element
  // |first_element| to |to_array| of |capacity| size respecting both array's
  // elements kinds.
  // |convert_holes| tells the function whether to convert holes to undefined.
  // |var_holes_converted| can be used to signify that the conversion happened
  // (i.e. that there were holes). If |convert_holes_to_undefined| is
  // HoleConversionMode::kConvertToUndefined, then it must not be the case that
  // IsDoubleElementsKind(to_kind).
  template <typename TIndex>
  void CopyFixedArrayElements(
      ElementsKind from_kind, TNode<FixedArrayBase> from_array,
      ElementsKind to_kind, TNode<FixedArrayBase> to_array,
      TNode<TIndex> first_element, TNode<TIndex> element_count,
      TNode<TIndex> capacity,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      HoleConversionMode convert_holes = HoleConversionMode::kDontConvert,
      TVariable<BoolT>* var_holes_converted = nullptr);

  void JumpIfPointersFromHereAreInteresting(TNode<Object> object,
                                            Label* interesting);

  // Efficiently copy elements within a single array. The regions
  // [src_index, src_index + length) and [dst_index, dst_index + length)
  // can be overlapping.
  void MoveElements(ElementsKind kind, TNode<FixedArrayBase> elements,
                    TNode<IntPtrT> dst_index, TNode<IntPtrT> src_index,
                    TNode<IntPtrT> length);

  // Efficiently copy elements from one array to another. The ElementsKind
  // needs to be the same. Copy from src_elements at
  // [src_index, src_index + length) to dst_elements at
  // [dst_index, dst_index + length).
  // The function decides whether it can use memcpy. In case it cannot,
  // |write_barrier| can help it to skip write barrier. SKIP_WRITE_BARRIER is
  // only safe when copying to new space, or when copying to old space and the
  // array does not contain object pointers.
  void CopyElements(ElementsKind kind, TNode<FixedArrayBase> dst_elements,
                    TNode<IntPtrT> dst_index,
                    TNode<FixedArrayBase> src_elements,
                    TNode<IntPtrT> src_index, TNode<IntPtrT> length,
                    WriteBarrierMode write_barrier = UPDATE_WRITE_BARRIER);

  void CopyRange(TNode<HeapObject> dst_object, int dst_offset,
                 TNode<HeapObject> src_object, int src_offset,
                 TNode<IntPtrT> length_in_tagged,
                 WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  TNode<FixedArray> HeapObjectToFixedArray(TNode<HeapObject> base,
                                           Label* cast_fail);

  TNode<FixedDoubleArray> HeapObjectToFixedDoubleArray(TNode<HeapObject> base,
                                                       Label* cast_fail) {
    GotoIf(TaggedNotEqual(LoadMap(base), FixedDoubleArrayMapConstant()),
           cast_fail);
    return UncheckedCast<FixedDoubleArray>(base);
  }

  TNode<ArrayList> AllocateArrayList(TNode<Smi> size);
  TNode<ArrayList> ArrayListEnsureSpace(TNode<ArrayList> array,
                                        TNode<Smi> length);
  TNode<ArrayList> ArrayListAdd(TNode<ArrayList> array, TNode<Object> object);
  void ArrayListSet(TNode<ArrayList> array, TNode<Smi> index,
                    TNode<Object> object);
  TNode<Smi> ArrayListGetLength(TNode<ArrayList> array);
  void ArrayListSetLength(TNode<ArrayList> array, TNode<Smi> length);
  // TODO(jgruber): Rename to ArrayListToFixedArray.
  TNode<FixedArray> ArrayListElements(TNode<ArrayList> array);

  template <typename T>
  bool ClassHasMapConstant() {
    return false;
  }

  template <typename T>
  TNode<Map> GetClassMapConstant() {
    UNREACHABLE();
    return TNode<Map>();
  }

  enum class ExtractFixedArrayFlag {
    kFixedArrays = 1,
    kFixedDoubleArrays = 2,
    kDontCopyCOW = 4,
    kAllFixedArrays = kFixedArrays | kFixedDoubleArrays,
    kAllFixedArraysDontCopyCOW = kAllFixedArrays | kDontCopyCOW
  };

  using ExtractFixedArrayFlags = base::Flags<ExtractFixedArrayFlag>;

  // Copy a portion of an existing FixedArray or FixedDoubleArray into a new
  // array, including special appropriate handling for empty arrays and COW
  // arrays. The result array will be of the same type as the original array.
  //
  // * |source| is either a FixedArray or FixedDoubleArray from which to copy
  // elements.
  // * |first| is the starting element index to copy from, if nullptr is passed
  // then index zero is used by default.
  // * |count| is the number of elements to copy out of the source array
  // starting from and including the element indexed by |start|. If |count| is
  // nullptr, then all of the elements from |start| to the end of |source| are
  // copied.
  // * |capacity| determines the size of the allocated result array, with
  // |capacity| >= |count|. If |capacity| is nullptr, then |count| is used as
  // the destination array's capacity.
  // * |extract_flags| determines whether FixedArrays, FixedDoubleArrays or both
  // are detected and copied. Although it's always correct to pass
  // kAllFixedArrays, the generated code is more compact and efficient if the
  // caller can specify whether only FixedArrays or FixedDoubleArrays will be
  // passed as the |source| parameter.
  // * |parameter_mode| determines the parameter mode of |first|, |count| and
  // |capacity|.
  // * If |var_holes_converted| is given, any holes will be converted to
  // undefined and the variable will be set according to whether or not there
  // were any hole.
  // * If |source_elements_kind| is given, the function will try to use the
  // runtime elements kind of source to make copy faster. More specifically, it
  // can skip write barriers.
  template <typename TIndex>
  TNode<FixedArrayBase> ExtractFixedArray(
      TNode<FixedArrayBase> source, std::optional<TNode<TIndex>> first,
      std::optional<TNode<TIndex>> count = std::nullopt,
      std::optional<TNode<TIndex>> capacity = std::nullopt,
      ExtractFixedArrayFlags extract_flags =
          ExtractFixedArrayFlag::kAllFixedArrays,
      TVariable<BoolT>* var_holes_converted = nullptr,
      std::optional<TNode<Int32T>> source_elements_kind = std::nullopt);

  // Copy a portion of an existing FixedArray or FixedDoubleArray into a new
  // FixedArray, including special appropriate handling for COW arrays.
  // * |source| is either a FixedArray or FixedDoubleArray from which to copy
  // elements. |source| is assumed to be non-empty.
  // * |first| is the starting element index to copy from.
  // * |count| is the number of elements to copy out of the source array
  // starting from and including the element indexed by |start|.
  // * |capacity| determines the size of the allocated result array, with
  // |capacity| >= |count|.
  // * |source_map| is the map of the |source|.
  // * |from_kind| is the elements kind that is consistent with |source| being
  // a FixedArray or FixedDoubleArray. This function only cares about double vs.
  // non-double, so as to distinguish FixedDoubleArray vs. FixedArray. It does
  // not care about holeyness. For example, when |source| is a FixedArray,
  // PACKED/HOLEY_ELEMENTS can be used, but not PACKED_DOUBLE_ELEMENTS.
  // * |allocation_flags| and |extract_flags| influence how the target
  // FixedArray is allocated.
  // * |convert_holes| is used to signify that the target array should use
  // undefined in places of holes.
  // * If |convert_holes| is true and |var_holes_converted| not nullptr, then
  // |var_holes_converted| is used to signal whether any holes were found and
  // converted. The caller should use this information to decide which map is
  // compatible with the result array. For example, if the input was of
  // HOLEY_SMI_ELEMENTS kind, and a conversion took place, the result will be
  // compatible only with HOLEY_ELEMENTS and PACKED_ELEMENTS.
  template <typename TIndex>
  TNode<FixedArray> ExtractToFixedArray(
      TNode<FixedArrayBase> source, TNode<TIndex> first, TNode<TIndex> count,
      TNode<TIndex> capacity, TNode<Map> source_map, ElementsKind from_kind,
      AllocationFlags allocation_flags, ExtractFixedArrayFlags extract_flags,
      HoleConversionMode convert_holes,
      TVariable<BoolT>* var_holes_converted = nullptr,
      std::optional<TNode<Int32T>> source_runtime_kind = std::nullopt);

  // Attempt to copy a FixedDoubleArray to another FixedDoubleArray. In the case
  // where the source array has a hole, produce a FixedArray instead where holes
  // are replaced with undefined.
  // * |source| is a FixedDoubleArray from which to copy elements.
  // * |first| is the starting element index to copy from.
  // * |count| is the number of elements to copy out of the source array
  // starting from and including the element indexed by |start|.
  // * |capacity| determines the size of the allocated result array, with
  // |capacity| >= |count|.
  // * |source_map| is the map of |source|. It will be used as the map of the
  // target array if the target can stay a FixedDoubleArray. Otherwise if the
  // target array needs to be a FixedArray, the FixedArrayMap will be used.
  // * |var_holes_converted| is used to signal whether a FixedAray
  // is produced or not.
  // * |allocation_flags| and |extract_flags| influence how the target array is
  // allocated.
  template <typename TIndex>
  TNode<FixedArrayBase> ExtractFixedDoubleArrayFillingHoles(
      TNode<FixedArrayBase> source, TNode<TIndex> first, TNode<TIndex> count,
      TNode<TIndex> capacity, TNode<Map> source_map,
      TVariable<BoolT>* var_holes_converted, AllocationFlags allocation_flags,
      ExtractFixedArrayFlags extract_flags);

  // Copy the entire contents of a FixedArray or FixedDoubleArray to a new
  // array, including special appropriate handling for empty arrays and COW
  // arrays.
  //
  // * |source| is either a FixedArray or FixedDoubleArray from which to copy
  // elements.
  // * |extract_flags| determines whether FixedArrays, FixedDoubleArrays or both
  // are detected and copied. Although it's always correct to pass
  // kAllFixedArrays, the generated code is more compact and efficient if the
  // caller can specify whether only FixedArrays or FixedDoubleArrays will be
  // passed as the |source| parameter.
  TNode<FixedArrayBase> CloneFixedArray(
      TNode<FixedArrayBase> source,
      ExtractFixedArrayFlags flags =
          ExtractFixedArrayFlag::kAllFixedArraysDontCopyCOW);

  // Loads an element from |array| of |from_kind| elements by given |offset|
  // (NOTE: not index!), does a hole check if |if_hole| is provided and
  // converts the value so that it becomes ready for storing to array of
  // |to_kind| elements.
  template <typename TResult>
  TNode<TResult> LoadElementAndPrepareForStore(TNode<FixedArrayBase> array,
                                               TNode<IntPtrT> offset,
                                               ElementsKind from_kind,
                                               ElementsKind to_kind,
                                               Label* if_hole);

  template <typename TIndex>
  TNode<TIndex> CalculateNewElementsCapacity(TNode<TIndex> old_capacity);

  // Tries to grow the |elements| array of given |object| to store the |key|
  // or bails out if the growing gap is too big. Returns new elements.
  TNode<FixedArrayBase> TryGrowElementsCapacity(TNode<HeapObject> object,
                                                TNode<FixedArrayBase> elements,
                                                ElementsKind kind,
                                                TNode<Smi> key, Label* bailout);

  // Tries to grow the |capacity|-length |elements| array of given |object|
  // to store the |key| or bails out if the growing gap is too big. Returns
  // new elements.
  template <typename TIndex>
  TNode<FixedArrayBase> TryGrowElementsCapacity(TNode<HeapObject> object,
                                                TNode<FixedArrayBase> elements,
                                                ElementsKind kind,
                                                TNode<TIndex> key,
                                                TNode<TIndex> capacity,
                                                Label* bailout);

  // Grows elements capacity of given object. Returns new elements.
  template <typename TIndex>
  TNode<FixedArrayBase> GrowElementsCapacity(
      TNode<HeapObject> object, TNode<FixedArrayBase> elements,
      ElementsKind from_kind, ElementsKind to_kind, TNode<TIndex> capacity,
      TNode<TIndex> new_capacity, Label* bailout);

  // Given a need to grow by |growth|, allocate an appropriate new capacity
  // if necessary, and return a new elements FixedArray object. Label |bailout|
  // is followed for allocation failure.
  void PossiblyGrowElementsCapacity(ElementsKind kind, TNode<HeapObject> array,
                                    TNode<BInt> length,
                                    TVariable<FixedArrayBase>* var_elements,
                                    TNode<BInt> growth, Label* bailout);

  // Allocation site manipulation
  void InitializeAllocationMemento(TNode<HeapObject> base,
                                   TNode<IntPtrT> base_allocation_size,
                                   TNode<AllocationSite> allocation_site);

  TNode<IntPtrT> TryTaggedToInt32AsIntPtr(TNode<Object> value,
                                          Label* if_not_possible);
  TNode<Float64T> TryTaggedToFloat64(TNode<Object> value,
                                     Label* if_valueisnotnumber);
  TNode<Float64T> TruncateTaggedToFloat64(TNode<Context> context,
                                          TNode<Object> value);
  TNode<Word32T> TruncateTaggedToWord32(TNode<Context> context,
                                        TNode<Object> value);
  void TaggedToWord32OrBigInt(TNode<Context> context, TNode<Object> value,
                              Label* if_number, TVariable<Word32T>* var_word32,
                              Label* if_bigint, Label* if_bigint64,
                              TVariable<BigInt>* var_maybe_bigint);
  struct FeedbackValues {
    TVariable<Smi>* var_feedback = nullptr;
    const LazyNode<HeapObject>* maybe_feedback_vector = nullptr;
    TNode<UintPtrT>* slot = nullptr;
    UpdateFeedbackMode update_mode = UpdateFeedbackMode::kNoFeedback;
  };
  void TaggedToWord32OrBigIntWithFeedback(TNode<Context> context,
                                          TNode<Object> value, Label* if_number,
                                          TVariable<Word32T>* var_word32,
                                          Label* if_bigint, Label* if_bigint64,
                                          TVariable<BigInt>* var_maybe_bigint,
                                          const FeedbackValues& feedback);
  void TaggedPointerToWord32OrBigIntWithFeedback(
      TNode<Context> context, TNode<HeapObject> pointer, Label* if_number,
      TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
      TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback);

  TNode<Int32T> TruncateNumberToWord32(TNode<Number> value);
  // Truncate the floating point value of a HeapNumber to an Int32.
  TNode<Int32T> TruncateHeapNumberValueToWord32(TNode<HeapNumber> object);

  // Conversions.
  TNode<Smi> TryHeapNumberToSmi(TNode<HeapNumber> number, Label* not_smi);
  TNode<Smi> TryFloat32ToSmi(TNode<Float32T> number, Label* not_smi);
  TNode<Smi> TryFloat64ToSmi(TNode<Float64T> number, Label* not_smi);

  TNode<Uint32T> BitcastFloat16ToUint32(TNode<Float16RawBitsT> value);
  TNode<Float16RawBitsT> BitcastUint32ToFloat16(TNode<Uint32T> value);
  TNode<Float16RawBitsT> RoundInt32ToFloat16(TNode<Int32T> value);

  TNode<Float64T> ChangeFloat16ToFloat64(TNode<Float16RawBitsT> value);
  TNode<Float32T> ChangeFloat16ToFloat32(TNode<Float16RawBitsT> value);
  TNode<Number> ChangeFloat32ToTagged(TNode<Float32T> value);
  TNode<Number> ChangeFloat64ToTagged(TNode<Float64T> value);
  TNode<Number> ChangeInt32ToTagged(TNode<Int32T> value);
  TNode<Number> ChangeInt32ToTaggedNoOverflow(TNode<Int32T> value);
  TNode<Number> ChangeUint32ToTagged(TNode<Uint32T> value);
  TNode<Number> ChangeUintPtrToTagged(TNode<UintPtrT> value);
  TNode<Uint32T> ChangeNonNegativeNumberToUint32(TNode<Number> value);
  TNode<Float64T> ChangeNumberToFloat64(TNode<Number> value);

  TNode<Int32T> ChangeTaggedNonSmiToInt32(TNode<Context> context,
                                          TNode<HeapObject> input);
  TNode<Float64T> ChangeTaggedToFloat64(TNode<Context> context,
                                        TNode<Object> input);

  TNode<Int32T> ChangeBoolToInt32(TNode<BoolT> b);

  void TaggedToBigInt(TNode<Context> context, TNode<Object> value,
                      Label* if_not_bigint, Label* if_bigint,
                      Label* if_bigint64, TVariable<BigInt>* var_bigint,
                      TVariable<Smi>* var_feedback);

  // Ensures that {var_shared_value} is shareable across Isolates, and throws if
  // not.
  void SharedValueBarrier(TNode<Context> context,
                          TVariable<Object>* var_shared_value);

  TNode<WordT> TimesSystemPointerSize(TNode<WordT> value);
  TNode<IntPtrT> TimesSystemPointerSize(TNode<IntPtrT> value) {
    return Signed(TimesSystemPointerSize(implicit_cast<TNode<WordT>>(value)));
  }
  TNode<UintPtrT> TimesSystemPointerSize(TNode<UintPtrT> value) {
    return Unsigned(TimesSystemPointerSize(implicit_cast<TNode<WordT>>(value)));
  }

  TNode<WordT> TimesTaggedSize(TNode<WordT> value);
  TNode<IntPtrT> TimesTaggedSize(TNode<IntPtrT> value) {
    return Signed(TimesTaggedSize(implicit_cast<TNode<WordT>>(value)));
  }
  TNode<UintPtrT> TimesTaggedSize(TNode<UintPtrT> value) {
    return Unsigned(TimesTaggedSize(implicit_cast<TNode<WordT>>(value)));
  }

  TNode<WordT> TimesDoubleSize(TNode<WordT> value);
  TNode<UintPtrT> TimesDoubleSize(TNode<UintPtrT> value) {
    return Unsigned(TimesDoubleSize(implicit_cast<TNode<WordT>>(value)));
  }
  TNode<IntPtrT> TimesDoubleSize(TNode<IntPtrT> value) {
    return Signed(TimesDoubleSize(implicit_cast<TNode<WordT>>(value)));
  }

  // Type conversions.
  // Throws a TypeError for {method_name} if {value} is not coercible to Object,
  // or returns the {value} converted to a String otherwise.
  TNode<String> ToThisString(TNode<Context> context, TNode<Object> value,
                             TNode<String> method_name);
  TNode<String> ToThisString(TNode<Context> context, TNode<Object> value,
                             char const* method_name) {
    return ToThisString(context, value, StringConstant(method_name));
  }

  // Throws a TypeError for {method_name} if {value} is neither of the given
  // {primitive_type} nor a JSPrimitiveWrapper wrapping a value of
  // {primitive_type}, or returns the {value} (or wrapped value) otherwise.
  TNode<Object> ToThisValue(TNode<Context> context, TNode<Object> value,
                            PrimitiveType primitive_type,
                            char const* method_name);

  // Throws a TypeError for {method_name} if {value} is not of the given
  // instance type.
  void ThrowIfNotInstanceType(TNode<Context> context, TNode<Object> value,
                              InstanceType instance_type,
                              char const* method_name);
  // Throws a TypeError for {method_name} if {value} is not a JSReceiver.
  void ThrowIfNotJSReceiver(TNode<Context> context, TNode<Object> value,
                            MessageTemplate msg_template,
                            const char* method_name);
  void ThrowIfNotCallable(TNode<Context> context, TNode<Object> value,
                          const char* method_name);

  void ThrowRangeError(TNode<Context> context, MessageTemplate message,
                       std::optional<TNode<Object>> arg0 = std::nullopt,
                       std::optional<TNode<Object>> arg1 = std::nullopt,
                       std::optional<TNode<Object>> arg2 = std::nullopt);
  void ThrowTypeError(TNode<Context> context, MessageTemplate message,
                      char const* arg0 = nullptr, char const* arg1 = nullptr);
  void ThrowTypeError(TNode<Context> context, MessageTemplate message,
                      std::optional<TNode<Object>> arg0,
                      std::optional<TNode<Object>> arg1 = std::nullopt,
                      std::optional<TNode<Object>> arg2 = std::nullopt);

  void TerminateExecution(TNode<Context> context);

  TNode<HeapObject> GetPendingMessage();
  void SetPendingMessage(TNode<HeapObject> message);
  TNode<BoolT> IsExecutionTerminating();

  TNode<Object> GetContinuationPreservedEmbedderData();
  void SetContinuationPreservedEmbedderData(TNode<Object> value);

  // Type checks.
  // Check whether the map is for an object with special properties, such as a
  // JSProxy or an object with interceptors.
  TNode<BoolT> InstanceTypeEqual(TNode<Int32T> instance_type, int type);
  TNode<BoolT> IsNoElementsProtectorCellInvalid();
  TNode<BoolT> IsMegaDOMProtectorCellInvalid();
  TNode<BoolT> IsAlwaysSharedSpaceJSObjectInstanceType(
      TNode<Int32T> instance_type);
  TNode<BoolT> IsArrayIteratorProtectorCellInvalid();
  TNode<BoolT> IsBigIntInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsBigInt(TNode<HeapObject> object);
  TNode<BoolT> IsBoolean(TNode<HeapObject> object);
  TNode<BoolT> IsCallableMap(TNode<Map> map);
  TNode<BoolT> IsCallable(TNode<HeapObject> object);
  TNode<BoolT> TaggedIsCallable(TNode<Object> object);
  TNode<BoolT> IsCode(TNode<HeapObject> object);
  TNode<BoolT> TaggedIsCode(TNode<Object> object);
  TNode<BoolT> IsConsStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsConstructorMap(TNode<Map> map);
  TNode<BoolT> IsConstructor(TNode<HeapObject> object);
  TNode<BoolT> IsDeprecatedMap(TNode<Map> map);
  TNode<BoolT> IsPropertyDictionary(TNode<HeapObject> object);
  TNode<BoolT> IsOrderedNameDictionary(TNode<HeapObject> object);
  TNode<BoolT> IsGlobalDictionary(TNode<HeapObject> object);
  TNode<BoolT> IsExtensibleMap(TNode<Map> map);
  TNode<BoolT> IsExtensibleNonPrototypeMap(TNode<Map> map);
  TNode<BoolT> IsExternalStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsFixedArray(TNode<HeapObject> object);
  TNode<BoolT> IsFixedArraySubclass(TNode<HeapObject> object);
  TNode<BoolT> IsFixedArrayWithKind(TNode<HeapObject> object,
                                    ElementsKind kind);
  TNode<BoolT> IsFixedArrayWithKindOrEmpty(TNode<FixedArrayBase> object,
                                           ElementsKind kind);
  TNode<BoolT> IsFunctionWithPrototypeSlotMap(TNode<Map> map);
  TNode<BoolT> IsHashTable(TNode<HeapObject> object);
  TNode<BoolT> IsEphemeronHashTable(TNode<HeapObject> object);
  TNode<BoolT> IsHeapNumberInstanceType(TNode<Int32T> instance_type);
  // We only want to check for any hole in a negated way. For regular hole
  // checks, we should check for a specific hole kind instead.
  TNode<BoolT> IsNotAnyHole(TNode<Object> object);
  TNode<BoolT> IsHoleInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsOddball(TNode<HeapObject> object);
  TNode<BoolT> IsOddballInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsIndirectStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSArrayBuffer(TNode<HeapObject> object);
  TNode<BoolT> IsJSDataView(TNode<HeapObject> object);
  TNode<BoolT> IsJSRabGsabDataView(TNode<HeapObject> object);
  TNode<BoolT> IsJSArrayInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSArrayMap(TNode<Map> map);
  TNode<BoolT> IsJSArray(TNode<HeapObject> object);
  TNode<BoolT> IsJSArrayIterator(TNode<HeapObject> object);
  TNode<BoolT> IsJSAsyncGeneratorObject(TNode<HeapObject> object);
  TNode<BoolT> IsFunctionInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSFunctionInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSFunctionMap(TNode<Map> map);
  TNode<BoolT> IsJSFunction(TNode<HeapObject> object);
  TNode<BoolT> IsJSBoundFunction(TNode<HeapObject> object);
  TNode<BoolT> IsJSGeneratorObject(TNode<HeapObject> object);
  TNode<BoolT> IsJSGlobalProxyInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSGlobalProxyMap(TNode<Map> map);
  TNode<BoolT> IsJSGlobalProxy(TNode<HeapObject> object);
  TNode<BoolT> IsJSObjectInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSObjectMap(TNode<Map> map);
  TNode<BoolT> IsJSObject(TNode<HeapObject> object);
  TNode<BoolT> IsJSApiObjectInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSApiObjectMap(TNode<Map> map);
  TNode<BoolT> IsJSApiObject(TNode<HeapObject> object);
  TNode<BoolT> IsJSFinalizationRegistryMap(TNode<Map> map);
  TNode<BoolT> IsJSFinalizationRegistry(TNode<HeapObject> object);
  TNode<BoolT> IsJSPromiseMap(TNode<Map> map);
  TNode<BoolT> IsJSPromise(TNode<HeapObject> object);
  TNode<BoolT> IsJSProxy(TNode<HeapObject> object);
  TNode<BoolT> IsJSStringIterator(TNode<HeapObject> object);
  TNode<BoolT> IsJSShadowRealm(TNode<HeapObject> object);
  TNode<BoolT> IsJSRegExpStringIterator(TNode<HeapObject> object);
  TNode<BoolT> IsJSReceiverInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSReceiverMap(TNode<Map> map);
  TNode<BoolT> IsJSReceiver(TNode<HeapObject> object);
  // The following two methods assume that we deal either with a primitive
  // object or a JS receiver.
  TNode<BoolT> JSAnyIsNotPrimitiveMap(TNode<Map> map);
  TNode<BoolT> JSAnyIsNotPrimitive(TNode<HeapObject> object);
  TNode<BoolT> IsJSRegExp(TNode<
"""


```