Response:
Let's break down the thought process for analyzing this C++ header file and generating the detailed explanation.

1. **Identify the Core Purpose:** The filename `machine-lowering-reducer-inl.h` immediately suggests this file is part of the "machine lowering" phase in the Turboshaft compiler. The "reducer" part indicates it contains logic to simplify or transform operations at this level. The `.inl.h` suffix means it's an inline header, likely containing implementations of template functions or small, frequently used utility functions.

2. **Scan for Key Concepts:**  A quick skim reveals several recurring themes:
    * **Memory Operations:**  Loads (`Load`, `LoadField`, `LoadElement`), Stores (`StoreField`, `InitializeElement`), Allocation (`Allocate`). This reinforces the idea of "machine lowering," dealing with low-level memory access.
    * **Data Structures:** Mentions of `OrderedHashMap`, `OrderedHashSet`, `String`, `SeqTwoByteString`, `BigInt`, `HeapNumber`, `JSArray`, `Map`, `FixedArray`. This tells us the code interacts with V8's internal object representations.
    * **Types and Representations:**  `WordPtr`, `Word32`, `Float64`, `Smi`, `Tagged`, `Untagged`. This highlights the manipulation of different data types at the machine level, including tagged pointers and raw data.
    * **Control Flow:**  `Label`, `GOTO`, `GOTO_IF`, `IF`, `BIND`, `BIND_LOOP`. This indicates the code generates low-level control flow structures.
    * **Builtins and Runtime Functions:** Calls to `__ CallBuiltin_...` and `__ CallRuntime_...` imply interaction with pre-defined V8 functions.
    * **Deoptimization:**  `__ DeoptimizeIf`, `__ DeoptimizeIfNot`. This is a crucial aspect of optimizing compilers, handling cases where assumptions break down.
    * **Unicode Encoding:**  References to `UTF16` and `UTF32` suggest string manipulation at a low level.
    * **BigInt Operations:** Dedicated functions for BigInt allocation and operations.

3. **Categorize and Group Functionality:** Based on the identified concepts, we can start grouping functions and their purposes:

    * **Hash Map/Set Operations:** `FindOrderedHashEntry`.
    * **String Manipulation:** `LoadSurrogatePairAt`, `StringFromSingleCharCode`, `StringFromSingleCodePoint`, `AllocateSeqTwoByteString`.
    * **BigInt Operations:** `AllocateBigInt`, `CallBuiltinForBigIntOp`, `GetBuiltinForBigIntBinop`.
    * **Typed Array Operations:** `BuildTypedArrayDataPointer`.
    * **General Memory and Object Operations:**  Loads, Stores, Allocation, Tagging/Untagging (`__ UntagSmi`, `__ BitcastWord32ToSmi`).
    * **Type Checking and Conversion:**  `ConvertHeapObjectToFloat64OrDeopt`, `IsNonZero`.
    * **Deoptimization Helpers:**  Functions involving `__ DeoptimizeIf`, `__ DeoptimizeIfNot`.
    * **Runtime Calls:** Functions using `__ CallRuntime_...`.
    * **Bitwise Operations and Utilities:** `BuildUint32Mod`, `ComputeUnseededHash`.
    * **Continuation Preserved Embedder Data:** `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`.
    * **Array Transitions:** `TransitionElementsTo`.
    * **Map Comparison:** `CompareMapAgainstMultipleMaps`.

4. **Analyze Individual Functions (Example: `FindOrderedHashEntry`):**

    * **Purpose:** The name clearly suggests finding an entry in an ordered hash map or set.
    * **Input:** Takes `data_structure` (the hash map/set object) and `key`.
    * **Logic:**
        * Computes a hash of the key.
        * Uses the hash to find the starting bucket in the hash table.
        * Iterates through the linked list of entries in the bucket, comparing keys.
        * Handles both Smi and HeapNumber keys.
        * Returns the entry if found, otherwise a "not found" value.
    * **Connection to JavaScript:**  This is directly related to how JavaScript `Map` and `Set` are implemented internally. When you do `map.get(key)` or `set.has(key)`, this kind of low-level logic is involved.
    * **Example:**  `const map = new Map([[1, 'a'], [2, 'b']]); map.get(1);` would trigger this kind of hash lookup.
    * **Potential Errors:**  Using non-primitive keys in a way that relies on object identity rather than value (though `Map` handles this better than plain objects).

5. **Connect to Turboshaft and Machine Lowering:**  Explain how the functions relate to the overall compiler pipeline. Machine lowering is about converting high-level operations into low-level, architecture-specific instructions. These functions are stepping stones in that process, dealing with raw memory addresses, tagged pointers, and fundamental data representations.

6. **Address Specific Prompts:**  Go through each of the user's requests:

    * **List Functions:**  Provide a clear, categorized list.
    * **`.tq` Check:**  Explain that `.inl.h` is C++, not Torque.
    * **JavaScript Relation:**  Provide concrete JavaScript examples for relevant functions (like hash maps, strings).
    * **Logic Reasoning (Example):** Choose a function like `FindOrderedHashEntry` and demonstrate with hypothetical inputs and outputs.
    * **Common Errors:**  Think about how JavaScript developers might misuse the underlying concepts (e.g., assuming object identity works for hash map keys without understanding the implications).
    * **Overall Functionality (Summary):**  Synthesize the individual function descriptions into a concise summary of the file's role.

7. **Refine and Structure:** Organize the information logically with clear headings and bullet points. Use precise language and avoid jargon where possible, or explain it when necessary. Ensure the explanation flows well and is easy to understand.

8. **Self-Correction/Review:**  Read through the generated explanation. Does it accurately reflect the code? Are there any ambiguities or areas that could be clearer?  Did I miss any important aspects? For example, initially, I might focus heavily on individual functions, but then realize the importance of emphasizing the *context* within the Turboshaft pipeline. I might also realize I haven't explicitly mentioned the role of the `Assembler` class and the macro-based code generation.

By following this process, combining code analysis with knowledge of compiler design and JavaScript semantics, we can create a comprehensive and accurate explanation of the given C++ header file.
This header file, `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h`, is a crucial part of V8's Turboshaft compiler, specifically within the "machine lowering" phase. It defines inline functions (hence the `.inl.h`) used by the `MachineLoweringReducer`. The `MachineLoweringReducer`'s job is to take high-level, machine-independent operations produced by earlier stages of the compiler and translate them into lower-level, machine-specific operations that can be directly executed by the target architecture.

Here's a breakdown of its functionalities:

**Core Functionality: Implementing Low-Level Operations**

The primary function of this header is to provide implementations for various low-level operations. These operations are often architectural primitives or close to them. The functions within this header are used by the `MachineLoweringReducer` to *reduce* high-level operations into these low-level equivalents.

**Specific Functionalities (based on the code):**

1. **Hash Map and Set Operations:**
   - `FindOrderedHashEntry`: Implements the logic to find an entry (key-value pair or just a key) in an `OrderedHashMap` or `OrderedHashSet`. It calculates the hash, finds the bucket, and iterates through the linked list to find the matching entry.

2. **String Manipulation:**
   - `LoadSurrogatePairAt`:  Loads a surrogate pair (for Unicode characters outside the Basic Multilingual Plane) from a string at a given index, encoding it according to the specified `UnicodeEncoding` (UTF-16 or UTF-32).
   - `StringFromSingleCharCode`: Creates a one-character string from a given Unicode code point. It optimizes for one-byte characters by using the single character string table.
   - `StringFromSingleCodePoint`: Creates a one or two-character string from a given Unicode code point, handling both BMP characters and those requiring surrogate pairs.
   - `AllocateSeqTwoByteString`: Allocates memory for a `SeqTwoByteString` (a string where each character takes two bytes), initializing its basic properties.

3. **BigInt Operations:**
   - `AllocateBigInt`:  Allocates a `BigInt` object in memory.
   - `CallBuiltinForBigIntOp`:  Calls a built-in function for BigInt operations (like addition, subtraction, etc.).
   - `GetBuiltinForBigIntBinop`:  Returns the appropriate built-in function for a given BigInt binary operation.

4. **Typed Array Operations:**
   - `BuildTypedArrayDataPointer`: Calculates the actual memory address of the data buffer within a Typed Array.

5. **General Memory and Object Operations:**
   - The code uses macros like `__ LoadField`, `__ StoreField`, `__ LoadElement`, `__ InitializeField`, `__ Allocate` which are likely defined in other parts of Turboshaft's assembler infrastructure. These are fundamental operations for accessing and manipulating objects in V8's heap.

6. **Type Checking and Conversion:**
   - `ConvertHeapObjectToFloat64OrDeopt`: Attempts to convert a heap object to a `Float64`. If the object isn't a number (or a boolean/oddball that can be coerced to a number), it triggers deoptimization (reverting to a less optimized execution path).
   - `IsNonZero`: Checks if a 32-bit word is non-zero and returns 1 if it is, 0 otherwise.

7. **Deoptimization:**
   - The code frequently uses `__ DeoptimizeIf` and `__ DeoptimizeIfNot`. These are critical for maintaining correctness in optimized code. If assumptions made during optimization turn out to be false at runtime, the code needs to "bail out" to a safer, less optimized version.
   - `MigrateInstanceOrDeopt`: Handles the migration of an object's representation if its map is deprecated, potentially deoptimizing if migration fails.

8. **Runtime Calls:**
   - Functions like `__ CallRuntime_TryMigrateInstance` and `__ CallRuntime_TransitionElementsKind` indicate interaction with V8's runtime system for more complex operations that cannot be efficiently implemented with inline code.

9. **Bitwise Operations and Utilities:**
   - `BuildUint32Mod`: Implements a modulo operation for unsigned 32-bit integers, optimizing for cases where the divisor is a power of two.
   - `ComputeUnseededHash`: Calculates an unseeded hash code for a 32-bit value.

10. **Continuation Preserved Embedder Data:**
    - `REDUCE(GetContinuationPreservedEmbedderData)` and `REDUCE(SetContinuationPreservedEmbedderData)`: These functions deal with getting and setting embedder-specific data that needs to be preserved across continuations (like async/await).

11. **Array Transitions:**
    - `TransitionElementsTo`:  Handles the process of changing the internal representation (elements kind) of a JavaScript array (e.g., from Smi-only elements to double elements or holey elements).

12. **Map Comparison:**
    - `CompareMapAgainstMultipleMaps`: Efficiently checks if a given `Map` object is equal to any of the `Map` objects in a provided list.

**Is `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` a Torque source?**

No, if the file ends with `.inl.h`, it's a standard C++ header file with inline function definitions. Torque source files typically end with `.tq`.

**Relationship to JavaScript Functionality:**

This file has a *very direct* relationship to JavaScript functionality. The operations implemented here are the underlying mechanisms that power many JavaScript features.

**Examples:**

* **Hash Maps/Sets:** The `FindOrderedHashEntry` function is directly related to how JavaScript `Map` and `Set` work. When you access a `Map` using `map.get(key)` or check if a `Set` has a value using `set.has(value)`, the underlying implementation (at the machine code level) will involve logic similar to this function.

   ```javascript
   const myMap = new Map();
   myMap.set('a', 1);
   myMap.set('b', 2);
   console.log(myMap.get('a')); // Internally uses hash lookup

   const mySet = new Set();
   mySet.add(5);
   console.log(mySet.has(5));   // Internally uses hash lookup
   ```

* **Strings:** The string manipulation functions are used when you work with strings in JavaScript.

   ```javascript
   const str = "你好"; // Contains characters outside the basic ASCII range
   console.log(str.length); //  Internally involves checking for surrogate pairs
   console.log(str.charCodeAt(0));
   ```

* **BigInts:** The BigInt operations are used when you work with JavaScript's `BigInt` type.

   ```javascript
   const largeNumber = 9007199254740991n + 1n; // BigInt addition
   console.log(largeNumber);
   ```

* **Typed Arrays:** The `BuildTypedArrayDataPointer` function is essential for accessing the underlying memory buffer of Typed Arrays.

   ```javascript
   const buffer = new ArrayBuffer(16);
   const uint8Array = new Uint8Array(buffer);
   uint8Array[0] = 42; // Low-level memory access
   ```

**Code Logic Reasoning (Example: `FindOrderedHashEntry`)**

**Hypothetical Input:**

* `data_structure`: An `OrderedHashMap` object in memory containing the following key-value pairs (assuming keys are small integers): `{ 1: 'value1', 5: 'value5', 9: 'value9' }`. Let's assume the hash table has a size of 8 buckets.
* `key`: The integer `5`.

**Expected Output:**

The memory address of the entry in the hash map where the key is `5`. This entry would likely contain pointers to the key `5` and the value `'value5'`.

**Step-by-step Logic:**

1. **Compute Hash:** `ComputeUnseededHash(5)` would be calculated. Let's say the result is `12345`.
2. **Calculate Bucket Index:**
   - `number_of_buckets` would be loaded from the `data_structure` (assuming it's 8).
   - `hash & (number_of_buckets - 1)` would be `12345 & 7`. This would give the bucket index (between 0 and 7).
3. **Load First Entry:** The address of the first entry in the calculated bucket is loaded.
4. **Loop and Compare:**
   - The code enters a loop, starting with the first entry in the bucket.
   - It checks if the current entry is `kNotFound` (meaning the bucket is empty or the end of a chain).
   - If not `kNotFound`, it loads the `candidate_key` from the entry.
   - It compares the `candidate_key` with the input `key` (5).
   - If they match, the address of the current entry is the `result`.
   - If they don't match, it loads the `next_entry` pointer from the current entry and continues the loop.

**Common Programming Errors (Related to Concepts):**

While JavaScript developers don't directly interact with this C++ code, understanding the underlying concepts can help avoid certain programming errors:

* **Inefficient Use of Objects as Keys in Maps/Sets (Pre-ES6):**  Before `Map` and `Set`, developers often used plain JavaScript objects as "dictionaries."  They might make the mistake of thinking that two distinct objects with the same properties will be treated as the same key. However, object identity is used, not structural equality.

   ```javascript
   const obj1 = { id: 1 };
   const obj2 = { id: 1 };
   const myObjMap = {};
   myObjMap[obj1] = 'value1';
   console.log(myObjMap[obj2]); // Output: undefined (obj1 and obj2 are different objects)

   const myMap = new Map();
   myMap.set(obj1, 'value1');
   console.log(myMap.get(obj2)); // Output: undefined (same reason)
   ```

* **Understanding String Encodings:** Developers might make assumptions about the length of a string being equal to the number of characters, which isn't true for characters outside the Basic Multilingual Plane (BMP) that use surrogate pairs.

   ```javascript
   const emoji = "😊";
   console.log(emoji.length);       // Output: 2 (because it's a surrogate pair)
   console.log(emoji.charCodeAt(0)); // First code unit
   console.log(emoji.charCodeAt(1)); // Second code unit
   ```

* **Performance Implications of Array Operations:** Understanding how array transitions work internally can help developers write more performant code. For example, repeatedly adding elements of different types to an array can trigger multiple transitions, which can have a performance cost.

**歸納一下它的功能 (Summary of its Functionality):**

The `v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h` header file provides the low-level building blocks for the Turboshaft compiler's machine lowering phase. It contains inline functions that implement fundamental operations related to:

* **Data structure manipulation:**  Searching hash maps and sets.
* **String and character handling:** Loading surrogate pairs, creating strings from code points.
* **Number and BigInt operations:** Allocation, arithmetic.
* **Memory access:** Loading and storing data in the heap.
* **Type checking and conversion:** Ensuring operations are performed on the correct data types.
* **Deoptimization:** Handling cases where optimizations are no longer valid.
* **Interaction with the V8 runtime:** Calling runtime functions for complex tasks.

Essentially, this file bridges the gap between high-level, abstract operations and the concrete, machine-specific instructions that the processor will eventually execute. It's a critical component for achieving high performance in V8 by enabling the compiler to generate efficient machine code.

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/machine-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
ey: {
        // Compute the integer hash code.
        V<WordPtr> hash = __ ChangeUint32ToUintPtr(ComputeUnseededHash(key));

        V<WordPtr> number_of_buckets =
            __ ChangeInt32ToIntPtr(__ UntagSmi(__ template LoadField<Smi>(
                data_structure,
                AccessBuilder::ForOrderedHashMapOrSetNumberOfBuckets())));
        hash = __ WordPtrBitwiseAnd(hash, __ WordPtrSub(number_of_buckets, 1));
        V<WordPtr> first_entry = __ ChangeInt32ToIntPtr(__ UntagSmi(__ Load(
            data_structure,
            __ WordPtrAdd(__ WordPtrShiftLeft(hash, kTaggedSizeLog2),
                          OrderedHashMap::HashTableStartOffset()),
            LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedSigned())));

        Label<WordPtr> done(this);
        LoopLabel<WordPtr> loop(this);
        GOTO(loop, first_entry);

        BIND_LOOP(loop, entry) {
          GOTO_IF(__ WordPtrEqual(entry, OrderedHashMap::kNotFound), done,
                  entry);
          V<WordPtr> candidate =
              __ WordPtrAdd(__ WordPtrMul(entry, OrderedHashMap::kEntrySize),
                            number_of_buckets);
          V<Object> candidate_key = __ Load(
              data_structure,
              __ WordPtrAdd(__ WordPtrShiftLeft(candidate, kTaggedSizeLog2),
                            OrderedHashMap::HashTableStartOffset()),
              LoadOp::Kind::TaggedBase(), MemoryRepresentation::AnyTagged());

          IF (LIKELY(__ ObjectIsSmi(candidate_key))) {
            GOTO_IF(
                __ Word32Equal(__ UntagSmi(V<Smi>::Cast(candidate_key)), key),
                done, candidate);
          } ELSE IF (__ TaggedEqual(
                        __ LoadMapField(candidate_key),
                        __ HeapConstant(factory_->heap_number_map()))) {
            GOTO_IF(__ Float64Equal(__ LoadHeapNumberValue(
                                        V<HeapNumber>::Cast(candidate_key)),
                                    __ ChangeInt32ToFloat64(key)),
                    done, candidate);
          }

          V<WordPtr> next_entry = __ ChangeInt32ToIntPtr(__ UntagSmi(__ Load(
              data_structure,
              __ WordPtrAdd(__ WordPtrShiftLeft(candidate, kTaggedSizeLog2),
                            (OrderedHashMap::HashTableStartOffset() +
                             OrderedHashMap::kChainOffset * kTaggedSize)),
              LoadOp::Kind::TaggedBase(),
              MemoryRepresentation::TaggedSigned())));
          GOTO(loop, next_entry);
        }

        BIND(done, result);
        return result;
      }
      case FindOrderedHashEntryOp::Kind::kFindOrderedHashSetEntry:
        return __ CallBuiltin_FindOrderedHashSetEntry(
            isolate_, __ NoContextConstant(), data_structure, key);
    }
  }

  // Loads a surrogate pair from {string} starting at {index} and returns the
  // result encode in {encoding}. Note that UTF32 encoding is identical to the
  // code point. If the string's {length} is already available, it can be
  // passed, otherwise it will be loaded when required.
  V<Word32> LoadSurrogatePairAt(V<String> string, OptionalV<WordPtr> length,
                                V<WordPtr> index, UnicodeEncoding encoding) {
    Label<Word32> done(this);

    V<Word32> first_code_unit = __ StringCharCodeAt(string, index);
    GOTO_IF_NOT(UNLIKELY(__ Word32Equal(
                    __ Word32BitwiseAnd(first_code_unit, 0xFC00), 0xD800)),
                done, first_code_unit);
    if (!length.has_value()) {
      length = __ ChangeUint32ToUintPtr(__ template LoadField<Word32>(
          string, AccessBuilder::ForStringLength()));
    }
    V<WordPtr> next_index = __ WordPtrAdd(index, 1);
    GOTO_IF_NOT(__ IntPtrLessThan(next_index, length.value()), done,
                first_code_unit);

    V<Word32> second_code_unit = __ StringCharCodeAt(string, next_index);
    GOTO_IF_NOT(
        __ Word32Equal(__ Word32BitwiseAnd(second_code_unit, 0xFC00), 0xDC00),
        done, first_code_unit);

    switch (encoding) {
      case UnicodeEncoding::UTF16: {
// Need to swap the order for big-endian platforms
#if V8_TARGET_BIG_ENDIAN
        V<Word32> value = __ Word32BitwiseOr(
            __ Word32ShiftLeft(first_code_unit, 16), second_code_unit);
#else
        V<Word32> value = __ Word32BitwiseOr(
            __ Word32ShiftLeft(second_code_unit, 16), first_code_unit);
#endif
        GOTO(done, value);
        break;
      }
      case UnicodeEncoding::UTF32: {
        const int32_t surrogate_offset = 0x10000 - (0xD800 << 10) - 0xDC00;
        V<Word32> value =
            __ Word32Add(__ Word32ShiftLeft(first_code_unit, 10),
                         __ Word32Add(second_code_unit, surrogate_offset));
        GOTO(done, value);
        break;
      }
    }

    BIND(done, result);
    return result;
  }

  V<String> StringFromSingleCharCode(V<Word32> code) {
    Label<String> done(this);

    // Check if the {code} is a one byte character.
    IF (LIKELY(__ Uint32LessThanOrEqual(code, String::kMaxOneByteCharCode))) {
      // Load the isolate wide single character string table.
      V<FixedArray> table = __ SingleCharacterStringTableConstant();

      // Compute the {table} index for {code}.
      V<WordPtr> index = __ ChangeUint32ToUintPtr(code);

      // Load the string for the {code} from the single character string
      // table.
      V<String> entry = __ LoadElement(
          table, AccessBuilderTS::ForFixedArrayElement<String>(), index);

      // Use the {entry} from the {table}.
      GOTO(done, entry);
    } ELSE {
      Uninitialized<SeqTwoByteString> string =
          AllocateSeqTwoByteString(1, AllocationType::kYoung);
      __ InitializeElement(
          string, AccessBuilderTS::ForSeqTwoByteStringCharacter(), 0, code);
      GOTO(done, __ FinishInitialization(std::move(string)));
    }

    BIND(done, result);
    return result;
  }

  V<String> StringFromSingleCodePoint(V<Word32> codepoint,
                                      UnicodeEncoding encoding) {
    Label<String> done(this);
    // Check if the input is a single code unit.
    GOTO_IF(LIKELY(__ Uint32LessThan(codepoint, 0x10000)), done,
            StringFromSingleCharCode(codepoint));

    V<Word32> code;
    switch (encoding) {
      case UnicodeEncoding::UTF16:
        code = codepoint;
        break;
      case UnicodeEncoding::UTF32: {
        // Convert UTF32 to UTF16 code units and store as a 32 bit word.
        V<Word32> lead_offset = __ Word32Constant(0xD800 - (0x10000 >> 10));

        // lead = (codepoint >> 10) + LEAD_OFFSET
        V<Word32> lead = __ Word32Add(__ Word32ShiftRightLogical(codepoint, 10),
                                      lead_offset);

        // trail = (codepoint & 0x3FF) + 0xDC00
        V<Word32> trail =
            __ Word32Add(__ Word32BitwiseAnd(codepoint, 0x3FF), 0xDC00);

        // codepoint = (trail << 16) | lead
#if V8_TARGET_BIG_ENDIAN
        code = __ Word32BitwiseOr(__ Word32ShiftLeft(lead, 16), trail);
#else
        code = __ Word32BitwiseOr(__ Word32ShiftLeft(trail, 16), lead);
#endif
        break;
      }
    }

    Uninitialized<SeqTwoByteString> string =
        AllocateSeqTwoByteString(2, AllocationType::kYoung);
    // Write the code as a single 32-bit value by adapting the elements
    // access to SeqTwoByteString characters.
    auto access = AccessBuilderTS::ForSeqTwoByteStringCharacter();
    access.machine_type = MachineType::Uint32();
    __ InitializeElement(string, access, 0, code);
    GOTO(done, __ FinishInitialization(std::move(string)));

    BIND(done, result);
    return result;
  }

  Uninitialized<SeqTwoByteString> AllocateSeqTwoByteString(
      uint32_t length, AllocationType type) {
    __ CodeComment("AllocateSeqTwoByteString");
    DCHECK_GT(length, 0);
    // Allocate a new string object.
    Uninitialized<SeqTwoByteString> string =
        __ template Allocate<SeqTwoByteString>(
            SeqTwoByteString::SizeFor(length), type);
    // Set padding to 0.
    __ Initialize(string, __ IntPtrConstant(0),
                  MemoryRepresentation::TaggedSigned(),
                  WriteBarrierKind::kNoWriteBarrier,
                  SeqTwoByteString::SizeFor(length) - kObjectAlignment);
    // Initialize remaining fields.
    __ InitializeField(string, AccessBuilderTS::ForMap(),
                       __ SeqTwoByteStringMapConstant());
    __ InitializeField(string, AccessBuilderTS::ForStringLength(), length);
    __ InitializeField(string, AccessBuilderTS::ForNameRawHashField(),
                       Name::kEmptyHashField);
    // Do not finish allocation here, because the caller has to initialize
    // characters.
    return string;
  }

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  V<Object> REDUCE(GetContinuationPreservedEmbedderData)() {
    return __ LoadOffHeap(
        __ IsolateField(IsolateFieldId::kContinuationPreservedEmbedderData),
        MemoryRepresentation::UncompressedTaggedPointer());
  }

  V<None> REDUCE(SetContinuationPreservedEmbedderData)(V<Object> data) {
    __ StoreOffHeap(
        __ IsolateField(IsolateFieldId::kContinuationPreservedEmbedderData),
        data, MemoryRepresentation::UncompressedTaggedPointer());
    return {};
  }
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

 private:
  V<Word32> BuildUint32Mod(V<Word32> left, V<Word32> right) {
    Label<Word32> done(this);

    // Compute the mask for the {rhs}.
    V<Word32> msk = __ Word32Sub(right, 1);

    // Check if the {rhs} is a power of two.
    IF (__ Word32Equal(__ Word32BitwiseAnd(right, msk), 0)) {
      // The {rhs} is a power of two, just do a fast bit masking.
      GOTO(done, __ Word32BitwiseAnd(left, msk));
    } ELSE {
      // The {rhs} is not a power of two, do a generic Uint32Mod.
      GOTO(done, __ Uint32Mod(left, right));
    }

    BIND(done, result);
    return result;
  }

  // Pass {bitfield} = {digit} = OpIndex::Invalid() to construct the canonical
  // 0n BigInt.
  V<BigInt> AllocateBigInt(V<Word32> bitfield, V<Word64> digit) {
    if (Asm().generating_unreachable_operations()) return OpIndex::Invalid();

    DCHECK(Is64());
    DCHECK_EQ(bitfield.valid(), digit.valid());
    static constexpr auto zero_bitfield =
        BigInt::SignBits::update(BigInt::LengthBits::encode(0), false);

    V<Map> map = __ HeapConstant(factory_->bigint_map());
    auto bigint = __ template Allocate<FreshlyAllocatedBigInt>(
        __ IntPtrConstant(BigInt::SizeFor(digit.valid() ? 1 : 0)),
        AllocationType::kYoung);
    __ InitializeField(bigint, AccessBuilder::ForMap(), map);
    __ InitializeField(
        bigint, AccessBuilder::ForBigIntBitfield(),
        bitfield.valid() ? bitfield : __ Word32Constant(zero_bitfield));

    // BigInts have no padding on 64 bit architectures with pointer compression.
#ifdef BIGINT_NEEDS_PADDING
    __ InitializeField(bigint, AccessBuilder::ForBigIntOptionalPadding(),
                       __ Word32Constant(0));
#endif
    if (digit.valid()) {
      __ InitializeField(
          bigint, AccessBuilder::ForBigIntLeastSignificantDigit64(), digit);
    }
    return V<BigInt>::Cast(__ FinishInitialization(std::move(bigint)));
  }

  void TagSmiOrOverflow(V<Word32> input, Label<>* overflow,
                        Label<Number>* done) {
    DCHECK(SmiValuesAre31Bits());

    // Check for overflow at the same time that we are smi tagging.
    // Since smi tagging shifts left by one, it's the same as adding value
    // twice.
    V<Tuple<Word32, Word32>> add = __ Int32AddCheckOverflow(input, input);
    V<Word32> check = __ template Projection<1>(add);
    GOTO_IF(UNLIKELY(check), *overflow);
    GOTO(*done, __ BitcastWord32ToSmi(__ template Projection<0>(add)));
  }

  // `IsNonZero` converts any non-0 value into 1.
  V<Word32> IsNonZero(V<Word32> value) {
    return __ Word32Equal(__ Word32Equal(value, 0), 0);
  }

  V<HeapNumber> AllocateHeapNumber(V<Float64> value) {
    return __ AllocateHeapNumberWithValue(value, factory_);
  }

  V<Float64> ConvertHeapObjectToFloat64OrDeopt(
      V<Object> heap_object, V<FrameState> frame_state,
      ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind input_kind,
      const FeedbackSource& feedback) {
    V<Map> map = __ LoadMapField(heap_object);
    switch (input_kind) {
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kSmi:
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
          kNumberOrString:
        UNREACHABLE();
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber: {
        V<Word32> is_number =
            __ TaggedEqual(map, __ HeapConstant(factory_->heap_number_map()));
        __ DeoptimizeIfNot(is_number, frame_state,
                           DeoptimizeReason::kNotAHeapNumber, feedback);
        break;
      }
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
          kNumberOrBoolean: {
#if V8_STATIC_ROOTS_BOOL
        // TODO(leszeks): Consider checking the boolean oddballs by value,
        // before loading the map.
        static_assert(StaticReadOnlyRoot::kBooleanMap + Map::kSize ==
                      StaticReadOnlyRoot::kHeapNumberMap);
        V<Word32> map_int32 =
            __ TruncateWordPtrToWord32(__ BitcastHeapObjectToWordPtr(map));
        V<Word32> is_in_range = __ Uint32LessThanOrEqual(
            __ Word32Sub(map_int32,
                         __ Word32Constant(StaticReadOnlyRoot::kBooleanMap)),
            __ Word32Constant(StaticReadOnlyRoot::kHeapNumberMap -
                              StaticReadOnlyRoot::kBooleanMap));
        __ DeoptimizeIfNot(is_in_range, frame_state,
                           DeoptimizeReason::kNotANumberOrBoolean, feedback);
#else
        IF_NOT (__ TaggedEqual(map,
                               __ HeapConstant(factory_->heap_number_map()))) {
          __ DeoptimizeIfNot(
              __ TaggedEqual(map, __ HeapConstant(factory_->boolean_map())),
              frame_state, DeoptimizeReason::kNotANumberOrBoolean, feedback);
        }
#endif

        break;
      }
      case ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
          kNumberOrOddball: {
#if V8_STATIC_ROOTS_BOOL
        constexpr auto kNumberOrOddballRange =
            InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(
                HEAP_NUMBER_TYPE, ODDBALL_TYPE)
                .value();
        V<Word32> map_int32 =
            __ TruncateWordPtrToWord32(__ BitcastHeapObjectToWordPtr(map));
        V<Word32> is_in_range = __ Uint32LessThanOrEqual(
            __ Word32Sub(map_int32,
                         __ Word32Constant(kNumberOrOddballRange.first)),
            __ Word32Constant(kNumberOrOddballRange.second -
                              kNumberOrOddballRange.first));
        __ DeoptimizeIfNot(is_in_range, frame_state,
                           DeoptimizeReason::kNotANumberOrOddball, feedback);
#else
        IF_NOT (__ TaggedEqual(map,
                               __ HeapConstant(factory_->heap_number_map()))) {
          // For oddballs also contain the numeric value, let us just check that
          // we have an oddball here.
          V<Word32> instance_type = __ LoadInstanceTypeField(map);
          __ DeoptimizeIfNot(__ Word32Equal(instance_type, ODDBALL_TYPE),
                             frame_state,
                             DeoptimizeReason::kNotANumberOrOddball, feedback);
        }
#endif

        break;
      }
    }
    return __ template LoadField<Float64>(
        heap_object, AccessBuilder::ForHeapNumberOrOddballOrHoleValue());
  }

  OpIndex LoadFromSeqString(V<Object> receiver, V<WordPtr> position,
                            V<Word32> onebyte) {
    Label<Word32> done(this);

    IF (onebyte) {
      GOTO(done, __ template LoadNonArrayBufferElement<Word32>(
                     receiver, AccessBuilder::ForSeqOneByteStringCharacter(),
                     position));
    } ELSE {
      GOTO(done, __ template LoadNonArrayBufferElement<Word32>(
                     receiver, AccessBuilder::ForSeqTwoByteStringCharacter(),
                     position));
    }

    BIND(done, result);
    return result;
  }

  void MigrateInstanceOrDeopt(V<HeapObject> heap_object, V<Map> heap_object_map,
                              V<FrameState> frame_state,
                              const FeedbackSource& feedback) {
    // If {heap_object_map} is not deprecated, the migration attempt does not
    // make sense.
    V<Word32> bitfield3 = __ template LoadField<Word32>(
        heap_object_map, AccessBuilder::ForMapBitField3());
    V<Word32> deprecated =
        __ Word32BitwiseAnd(bitfield3, Map::Bits3::IsDeprecatedBit::kMask);
    __ DeoptimizeIfNot(deprecated, frame_state, DeoptimizeReason::kWrongMap,
                       feedback);
    V<Object> result = __ CallRuntime_TryMigrateInstance(
        isolate_, __ NoContextConstant(), heap_object);
    // TryMigrateInstance returns a Smi value to signal failure.
    __ DeoptimizeIf(__ ObjectIsSmi(result), frame_state,
                    DeoptimizeReason::kInstanceMigrationFailed, feedback);
  }

  // TODO(nicohartmann@): Might use the CallBuiltinDescriptors here.
  OpIndex CallBuiltinForBigIntOp(Builtin builtin,
                                 std::initializer_list<OpIndex> arguments) {
    DCHECK_IMPLIES(builtin == Builtin::kBigIntUnaryMinus,
                   arguments.size() == 1);
    DCHECK_IMPLIES(builtin != Builtin::kBigIntUnaryMinus,
                   arguments.size() == 2);
    base::SmallVector<OpIndex, 4> args(arguments);
    args.push_back(__ NoContextConstant());

    Callable callable = Builtins::CallableFor(isolate_, builtin);
    auto descriptor = Linkage::GetStubCallDescriptor(
        __ graph_zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(),
        CallDescriptor::kNoFlags, Operator::kFoldable | Operator::kNoThrow);
    auto ts_descriptor = TSCallDescriptor::Create(
        descriptor, CanThrow::kNo, LazyDeoptOnThrow::kNo, __ graph_zone());
    return __ Call(__ HeapConstant(callable.code()), OpIndex::Invalid(),
                   base::VectorOf(args), ts_descriptor);
  }

  Builtin GetBuiltinForBigIntBinop(BigIntBinopOp::Kind kind) {
    switch (kind) {
      case BigIntBinopOp::Kind::kAdd:
        return Builtin::kBigIntAddNoThrow;
      case BigIntBinopOp::Kind::kSub:
        return Builtin::kBigIntSubtractNoThrow;
      case BigIntBinopOp::Kind::kMul:
        return Builtin::kBigIntMultiplyNoThrow;
      case BigIntBinopOp::Kind::kDiv:
        return Builtin::kBigIntDivideNoThrow;
      case BigIntBinopOp::Kind::kMod:
        return Builtin::kBigIntModulusNoThrow;
      case BigIntBinopOp::Kind::kBitwiseAnd:
        return Builtin::kBigIntBitwiseAndNoThrow;
      case BigIntBinopOp::Kind::kBitwiseOr:
        return Builtin::kBigIntBitwiseOrNoThrow;
      case BigIntBinopOp::Kind::kBitwiseXor:
        return Builtin::kBigIntBitwiseXorNoThrow;
      case BigIntBinopOp::Kind::kShiftLeft:
        return Builtin::kBigIntShiftLeftNoThrow;
      case BigIntBinopOp::Kind::kShiftRightArithmetic:
        return Builtin::kBigIntShiftRightNoThrow;
    }
  }

  V<WordPtr> BuildTypedArrayDataPointer(V<Object> base, V<WordPtr> external) {
    if (__ matcher().MatchZero(base)) return external;
    V<WordPtr> untagged_base = __ BitcastTaggedToWordPtr(base);
    if (COMPRESS_POINTERS_BOOL) {
      // Zero-extend Tagged_t to UintPtr according to current compression
      // scheme so that the addition with |external_pointer| (which already
      // contains compensated offset value) will decompress the tagged value.
      // See JSTypedArray::ExternalPointerCompensationForOnHeapArray() for
      // details.
      untagged_base =
          __ ChangeUint32ToUintPtr(__ TruncateWordPtrToWord32(untagged_base));
    }
    return __ WordPtrAdd(untagged_base, external);
  }

  V<Word32> ComputeUnseededHash(V<Word32> value) {
    // See v8::internal::ComputeUnseededHash()
    value = __ Word32Add(__ Word32BitwiseXor(value, 0xFFFFFFFF),
                         __ Word32ShiftLeft(value, 15));
    value = __ Word32BitwiseXor(value, __ Word32ShiftRightLogical(value, 12));
    value = __ Word32Add(value, __ Word32ShiftLeft(value, 2));
    value = __ Word32BitwiseXor(value, __ Word32ShiftRightLogical(value, 4));
    value = __ Word32Mul(value, 2057);
    value = __ Word32BitwiseXor(value, __ Word32ShiftRightLogical(value, 16));
    value = __ Word32BitwiseAnd(value, 0x3FFFFFFF);
    return value;
  }

  void TransitionElementsTo(V<JSArray> array, ElementsKind from,
                            ElementsKind to, Handle<Map> target_map) {
    DCHECK(IsMoreGeneralElementsKindTransition(from, to));
    DCHECK(to == HOLEY_ELEMENTS || to == HOLEY_DOUBLE_ELEMENTS);

    if (IsSimpleMapChangeTransition(from, to)) {
      __ StoreField(array, AccessBuilder::ForMap(),
                    __ HeapConstant(target_map));
    } else {
      // Instance migration, call out to the runtime for {array}.
      __ CallRuntime_TransitionElementsKind(isolate_, __ NoContextConstant(),
                                            array, __ HeapConstant(target_map));
    }
  }

  V<Word32> CompareMapAgainstMultipleMaps(V<Map> heap_object_map,
                                          const ZoneRefSet<Map>& maps) {
    if (maps.is_empty()) {
      return __ Word32Constant(0);
    }
    V<Word32> result;
    for (size_t i = 0; i < maps.size(); ++i) {
      V<Map> map = __ HeapConstant(maps[i].object());
      if (i == 0) {
        result = __ TaggedEqual(heap_object_map, map);
      } else {
        result =
            __ Word32BitwiseOr(result, __ TaggedEqual(heap_object_map, map));
      }
    }
    return result;
  }

  bool DependOnNoUndetectableObjectsProtector() {
    if (!undetectable_objects_protector_) {
      UnparkedScopeIfNeeded unpark(broker_);
      undetectable_objects_protector_ =
          broker_->dependencies()->DependOnNoUndetectableObjectsProtector();
    }
    return *undetectable_objects_protector_;
  }

  Isolate* isolate_ = __ data() -> isolate();
  Factory* factory_ = isolate_ ? isolate_->factory() : nullptr;
  JSHeapBroker* broker_ = __ data() -> broker();
  std::optional<bool> undetectable_objects_protector_ = {};
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_MACHINE_LOWERING_REDUCER_INL_H_

"""


```