Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/builtins-regexp-gen.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core functions:**  Scan the code for function definitions within the `RegExpBuiltinsAssembler` class.
2. **Analyze each function:**  Examine the code within each function to understand its purpose. Look for keywords, built-in calls, and control flow.
3. **Relate to JavaScript:**  If a function seems related to JavaScript's RegExp functionality, try to find the corresponding JavaScript method.
4. **Provide examples:** Illustrate the functionality with JavaScript code examples.
5. **Infer logic and provide examples:** If the code involves logical steps (like loops or conditional statements), try to reason about the input and output. Provide hypothetical examples.
6. **Identify potential errors:** Think about common mistakes developers might make when using the related JavaScript features.
7. **Synthesize the overall functionality:** Summarize the purpose of the code based on the analysis of individual functions.

**Detailed Analysis of the Code Snippet:**

* **`RegExpBuiltinsAssembler::RegExpSplit`:** This function seems to implement the logic for the `String.prototype.split()` method when used with a regular expression.
    * It initializes a `GrowableFixedArray` to store the split substrings.
    * It uses `RegExpExecInternal` to find matches of the regular expression in the input string.
    * It iterates through the matches and extracts the substrings between them.
    * It handles the `limit` argument to control the number of splits.
    * It deals with edge cases like empty strings and zero limits.

* **`RegExpBuiltinsAssembler::RegExpExecInternal_Batched`:** This function appears to be an internal helper for executing regular expressions in a "batched" manner, primarily used for global regular expressions.
    * It calls into the "irregexp" engine (`RegExpExecInternal`).
    * It loops to find multiple matches of a global regular expression.
    * It uses `OncePerBatchFunction` and `OncePerMatchFunction` callbacks to process matches.

* **`RegExpBuiltinsAssembler::RegExpMatchGlobal`:** This function seems to implement the logic for `String.prototype.matchAll()` or `String.prototype.match()` with a global regular expression.
    * It utilizes `RegExpExecInternal_Batched` to find all matches.
    * It creates an array containing all the matched substrings.

* **`RegExpBuiltinsAssembler::AppendStringSlice`:** This is a helper function to extract a substring and append it to another string.

* **`RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString`:** This function implements the logic for `String.prototype.replace()` with a global regular expression and a simple replacement string (no special `$n` patterns).
    * It uses `RegExpExecInternal_Batched` to find all matches.
    * It constructs the result string by appending the parts of the original string before each match, followed by the replacement string.

**Consider the ".tq" aspect:** The prompt mentions that if the file ended with ".tq", it would be Torque code. Since this file ends with ".cc", it's C++ code generated from Torque or directly written in C++.

**Final Synthesis:** Based on the individual function analysis, the code primarily handles the implementation of several JavaScript `String.prototype` methods related to regular expressions: `split()`, `match()` (global), and `replace()` (global with a simple replacement string). It uses internal V8 mechanisms for efficient regular expression execution.
`v8/src/builtins/builtins-regexp-gen.cc` is a V8 source code file that contains implementations of built-in functions related to regular expressions (RegExp). Since the file ends with `.cc`, it's a standard C++ source file and not a Torque file.

Here's a breakdown of the functionalities implemented in this specific snippet:

**1. `RegExpBuiltinsAssembler::RegExpSplit`:** This function implements the logic for the `String.prototype.split()` method when used with a regular expression as the separator.

*   **Functionality:** It takes a string and a regular expression as input and splits the string into an array of substrings based on the occurrences of the regular expression. It also handles the optional `limit` argument, which restricts the number of splits.
*   **JavaScript Example:**
    ```javascript
    const str = "a,b,c,d";
    const regex = /,/;
    const result = str.split(regex); // Output: ["a", "b", "c", "d"]

    const str2 = "one two three four";
    const regex2 = /\s+/;
    const result2 = str2.split(regex2, 2); // Output: ["one", "two"]
    ```
*   **Code Logic Inference:**
    *   It first checks for an empty limit and returns an empty array if so.
    *   It handles the case of an empty input string. If the regex matches the empty string, it returns an array with an empty string; otherwise, it returns an array with the original empty string.
    *   It iteratively searches for matches of the regular expression in the string.
    *   Between each match, it extracts the substring and adds it to the result array.
    *   It respects the `limit` by stopping the splitting process once the limit is reached.
    *   It handles capturing groups within the regular expression by including the captured substrings in the result array.
*   **Hypothetical Input and Output:**
    *   **Input:** `string = "hello123world456"`, `regexp = /\d+/`, `limit = undefined`
    *   **Output:** `["hello", "world", ""]` (The empty string at the end is because the last match is at the end of the string)
    *   **Input:** `string = "apple,banana,orange"`, `regexp = /,/`, `limit = 2`
    *   **Output:** `["apple", "banana"]`
*   **Common Programming Errors:**
    *   Forgetting that capturing groups in the regex will be included in the result array.
        ```javascript
        const str = "abc123def";
        const regex = /([a-z]+)(\d+)/;
        const result = str.split(regex); // Output: ["", "abc", "123", "def"]
        ```
    *   Not understanding how the `limit` parameter works.

**2. `RegExpBuiltinsAssembler::RegExpExecInternal_Batched`:** This appears to be an internal helper function used for efficiently executing global regular expressions. It performs the execution in batches to optimize performance.

*   **Functionality:** It repeatedly executes the regular expression on the string, accumulating the matches. It's specifically designed for global regexps (`/g` flag).
*   **JavaScript Relation:** This function is an internal mechanism that supports the behavior of methods like `String.prototype.matchAll()` and `String.prototype.replace()` when used with global regular expressions.
*   **Code Logic Inference:**
    *   It allocates memory to store the offsets of the matches.
    *   It loops, repeatedly calling `RegExpExecInternal` to find batches of matches.
    *   It uses callbacks (`once_per_batch` and `once_per_match`) to process the found matches.
    *   It handles advancing the search index correctly, even for zero-length matches.
*   **No direct user-facing examples** as it's an internal function.

**3. `RegExpBuiltinsAssembler::RegExpMatchGlobal`:** This function implements the logic for the `String.prototype.match()` method when used with a global regular expression.

*   **Functionality:** It executes the regular expression globally on the input string and returns an array containing all the matched substrings. If no matches are found, it returns `null`.
*   **JavaScript Example:**
    ```javascript
    const str = "color colour";
    const regex = /colou?r/g;
    const matches = str.match(regex); // Output: ["color", "colour"]

    const str2 = "no matches here";
    const regex2 = /\d+/g;
    const matches2 = str2.match(regex2); // Output: null
    ```
*   **Code Logic Inference:**
    *   It uses `RegExpExecInternal_Batched` to find all matches.
    *   It collects the matched substrings into a `GrowableFixedArray`.
    *   It returns `null` if no matches are found.
*   **Hypothetical Input and Output:**
    *   **Input:** `string = "v8 javascript engine"`, `regexp = /[a-z]+/g`
    *   **Output:** `["v", "javascript", "engine"]`
*   **Common Programming Errors:**
    *   Assuming `match()` will always return an array. Remember to check for `null`.

**4. `RegExpBuiltinsAssembler::AppendStringSlice`:** This is a helper function to efficiently append a slice (substring) of one string to another.

*   **Functionality:**  It extracts a portion of a string and concatenates it to another string.
*   **JavaScript Relation:** This is an internal utility function used within other built-in methods for string manipulation.
*   **No direct user-facing examples** as it's an internal function.

**5. `RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString`:** This function implements the logic for the `String.prototype.replace()` method when used with a global regular expression and a simple replacement string (a string without special replacement patterns like `$n`, `$&`, etc.).

*   **Functionality:** It replaces all occurrences of the regular expression in the string with the provided replacement string.
*   **JavaScript Example:**
    ```javascript
    const str = "hello world world";
    const regex = /world/g;
    const newStr = str.replace(regex, "universe"); // Output: "hello universe universe"
    ```
*   **Code Logic Inference:**
    *   It uses `RegExpExecInternal_Batched` to find all matches.
    *   It iterates through the matches.
    *   For each match, it appends the portion of the original string before the match and then appends the replacement string to the result.
    *   Finally, it appends the remaining portion of the original string after the last match.
*   **Hypothetical Input and Output:**
    *   **Input:** `string = "count 1 count 2"`, `regexp = /count/g`, `replace_string = "number"`
    *   **Output:** `"number 1 number 2"`
*   **Common Programming Errors:**
    *   Thinking this function handles complex replacement patterns (like using `$1` for capturing groups). This specific function is for *simple* replacement strings.

**Summary of Functionalities:**

This part of `v8/src/builtins/builtins-regexp-gen.cc` focuses on implementing the core logic for several JavaScript `String.prototype` methods that involve regular expressions:

*   **`split()`:**  Splitting a string based on a regular expression separator.
*   **`match()` (global):** Finding all matches of a global regular expression in a string.
*   **`replace()` (global, simple replacement string):** Replacing all occurrences of a global regular expression with a fixed string.

The code utilizes internal V8 mechanisms like `RegExpExecInternal` and batching to efficiently perform these operations. It also handles various edge cases and optimizations to ensure correct and performant behavior of these essential JavaScript string methods.

Prompt: 
```
这是目录为v8/src/builtins/builtins-regexp-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-regexp-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
er_match = RegistersForCaptureCount(capture_count);
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(register_count_per_match);
  TNode<Int32T> result_offsets_vector_length =
      SmiToInt32(register_count_per_match);

  {
    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    // If the limit is zero, return an empty array.
    GotoIf(SmiEqual(limit, SmiZero()), &return_empty_array);

    TNode<Smi> string_length = LoadStringLengthAsSmi(string);

    // If passed the empty {string}, return either an empty array or a singleton
    // array depending on whether the {regexp} matches.
    {
      Label next(this), if_stringisempty(this, Label::kDeferred);
      Branch(SmiEqual(string_length, SmiZero()), &if_stringisempty, &next);

      BIND(&if_stringisempty);
      {
        TNode<IntPtrT> num_matches = UncheckedCast<IntPtrT>(RegExpExecInternal(
            context, regexp, string, SmiZero(), result_offsets_vector,
            result_offsets_vector_length));

        Label if_matched(this), if_not_matched(this);
        Branch(IntPtrEqual(num_matches, IntPtrConstant(0)), &if_not_matched,
               &if_matched);

        BIND(&if_matched);
        {
          CSA_DCHECK(this, IntPtrEqual(num_matches, IntPtrConstant(1)));
          CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
          TNode<RegExpMatchInfo> last_match_info = CAST(LoadContextElement(
              context, Context::REGEXP_LAST_MATCH_INFO_INDEX));

          InitializeMatchInfoFromRegisters(context, last_match_info,
                                           register_count_per_match, string,
                                           result_offsets_vector);
          Goto(&return_empty_array);
        }

        BIND(&if_not_matched);
        {
          TNode<Smi> length = SmiConstant(1);
          TNode<IntPtrT> capacity = IntPtrConstant(1);
          std::optional<TNode<AllocationSite>> allocation_site = std::nullopt;
          CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
          TNode<Map> array_map =
              LoadJSArrayElementsMap(elements_kind, CAST(context));
          var_result = AllocateJSArray(elements_kind, array_map, capacity,
                                       length, allocation_site);

          TNode<FixedArray> fixed_array =
              CAST(LoadElements(var_result.value()));
          UnsafeStoreFixedArrayElement(fixed_array, 0, string);

          Goto(&done);
        }
      }

      BIND(&next);
    }

    // Loop preparations.

    GrowableFixedArray array(state());

    TVARIABLE(Smi, var_last_matched_until, SmiZero());
    TVARIABLE(Smi, var_next_search_from, SmiZero());

    Label loop(this,
               {array.var_array(), array.var_length(), array.var_capacity(),
                &var_last_matched_until, &var_next_search_from}),
        push_suffix_and_out(this), out(this);
    Goto(&loop);

    BIND(&loop);
    {
      TNode<Smi> next_search_from = var_next_search_from.value();
      TNode<Smi> last_matched_until = var_last_matched_until.value();

      // We're done if we've reached the end of the string.
      GotoIf(SmiEqual(next_search_from, string_length), &push_suffix_and_out);

      // Search for the given {regexp}.

      TNode<IntPtrT> num_matches = UncheckedCast<IntPtrT>(RegExpExecInternal(
          context, regexp, string, next_search_from, result_offsets_vector,
          result_offsets_vector_length));

      // We're done if no match was found.
      GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &push_suffix_and_out);

      TNode<Int32T> match_from_int32 = UncheckedCast<Int32T>(
          Load(MachineType::Int32(), result_offsets_vector, IntPtrConstant(0)));
      TNode<Smi> match_from = SmiFromInt32(match_from_int32);

      // We're also done if the match is at the end of the string.
      GotoIf(SmiEqual(match_from, string_length), &push_suffix_and_out);

      // Set the LastMatchInfo.
      // TODO(jgruber): We could elide all but the last of these. BUT this is
      // tricky due to how we omit any match at the end of the string, which
      // makes it hard to tell if we're at the 'last match except for
      // empty-match-at-end-of-string'.
      CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
      TNode<RegExpMatchInfo> match_info = CAST(
          LoadContextElement(context, Context::REGEXP_LAST_MATCH_INFO_INDEX));
      match_info = InitializeMatchInfoFromRegisters(
          context, match_info, register_count_per_match, string,
          result_offsets_vector);

      TNode<Smi> match_to = LoadArrayElement(match_info, IntPtrConstant(1));

      // Advance index and continue if the match is empty.
      {
        Label next(this);

        GotoIfNot(SmiEqual(match_to, next_search_from), &next);
        GotoIfNot(SmiEqual(match_to, last_matched_until), &next);

        TNode<BoolT> is_unicode =
            Word32Or(FastFlagGetter(regexp, JSRegExp::kUnicode),
                     FastFlagGetter(regexp, JSRegExp::kUnicodeSets));
        TNode<Number> new_next_search_from =
            AdvanceStringIndex(string, next_search_from, is_unicode, true);
        var_next_search_from = CAST(new_next_search_from);
        Goto(&loop);

        BIND(&next);
      }

      // A valid match was found, add the new substring to the array.
      {
        TNode<Smi> from = last_matched_until;
        TNode<Smi> to = match_from;
        array.Push(CallBuiltin(Builtin::kSubString, context, string, from, to));
        GotoIf(WordEqual(array.length(), int_limit), &out);
      }

      // Add all captures to the array.
      {
        TNode<IntPtrT> int_num_registers =
            PositiveSmiUntag(register_count_per_match);

        TVARIABLE(IntPtrT, var_reg, IntPtrConstant(2));

        Label nested_loop(this, {array.var_array(), array.var_length(),
                                 array.var_capacity(), &var_reg}),
            nested_loop_out(this);
        Branch(IntPtrLessThan(var_reg.value(), int_num_registers), &nested_loop,
               &nested_loop_out);

        BIND(&nested_loop);
        {
          TNode<IntPtrT> reg = var_reg.value();
          TNode<Smi> from = LoadArrayElement(match_info, reg);
          TNode<Smi> to = LoadArrayElement(match_info, reg, 1 * kTaggedSize);

          Label select_capture(this), select_undefined(this), store_value(this);
          TVARIABLE(Object, var_value);
          Branch(SmiEqual(to, SmiConstant(-1)), &select_undefined,
                 &select_capture);

          BIND(&select_capture);
          {
            var_value =
                CallBuiltin(Builtin::kSubString, context, string, from, to);
            Goto(&store_value);
          }

          BIND(&select_undefined);
          {
            var_value = UndefinedConstant();
            Goto(&store_value);
          }

          BIND(&store_value);
          {
            array.Push(var_value.value());
            GotoIf(WordEqual(array.length(), int_limit), &out);

            TNode<IntPtrT> new_reg = IntPtrAdd(reg, IntPtrConstant(2));
            var_reg = new_reg;

            Branch(IntPtrLessThan(new_reg, int_num_registers), &nested_loop,
                   &nested_loop_out);
          }
        }

        BIND(&nested_loop_out);
      }

      var_last_matched_until = match_to;
      var_next_search_from = match_to;
      Goto(&loop);
    }

    BIND(&push_suffix_and_out);
    {
      TNode<Smi> from = var_last_matched_until.value();
      TNode<Smi> to = string_length;
      array.Push(CallBuiltin(Builtin::kSubString, context, string, from, to));
      Goto(&out);
    }

    BIND(&out);
    {
      var_result = array.ToJSArray(context);
      Goto(&done);
    }

    BIND(&return_empty_array);
    {
      TNode<Smi> length = SmiZero();
      TNode<IntPtrT> capacity = IntPtrZero();
      std::optional<TNode<AllocationSite>> allocation_site = std::nullopt;
      CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
      TNode<Map> array_map =
          LoadJSArrayElementsMap(elements_kind, CAST(context));
      var_result = AllocateJSArray(elements_kind, array_map, capacity, length,
                                   allocation_site);
      Goto(&done);
    }
  }

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&done);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_result.value();
}

TNode<IntPtrT> RegExpBuiltinsAssembler::RegExpExecInternal_Batched(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data, const VariableList& merge_vars,
    OncePerBatchFunction once_per_batch, OncePerMatchFunction once_per_match) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  // This calls into irregexp and loops over the returned result. Roughly:
  //
  // max_matches = .. that fit into the given offsets array;
  // num_matches_in_batch = max_matches;
  // index = 0;
  // while (num_matches_in_batch == max_matches) {
  //   num_matches_in_batch = ExecInternal(..., index);
  //   for (i = 0; i < num_matches_in_batch; i++) {
  //     .. handle match i
  //   }
  //   index = MaybeAdvanceZeroLength(last_end_index)
  // }

  Label out(this);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  // Determine the number of result slots we want and allocate them.
  TNode<Smi> register_count_per_match =
      RegistersForCaptureCount(LoadCaptureCount(data));
  // TODO(jgruber): Consider a different length selection that considers the
  // register count per match and can go higher than the current static offsets
  // size. Could be helpful for patterns that 1. have many captures and 2.
  // match many times in the given string.
  TNode<Smi> result_offsets_vector_length =
      SmiMax(register_count_per_match,
             SmiConstant(Isolate::kJSRegexpStaticOffsetsVectorSize));
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(result_offsets_vector_length);

  TNode<BoolT> is_unicode =
      Word32Or(FastFlagGetter(regexp, JSRegExp::kUnicode),
               FastFlagGetter(regexp, JSRegExp::kUnicodeSets));

  TVARIABLE(IntPtrT, var_last_match_offsets_vector, IntPtrConstant(0));
  TVARIABLE(Int32T, var_start_of_last_match, Int32Constant(0));
  TVARIABLE(Int32T, var_last_index, Int32Constant(0));
  FastStoreLastIndex(regexp, SmiConstant(0));

  TNode<IntPtrT> max_matches_in_batch =
      IntPtrDiv(SmiUntag(result_offsets_vector_length),
                SmiUntag(register_count_per_match));
  // Initialize such that we always enter the loop initially:
  TVARIABLE(IntPtrT, var_num_matches_in_batch, max_matches_in_batch);
  TVARIABLE(IntPtrT, var_num_matches, IntPtrConstant(0));

  // Loop over multiple batch executions:
  VariableList outer_loop_merge_vars(
      {&var_num_matches_in_batch, &var_num_matches, &var_last_index,
       &var_start_of_last_match, &var_last_match_offsets_vector},
      zone());
  outer_loop_merge_vars.insert(outer_loop_merge_vars.end(), merge_vars.begin(),
                               merge_vars.end());
  Label outer_loop(this, outer_loop_merge_vars);
  Label outer_loop_exit(this);
  Goto(&outer_loop);
  BIND(&outer_loop);
  {
    // Loop condition:
    GotoIf(
        IntPtrLessThan(var_num_matches_in_batch.value(), max_matches_in_batch),
        &outer_loop_exit);

    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    var_num_matches_in_batch = UncheckedCast<IntPtrT>(RegExpExecInternal(
        context, regexp, subject, SmiFromInt32(var_last_index.value()),
        result_offsets_vector, SmiToInt32(result_offsets_vector_length)));

    GotoIf(IntPtrEqual(var_num_matches_in_batch.value(), IntPtrConstant(0)),
           &outer_loop_exit);

    var_num_matches =
        IntPtrAdd(var_num_matches.value(), var_num_matches_in_batch.value());

    // At least one match was found. Construct the result array.
    //
    // Loop over the current batch of results:
    {
      once_per_batch(var_num_matches_in_batch.value());

      TNode<IntPtrT> register_count_per_match_intptr =
          SmiUntag(register_count_per_match);
      VariableList inner_loop_merge_vars(
          {&var_last_index, &var_start_of_last_match,
           &var_last_match_offsets_vector},
          zone());
      inner_loop_merge_vars.insert(inner_loop_merge_vars.end(),
                                   merge_vars.begin(), merge_vars.end());
      // Has to be IntPtrT for BuildFastLoop.
      TNode<IntPtrT> inner_loop_start =
          UncheckedCast<IntPtrT>(result_offsets_vector);
      TNode<IntPtrT> inner_loop_increment = WordShl(
          register_count_per_match_intptr, IntPtrConstant(kInt32SizeLog2));
      TNode<IntPtrT> inner_loop_end = IntPtrAdd(
          inner_loop_start,
          IntPtrMul(inner_loop_increment, var_num_matches_in_batch.value()));

      TVARIABLE(IntPtrT, var_inner_loop_index);
      BuildFastLoop<IntPtrT>(
          inner_loop_merge_vars, var_inner_loop_index, inner_loop_start,
          inner_loop_end,
          [&](TNode<IntPtrT> current_match_offsets_vector) {
            TNode<Int32T> start = UncheckedCast<Int32T>(
                Load(MachineType::Int32(), current_match_offsets_vector,
                     IntPtrConstant(0)));
            TNode<Int32T> end = UncheckedCast<Int32T>(
                Load(MachineType::Int32(), current_match_offsets_vector,
                     IntPtrConstant(kInt32Size)));

            once_per_match(UncheckedCast<RawPtrT>(current_match_offsets_vector),
                           start, end);

            var_last_match_offsets_vector = current_match_offsets_vector;
            var_start_of_last_match = start;
            var_last_index = end;
          },
          inner_loop_increment, LoopUnrollingMode::kYes,
          IndexAdvanceMode::kPost, IndexAdvanceDirection::kUp);
    }

    GotoIf(
        Word32NotEqual(var_start_of_last_match.value(), var_last_index.value()),
        &outer_loop);

    // For zero-length matches we need to run AdvanceStringIndex.
    var_last_index = SmiToInt32(CAST(AdvanceStringIndex(
        subject, SmiFromInt32(var_last_index.value()), is_unicode, true)));

    Goto(&outer_loop);
  }
  BIND(&outer_loop_exit);

  // If there were no matches, just return.
  GotoIf(IntPtrEqual(var_num_matches.value(), IntPtrConstant(0)), &out);

  // Otherwise initialize the last match info and the result JSArray.
  CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
  TNode<RegExpMatchInfo> last_match_info =
      CAST(LoadContextElement(context, Context::REGEXP_LAST_MATCH_INFO_INDEX));

  InitializeMatchInfoFromRegisters(context, last_match_info,
                                   register_count_per_match, subject,
                                   var_last_match_offsets_vector.value());

  Goto(&out);

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&out);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_num_matches.value();
}

TNode<HeapObject> RegExpBuiltinsAssembler::RegExpMatchGlobal(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  TVARIABLE(HeapObject, var_result, NullConstant());
  Label out(this);
  GrowableFixedArray array(state());

  VariableList merge_vars(
      {array.var_array(), array.var_length(), array.var_capacity()}, zone());
  TNode<IntPtrT> num_matches = RegExpExecInternal_Batched(
      context, regexp, subject, data, merge_vars,
      [&](TNode<IntPtrT> num_matches_in_batch) {
        array.Reserve(UncheckedCast<IntPtrT>(
            IntPtrAdd(array.length(), num_matches_in_batch)));
      },
      [&](TNode<RawPtrT> match_offsets, TNode<Int32T> match_start,
          TNode<Int32T> match_end) {
        TNode<Smi> start = SmiFromInt32(match_start);
        TNode<Smi> end = SmiFromInt32(match_end);

        // TODO(jgruber): Consider inlining this or at least reducing the number
        // of redundant checks.
        TNode<String> matched_string = CAST(
            CallBuiltin(Builtin::kSubString, context, subject, start, end));
        array.Push(matched_string);
      });

  CSA_DCHECK(this, IntPtrEqual(num_matches, array.length()));

  // No matches, return null.
  GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &out);

  // Otherwise create the JSArray.
  var_result = array.ToJSArray(context);
  Goto(&out);

  BIND(&out);
  return var_result.value();  // NullConstant | JSArray.
}

TNode<String> RegExpBuiltinsAssembler::AppendStringSlice(
    TNode<Context> context, TNode<String> to_string, TNode<String> from_string,
    TNode<Smi> slice_start, TNode<Smi> slice_end) {
  // TODO(jgruber): Consider inlining this.
  CSA_DCHECK(this, SmiLessThanOrEqual(slice_start, slice_end));
  TNode<String> slice = CAST(CallBuiltin(Builtin::kSubString, context,
                                         from_string, slice_start, slice_end));
  return CAST(
      CallBuiltin(Builtin::kStringAdd_CheckNone, context, to_string, slice));
}

TNode<String> RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data, TNode<String> replace_string) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  // The replace_string is 'simple' if it doesn't contain a '$' character.
  CSA_SLOW_DCHECK(this,
                  SmiEqual(StringBuiltinsAssembler{state()}.IndexOfDollarChar(
                               context, replace_string),
                           SmiConstant(-1)));

  TNode<Smi> replace_string_length = LoadStringLengthAsSmi(replace_string);

  TVARIABLE(String, var_result, EmptyStringConstant());
  TVARIABLE(Smi, var_last_match_end, SmiConstant(0));

  VariableList merge_vars({&var_result, &var_last_match_end}, zone());
  RegExpExecInternal_Batched(
      context, regexp, subject, data, merge_vars,
      [&](TNode<IntPtrT> num_matches_in_batch) {},
      [&](TNode<RawPtrT> match_offsets, TNode<Int32T> match_start,
          TNode<Int32T> match_end) {
        TNode<Smi> start = SmiFromInt32(match_start);
        TNode<Smi> end = SmiFromInt32(match_end);

        // Append the slice between this and the previous match.
        var_result = AppendStringSlice(context, var_result.value(), subject,
                                       var_last_match_end.value(), start);

        // Append the replace_string.
        {
          Label next(this);
          GotoIf(SmiEqual(replace_string_length, SmiConstant(0)), &next);

          var_result = CAST(CallBuiltin(Builtin::kStringAdd_CheckNone, context,
                                        var_result.value(), replace_string));
          Goto(&next);

          BIND(&next);
        }

        var_last_match_end = end;
      });

  var_result = AppendStringSlice(context, var_result.value(), subject,
                                 var_last_match_end.value(),
                                 LoadStringLengthAsSmi(subject));
  return var_result.value();
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""


```