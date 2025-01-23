Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part 2 of a larger file. I also need to explain its relation to JavaScript using examples if applicable.

Based on the code, I can see several functions related to regular expression execution:

- `RegExpBuiltinsAssembler::RegExpMatch` (from part 1, but related) seems to be handling the `String.prototype.match` method.
- The current part focuses on functions like `RegExpBuiltinsAssembler::RegExpSplit`, `RegExpBuiltinsAssembler::RegExpExecInternal_Batched`, `RegExpBuiltinsAssembler::RegExpMatchGlobal`, and `RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString`. These names strongly suggest they are implementations for JavaScript's `String.prototype.split`, internal batch execution of regex, `String.prototype.matchAll` (or a similar global match), and a simple version of `String.prototype.replace` respectively.

Let's break down the functionality of each function in this part:

- **`RegExpBuiltinsAssembler::RegExpSplit`**: This function appears to implement the logic for the `split()` method on strings using regular expressions as delimiters. It handles different scenarios, including empty strings, limits on the number of splits, and capturing groups in the regex.

- **`RegExpBuiltinsAssembler::RegExpExecInternal_Batched`**: This seems to be an internal helper function for efficiently executing global regular expressions. It processes matches in batches, likely to optimize performance when there are many matches.

- **`RegExpBuiltinsAssembler::RegExpMatchGlobal`**: This function seems to implement the behavior of `String.prototype.match` when called with a global regular expression. It collects all the matching substrings and returns them in an array.

- **`RegExpBuiltinsAssembler::AppendStringSlice`**: This is a helper function for appending a slice of a string to another string.

- **`RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString`**: This function implements a simplified version of the `String.prototype.replace` method when the replacement string doesn't contain any special replacement patterns (like `$1`, `$2`, etc.).

Now, I'll provide JavaScript examples to illustrate the connection for some of these functions.
这是 C++ 源代码文件 `v8/src/builtins/builtins-regexp-gen.cc` 的第二部分，主要负责实现与 JavaScript 正则表达式相关的内置函数，特别是涉及到全局匹配和字符串分割、替换等操作的底层逻辑。

以下是这部分代码的主要功能归纳：

1. **`RegExpBuiltinsAssembler::RegExpSplit`**:  实现了 `String.prototype.split()` 方法的逻辑，当使用正则表达式作为分隔符时会调用此函数。它负责在输入字符串中查找正则表达式的匹配项，并使用这些匹配项作为分隔符将字符串分割成一个字符串数组。该函数还处理了 `split()` 方法的可选 `limit` 参数，用于限制返回数组的最大长度，并处理了正则表达式中捕获组的情况，会将捕获到的子串也包含在返回的数组中。

2. **`RegExpBuiltinsAssembler::RegExpExecInternal_Batched`**: 这是一个内部的辅助函数，用于批量执行全局正则表达式的匹配。它被用于 `String.prototype.matchAll()` 和 `String.prototype.replace()` 等需要多次匹配的场景。该函数的核心思想是，在一个批次中执行多次匹配，并将匹配结果存储在一个预先分配的缓冲区中，然后对这些匹配结果进行统一处理，从而提高效率。

3. **`RegExpBuiltinsAssembler::RegExpMatchGlobal`**:  实现了 `String.prototype.match()` 方法在正则表达式带有 `g` (global) 标志时的行为。它会找出字符串中所有匹配正则表达式的子串，并将这些子串放入一个数组中返回。如果未找到匹配项，则返回 `null`。

4. **`RegExpBuiltinsAssembler::AppendStringSlice`**: 这是一个简单的辅助函数，用于将源字符串的一部分（切片）追加到目标字符串的末尾。

5. **`RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString`**:  实现了 `String.prototype.replace()` 方法的一个优化版本，专门处理替换字符串不包含特殊替换模式（如 `$1`, `$2` 等）的情况。当替换字符串是简单的静态字符串时，此函数能更高效地完成全局替换操作。

**与 JavaScript 功能的关联和示例：**

* **`RegExpBuiltinsAssembler::RegExpSplit` 与 `String.prototype.split()`:**

   ```javascript
   const str = 'a,b,c,d';
   const regex = /,/;
   const result = str.split(regex);
   console.log(result); // 输出: [ 'a', 'b', 'c', 'd' ]

   const strWithCapture = 'abc123def456';
   const regexWithCapture = /([a-z]+)(\d+)/g;
   const resultWithCapture = strWithCapture.split(regexWithCapture);
   console.log(resultWithCapture); // 输出: [ '', 'abc', '123', 'def', '456', '' ]

   const limitedSplit = '1-2-3-4-5';
   const limitRegex = /-/;
   const limitedResult = limitedSplit.split(limitRegex, 3);
   console.log(limitedResult); // 输出: [ '1', '2', '3' ]
   ```
   `RegExpBuiltinsAssembler::RegExpSplit` 负责实现上述 `split()` 方法在底层查找分隔符并生成数组的逻辑。

* **`RegExpBuiltinsAssembler::RegExpExecInternal_Batched` 和 `RegExpBuiltinsAssembler::RegExpMatchGlobal` 与 `String.prototype.match()` (global):**

   ```javascript
   const str = 'color car cool code';
   const regex = /coo[l|r]/g;
   const matches = str.match(regex);
   console.log(matches); // 输出: [ 'color', 'cool' ]
   ```
   当 `match()` 方法的正则表达式带有 `g` 标志时，`RegExpBuiltinsAssembler::RegExpMatchGlobal` 和其内部使用的 `RegExpExecInternal_Batched` 协同工作，查找所有匹配的 "color" 或 "cool" 并返回一个包含它们的数组。

* **`RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString` 与 `String.prototype.replace()` (global, simple replacement):**

   ```javascript
   const str = 'apple banana apple orange';
   const regex = /apple/g;
   const newStr = str.replace(regex, 'grape');
   console.log(newStr); // 输出: grape banana grape orange
   ```
   如果替换的字符串 'grape' 不包含像 `$1` 这样的特殊模式，`RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString` 会被调用来高效地执行全局替换。

总而言之，这部分 C++ 代码是 V8 引擎中实现 JavaScript 正则表达式相关功能的关键组成部分，它直接关联并支撑着 JavaScript 中 `String.prototype.split()`, `String.prototype.match()` (在全局匹配情况下) 和 `String.prototype.replace()` (在简单替换场景下) 等方法的运行。它通过底层的 C++ 代码实现了高效的正则表达式匹配和字符串操作。

### 提示词
```
这是目录为v8/src/builtins/builtins-regexp-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
```