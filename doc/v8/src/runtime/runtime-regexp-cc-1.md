Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Understanding the Request:**

The request asks for an analysis of the C++ code in `v8/src/runtime/runtime-regexp.cc`, focusing on its functionality, relationship to JavaScript, potential errors, and a summary. Key instructions include noting if it were Torque code (`.tq`), providing JavaScript examples, explaining logic with inputs and outputs, and highlighting common programming errors. The "Part 2 of 3" suggests a larger context.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for recognizable keywords and patterns. Things that immediately jump out are:

* **`RUNTIME_FUNCTION`:** This is a strong indicator of V8 runtime functions, which are C++ implementations of built-in JavaScript functionalities or internal operations.
* **`RegExp`:** The frequent appearance of `RegExp`, `JSRegExp`, `RegExpMatchInfo`, `RegExpData`, etc., clearly points to regular expression processing.
* **`String`:**  Interactions with `String` objects are also prominent, suggesting string manipulation related to regex matching and replacement.
* **`Isolate`:** This is a fundamental V8 concept representing an independent JavaScript execution environment.
* **`HandleScope`:** This is a V8 mechanism for managing object lifetimes.
* **Function names like `RegExpExec`, `RegExpGrowRegExpMatchInfo`, `RegExpBuildIndices`, `RegExpReplace`, `RegExpSplit`:**  These names are quite descriptive and give a high-level overview of the functions' purposes.
* **JavaScript-related terms:**  `global`, `sticky`, `lastIndex`, `groups`, `capture`.

**3. Grouping and Categorizing Functions:**

As I scan, I start mentally grouping the functions based on their names and arguments. This helps organize the analysis:

* **Execution:** `Runtime_RegExpExec`, `Runtime_RegExpExperimentalOneshotExec` - seem to be the core execution functions for regex matching.
* **Match Information:** `Runtime_RegExpGrowRegExpMatchInfo`, `Runtime_RegExpBuildIndices` -  deal with managing and building information about matches.
* **Replacement:** `Runtime_RegExpExecMultiple`, `Runtime_StringReplaceNonGlobalRegExpWithFunction` - appear related to string replacement using regex.
* **Splitting:** `Runtime_RegExpSplit` - likely handles the `String.prototype.split()` method with regex.
* **Internal Helpers:**  The anonymous namespace contains helper classes (`MatchInfoBackedMatch`, `VectorBackedMatch`) that provide an abstraction for accessing match details.

**4. Analyzing Individual Functions:**

Now I dive deeper into each `RUNTIME_FUNCTION`. For each one, I consider:

* **Arguments:** What types of arguments does it take?  This hints at the context in which it's called. `JSRegExp`, `String`, `RegExpMatchInfo` are common.
* **Return Value:** What does it return?  Often it's a `Handle<Object>`, which can be various JavaScript types.
* **Core Logic:** What are the key operations? Are they calling other `RegExp::` methods? Are they manipulating strings? Are they interacting with the V8 heap?
* **JavaScript Connection:** How does this function relate to JavaScript regex features?  For example, `Runtime_RegExpExec` is clearly linked to `RegExp.prototype.exec()` or similar internal calls.

**5. Connecting to JavaScript Examples:**

For each functional area identified, I try to create simple JavaScript examples that would invoke the corresponding C++ runtime function (indirectly). This involves thinking about how JavaScript regex methods work.

* `exec()` example for `Runtime_RegExpExec`.
* String replacement examples for `Runtime_RegExpReplace` and `Runtime_StringReplaceNonGlobalRegExpWithFunction`.
* `split()` example for `Runtime_RegExpSplit`.

**6. Identifying Logic and Input/Output:**

For functions with more involved logic (like `SearchRegExpMultiple`), I consider hypothetical inputs and what the expected output would be. This helps demonstrate the function's behavior.

**7. Spotting Potential Programming Errors:**

Based on the function's purpose and how it interacts with JavaScript, I think about common mistakes developers might make. For example:

* Incorrect use of `lastIndex`.
* Not understanding the difference between global and non-global regex.
* Issues with named capture groups.

**8. Considering Torque:**

The request specifically asks about `.tq` files. While this file isn't, I keep in mind that Torque is used for implementing built-in functions, and this C++ code likely interacts with or is called by Torque-generated code.

**9. Summarization:**

Finally, I synthesize the information gathered into a concise summary of the file's overall purpose. This involves identifying the main themes and the key functionalities it provides.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe some functions are directly exposed to JavaScript.
* **Correction:**  Realize these are *runtime* functions, meaning they are internal implementations called by the engine, not directly by user code.
* **Initial thought:** Focus too much on low-level C++ details.
* **Correction:** Shift focus to the *functionality* and its JavaScript implications.
* **Realization:** The "Part 2 of 3" likely means Part 1 and 3 deal with other aspects of regex implementation (parsing, compilation, bytecode generation, etc.). This helps contextualize the role of the runtime functions.

By following these steps, combining code analysis with an understanding of JavaScript regex features and V8 internals, I can construct a comprehensive answer like the example you provided. The key is to be systematic and to continually relate the C++ code back to its user-facing JavaScript counterparts.
好的，这是对`v8/src/runtime/runtime-regexp.cc`代码片段的功能归纳：

**功能归纳:**

这段代码是 V8 JavaScript 引擎中处理正则表达式运行时操作的核心部分。它包含了多个运行时函数 (以 `RUNTIME_FUNCTION` 宏定义)，这些函数实现了 JavaScript 中 `RegExp` 对象以及字符串相关方法（如 `exec`, `replace`, `split`）的底层逻辑。

**核心功能点：**

1. **正则表达式执行 (`Runtime_RegExpExec`, `Runtime_RegExpExperimentalOneshotExec`):**  负责执行正则表达式的匹配操作。它接收正则表达式对象、目标字符串、起始索引等参数，并返回匹配结果在字符串中的起始位置。`Runtime_RegExpExperimentalOneshotExec` 可能是实验性的单次匹配优化版本。

2. **管理匹配信息 (`Runtime_RegExpGrowRegExpMatchInfo`):**  用于扩展存储正则表达式匹配结果信息的 `RegExpMatchInfo` 对象。这在需要存储更多捕获组信息时使用。

3. **构建索引信息 (`Runtime_RegExpBuildIndices`):**  当正则表达式包含 `d` (indices) 标志时，此函数负责构建包含捕获组起始和结束索引信息的对象。

4. **全局正则表达式多次执行 (`Runtime_RegExpExecMultiple`):**  处理全局正则表达式 (`/g`) 的多次匹配。它会找到所有匹配项，并根据是否包含捕获组，返回匹配的字符串数组或包含匹配项和捕获组信息的数组。

5. **字符串替换 (`Runtime_StringReplaceNonGlobalRegExpWithFunction`):**  实现 `String.prototype.replace()` 方法中，当使用非全局正则表达式并提供替换函数时的逻辑。它会执行一次匹配，然后调用替换函数，并将结果拼接回字符串。

6. **字符串分割 (`Runtime_RegExpSplit`):**  实现 `String.prototype.split()` 方法，使用正则表达式作为分隔符来分割字符串。它会根据正则表达式的匹配位置将字符串分割成子字符串数组。

**与其他部分的关系：**

这段代码依赖于 V8 引擎的其他部分，例如：

* **`v8/src/regexp/regexp.h` 和 `v8/src/regexp/` 下的其他文件:**  提供了正则表达式的核心匹配算法和数据结构。
* **`v8/src/objects/js-regexp.h` 和 `v8/src/objects/objects.h`:** 定义了 `JSRegExp`、`RegExpMatchInfo` 等对象的结构。
* **`v8/src/execution/execution.h`:**  用于执行 JavaScript 函数 (例如在 `replace` 方法中使用回调函数)。

**JavaScript 功能关联与示例:**

* **`Runtime_RegExpExec`:** 对应 `RegExp.prototype.exec()` 方法。

   ```javascript
   const regex = /abc/;
   const str = 'abcdefg';
   const result = regex.exec(str);
   console.log(result.index); // 输出 0
   ```

* **`Runtime_RegExpGrowRegExpMatchInfo`:**  虽然 JavaScript 中没有直接对应的方法，但在内部，当正则表达式有大量捕获组时，V8 可能会调用此函数来扩展存储空间。

* **`Runtime_RegExpBuildIndices`:** 对应正则表达式的 `d` (indices) 标志。

   ```javascript
   const regex = /a(b)c/d;
   const str = 'abcdefg';
   const result = regex.exec(str);
   console.log(result.indices[1]); // 输出 [ 1, 2 ]，表示捕获组 (b) 的起始和结束索引
   ```

* **`Runtime_RegExpExecMultiple`:** 对应全局正则表达式在 `String.prototype.match()` 或 `String.prototype.replace()` 中的行为。

   ```javascript
   const regex = /a[bc]/g;
   const str = 'abc and acd';
   const matches = str.match(regex);
   console.log(matches); // 输出 [ 'ab', 'ac' ]

   const newStr = str.replace(regex, 'X');
   console.log(newStr); // 输出 'X and Xd'
   ```

* **`Runtime_StringReplaceNonGlobalRegExpWithFunction`:** 对应 `String.prototype.replace()` 使用函数作为替换参数，且正则表达式为非全局的情况。

   ```javascript
   const str = 'abc def';
   const newStr = str.replace(/b/, (match, offset, string) => {
       console.log(match, offset, string); // 输出 "b" 1 "abc def"
       return 'B';
   });
   console.log(newStr); // 输出 'aBc def'
   ```

* **`Runtime_RegExpSplit`:** 对应 `String.prototype.split()` 方法。

   ```javascript
   const str = 'a,b,c';
   const parts = str.split(/,/);
   console.log(parts); // 输出 [ 'a', 'b', 'c' ]
   ```

**代码逻辑推理与假设输入/输出:**

以 `Runtime_RegExpExec` 为例：

**假设输入:**

* `regexp`:  一个表示正则表达式 `/w+/` 的 `JSRegExp` 对象。
* `subject`:  字符串 "hello world"。
* `index`:  起始索引 0。
* `result_offsets_vector_length`:  一个足够大的值，例如 4 (对于 `/w+/` 来说，需要存储整个匹配的起始和结束位置)。
* `result_offsets_vector`:  一个预先分配的整数数组。

**预期输出:**

函数会调用底层的 `RegExp::Exec`，如果匹配成功，`result_offsets_vector` 将会填充匹配的起始和结束位置（例如 `[0, 5]`），函数返回匹配的起始索引 `0`。如果匹配失败，函数会抛出异常或返回一个指示失败的值 (根据代码，返回的是一个 `std::optional<int>`，失败时为空)。

**用户常见的编程错误:**

* **忘记设置全局标志 (`/g`) 就期望替换所有匹配项:**  导致 `String.prototype.replace()` 只替换第一个匹配项。

   ```javascript
   const str = 'ababab';
   const newStrWrong = str.replace(/a/, 'X'); // 错误：只替换第一个 'a'
   console.log(newStrWrong); // 输出 'Xbabab'

   const newStrCorrect = str.replace(/a/g, 'X'); // 正确：替换所有 'a'
   console.log(newStrCorrect); // 输出 'XbXbXb'
   ```

* **在 `split()` 中使用可能匹配空字符串的正则表达式:** 可能导致意外的结果，产生大量的空字符串。

   ```javascript
   const str = 'a,b,c';
   const partsWrong = str.split(/,/); // 正常情况

   const str2 = 'a,,c';
   const partsWeird = str2.split(/,/); // 可能产生空字符串
   console.log(partsWeird); // 输出 [ 'a', '', 'c' ]

   const partsEvenWeirder = 'abc'.split(''); // 分割每个字符
   console.log(partsEvenWeirder); // 输出 [ 'a', 'b', 'c' ]
   ```

* **不理解 `lastIndex` 属性的行为:**  对于有状态的正则表达式（例如全局或粘性正则表达式），`lastIndex` 属性会在多次调用 `exec()` 或在 `replace()`/`split()` 中被修改。不理解这一点可能导致循环或匹配失败。

   ```javascript
   const regex = /a/g;
   const str = 'aba';

   console.log(regex.exec(str)); // 输出 [ 'a', index: 0, input: 'aba', groups: undefined ]
   console.log(regex.lastIndex); // 输出 1
   console.log(regex.exec(str)); // 输出 [ 'a', index: 2, input: 'aba', groups: undefined ]
   console.log(regex.lastIndex); // 输出 3
   console.log(regex.exec(str)); // 输出 null (因为 lastIndex 已经超出字符串长度)
   ```

总而言之，`v8/src/runtime/runtime-regexp.cc` 代码片段是 V8 引擎中处理正则表达式相关操作的关键部分，它实现了 JavaScript 中 `RegExp` 对象和字符串方法的底层逻辑，涉及到匹配、替换和分割等核心功能。理解这段代码的功能有助于深入了解 JavaScript 正则表达式的内部工作原理。

### 提示词
```
这是目录为v8/src/runtime/runtime-regexp.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-regexp.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
:STRING_SPLIT_SUBSTRINGS);
    }
  }

  TruncateRegexpIndicesList(isolate);

  return *result;
}

namespace {

std::optional<int> RegExpExec(Isolate* isolate, DirectHandle<JSRegExp> regexp,
                              Handle<String> subject, int32_t index,
                              int32_t* result_offsets_vector,
                              uint32_t result_offsets_vector_length) {
  // Due to the way the JS calls are constructed this must be less than the
  // length of a string, i.e. it is always a Smi.  We check anyway for security.
  CHECK_LE(0, index);
  CHECK_GE(subject->length(), index);
  isolate->counters()->regexp_entry_runtime()->Increment();
  return RegExp::Exec(isolate, regexp, subject, index, result_offsets_vector,
                      result_offsets_vector_length);
}

std::optional<int> ExperimentalOneshotExec(
    Isolate* isolate, DirectHandle<JSRegExp> regexp,
    DirectHandle<String> subject, int32_t index, int32_t* result_offsets_vector,
    uint32_t result_offsets_vector_length) {
  CHECK_GE(result_offsets_vector_length,
           JSRegExp::RegistersForCaptureCount(
               regexp->data(isolate)->capture_count()));
  // Due to the way the JS calls are constructed this must be less than the
  // length of a string, i.e. it is always a Smi.  We check anyway for security.
  CHECK_LE(0, index);
  CHECK_GE(subject->length(), index);
  isolate->counters()->regexp_entry_runtime()->Increment();
  return RegExp::ExperimentalOneshotExec(isolate, regexp, subject, index,
                                         result_offsets_vector,
                                         result_offsets_vector_length);
}

}  // namespace

RUNTIME_FUNCTION(Runtime_RegExpExec) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  Handle<String> subject = args.at<String>(1);
  int32_t index = 0;
  CHECK(Object::ToInt32(args[2], &index));
  uint32_t result_offsets_vector_length = 0;
  CHECK(Object::ToUint32(args[3], &result_offsets_vector_length));

  // This untagged arg must be passed as an implicit arg.
  int32_t* result_offsets_vector = reinterpret_cast<int32_t*>(
      isolate->isolate_data()->regexp_exec_vector_argument());
  DCHECK_NOT_NULL(result_offsets_vector);

  std::optional<int> result =
      RegExpExec(isolate, regexp, subject, index, result_offsets_vector,
                 result_offsets_vector_length);
  DCHECK_EQ(!result, isolate->has_exception());
  if (!result) return ReadOnlyRoots(isolate).exception();
  return Smi::FromInt(result.value());
}

RUNTIME_FUNCTION(Runtime_RegExpGrowRegExpMatchInfo) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<RegExpMatchInfo> match_info = args.at<RegExpMatchInfo>(0);
  int32_t register_count;
  CHECK(Object::ToInt32(args[1], &register_count));

  // We never pass anything besides the global last_match_info.
  DCHECK_EQ(*match_info, *isolate->regexp_last_match_info());

  Handle<RegExpMatchInfo> result = RegExpMatchInfo::ReserveCaptures(
      isolate, match_info, JSRegExp::CaptureCountForRegisters(register_count));
  if (*result != *match_info) {
    isolate->native_context()->set_regexp_last_match_info(*result);
  }

  return *result;
}

RUNTIME_FUNCTION(Runtime_RegExpExperimentalOneshotExec) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  DirectHandle<String> subject = args.at<String>(1);
  int32_t index = 0;
  CHECK(Object::ToInt32(args[2], &index));
  uint32_t result_offsets_vector_length = 0;
  CHECK(Object::ToUint32(args[3], &result_offsets_vector_length));

  // This untagged arg must be passed as an implicit arg.
  int32_t* result_offsets_vector = reinterpret_cast<int32_t*>(
      isolate->isolate_data()->regexp_exec_vector_argument());
  DCHECK_NOT_NULL(result_offsets_vector);

  std::optional<int> result = ExperimentalOneshotExec(
      isolate, regexp, subject, index, result_offsets_vector,
      result_offsets_vector_length);
  DCHECK_EQ(!result, isolate->has_exception());
  if (!result) return ReadOnlyRoots(isolate).exception();
  return Smi::FromInt(result.value());
}

RUNTIME_FUNCTION(Runtime_RegExpBuildIndices) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  DirectHandle<RegExpMatchInfo> match_info = args.at<RegExpMatchInfo>(1);
  Handle<Object> maybe_names = args.at(2);
#ifdef DEBUG
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  DCHECK(regexp->flags() & JSRegExp::kHasIndices);
#endif

  return *JSRegExpResultIndices::BuildIndices(isolate, match_info, maybe_names);
}

namespace {

class MatchInfoBackedMatch : public String::Match {
 public:
  MatchInfoBackedMatch(Isolate* isolate, DirectHandle<JSRegExp> regexp,
                       DirectHandle<RegExpData> regexp_data,
                       Handle<String> subject,
                       Handle<RegExpMatchInfo> match_info)
      : isolate_(isolate), match_info_(match_info) {
    subject_ = String::Flatten(isolate, subject);

    if (RegExpData::TypeSupportsCaptures(regexp_data->type_tag())) {
      DCHECK(Is<IrRegExpData>(*regexp_data));
      Tagged<Object> o = Cast<IrRegExpData>(regexp_data)->capture_name_map();
      has_named_captures_ = IsFixedArray(o);
      if (has_named_captures_) {
        capture_name_map_ = handle(Cast<FixedArray>(o), isolate);
      }
    } else {
      has_named_captures_ = false;
    }
  }

  Handle<String> GetMatch() override {
    return RegExpUtils::GenericCaptureGetter(isolate_, match_info_, 0, nullptr);
  }

  Handle<String> GetPrefix() override {
    const int match_start = match_info_->capture(0);
    return isolate_->factory()->NewSubString(subject_, 0, match_start);
  }

  Handle<String> GetSuffix() override {
    const int match_end = match_info_->capture(1);
    return isolate_->factory()->NewSubString(subject_, match_end,
                                             subject_->length());
  }

  bool HasNamedCaptures() override { return has_named_captures_; }

  int CaptureCount() override {
    return match_info_->number_of_capture_registers() / 2;
  }

  MaybeHandle<String> GetCapture(int i, bool* capture_exists) override {
    Handle<Object> capture_obj = RegExpUtils::GenericCaptureGetter(
        isolate_, match_info_, i, capture_exists);
    return (*capture_exists) ? Object::ToString(isolate_, capture_obj)
                             : isolate_->factory()->empty_string();
  }

  MaybeHandle<String> GetNamedCapture(Handle<String> name,
                                      CaptureState* state) override {
    DCHECK(has_named_captures_);
    int capture_index = 0;
    int capture_name_map_index = 0;
    while (true) {
      capture_index = LookupNamedCapture(
          [=](Tagged<String> capture_name) {
            return capture_name->Equals(*name);
          },
          *capture_name_map_, &capture_name_map_index);
      if (capture_index == -1) {
        *state = UNMATCHED;
        return isolate_->factory()->empty_string();
      }
      if (RegExpUtils::IsMatchedCapture(*match_info_, capture_index)) {
        Handle<String> capture_value;
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate_, capture_value,
            Object::ToString(isolate_,
                             RegExpUtils::GenericCaptureGetter(
                                 isolate_, match_info_, capture_index)));
        *state = MATCHED;
        return capture_value;
      }
    }
  }

 private:
  Isolate* isolate_;
  Handle<String> subject_;
  Handle<RegExpMatchInfo> match_info_;

  bool has_named_captures_;
  Handle<FixedArray> capture_name_map_;
};

class VectorBackedMatch : public String::Match {
 public:
  VectorBackedMatch(Isolate* isolate, Handle<String> subject,
                    Handle<String> match, uint32_t match_position,
                    base::Vector<Handle<Object>> captures,
                    Handle<Object> groups_obj)
      : isolate_(isolate),
        match_(match),
        match_position_(match_position),
        captures_(captures) {
    subject_ = String::Flatten(isolate, subject);

    DCHECK(IsUndefined(*groups_obj, isolate) || IsJSReceiver(*groups_obj));
    has_named_captures_ = !IsUndefined(*groups_obj, isolate);
    if (has_named_captures_) groups_obj_ = Cast<JSReceiver>(groups_obj);
  }

  Handle<String> GetMatch() override { return match_; }

  Handle<String> GetPrefix() override {
    // match_position_ and match_ are user-controlled, hence we manually clamp
    // the index here.
    uint32_t end = std::min(subject_->length(), match_position_);
    return isolate_->factory()->NewSubString(subject_, 0, end);
  }

  Handle<String> GetSuffix() override {
    // match_position_ and match_ are user-controlled, hence we manually clamp
    // the index here.
    uint32_t start =
        std::min(subject_->length(), match_position_ + match_->length());
    return isolate_->factory()->NewSubString(subject_, start,
                                             subject_->length());
  }

  bool HasNamedCaptures() override { return has_named_captures_; }

  int CaptureCount() override { return captures_.length(); }

  MaybeHandle<String> GetCapture(int i, bool* capture_exists) override {
    Handle<Object> capture_obj = captures_[i];
    if (IsUndefined(*capture_obj, isolate_)) {
      *capture_exists = false;
      return isolate_->factory()->empty_string();
    }
    *capture_exists = true;
    return Object::ToString(isolate_, capture_obj);
  }

  MaybeHandle<String> GetNamedCapture(Handle<String> name,
                                      CaptureState* state) override {
    DCHECK(has_named_captures_);

    // Strings representing integer indices are not valid identifiers (and
    // therefore not valid capture names).
    {
      size_t unused;
      if (name->AsIntegerIndex(&unused)) {
        *state = UNMATCHED;
        return isolate_->factory()->empty_string();
      }
    }
    Handle<Object> capture_obj;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate_, capture_obj,
        Object::GetProperty(isolate_, groups_obj_, name));
    if (IsUndefined(*capture_obj, isolate_)) {
      *state = UNMATCHED;
      return isolate_->factory()->empty_string();
    } else {
      *state = MATCHED;
      return Object::ToString(isolate_, capture_obj);
    }
  }

 private:
  Isolate* isolate_;
  Handle<String> subject_;
  Handle<String> match_;
  const uint32_t match_position_;
  base::Vector<Handle<Object>> captures_;

  bool has_named_captures_;
  Handle<JSReceiver> groups_obj_;
};

// Create the groups object (see also the RegExp result creation in
// RegExpBuiltinsAssembler::ConstructNewResultFromMatchInfo).
// TODO(42203211): We cannot simply pass a std::function here, as the closure
// may contain direct handles and they cannot be stored off-stack.
template <typename FunctionType,
          typename = std::enable_if_t<std::is_function_v<Tagged<Object>(int)>>>
Handle<JSObject> ConstructNamedCaptureGroupsObject(
    Isolate* isolate, DirectHandle<FixedArray> capture_map,
    const FunctionType& f_get_capture) {
  Handle<JSObject> groups = isolate->factory()->NewJSObjectWithNullProto();

  const int named_capture_count = capture_map->length() >> 1;
  for (int i = 0; i < named_capture_count; i++) {
    const int name_ix = i * 2;
    const int index_ix = i * 2 + 1;

    Handle<String> capture_name(Cast<String>(capture_map->get(name_ix)),
                                isolate);
    const int capture_ix = Smi::ToInt(capture_map->get(index_ix));
    DCHECK_GE(capture_ix, 1);  // Explicit groups start at index 1.

    Handle<Object> capture_value(f_get_capture(capture_ix), isolate);
    DCHECK(IsUndefined(*capture_value, isolate) || IsString(*capture_value));

    LookupIterator it(isolate, groups, capture_name, groups,
                      LookupIterator::OWN_SKIP_INTERCEPTOR);
    if (it.IsFound()) {
      DCHECK(v8_flags.js_regexp_duplicate_named_groups);
      if (!IsUndefined(*capture_value, isolate)) {
        DCHECK(IsUndefined(*it.GetDataValue(), isolate));
        CHECK(Object::SetDataProperty(&it, capture_value).ToChecked());
      }
    } else {
      CHECK(Object::AddDataProperty(&it, capture_value, NONE,
                                    Just(ShouldThrow::kThrowOnError),
                                    StoreOrigin::kNamed)
                .IsJust());
    }
  }

  return groups;
}

// Only called from Runtime_RegExpExecMultiple so it doesn't need to maintain
// separate last match info.  See comment on that function.
template <bool has_capture>
static Tagged<Object> SearchRegExpMultiple(
    Isolate* isolate, Handle<String> subject, DirectHandle<JSRegExp> regexp,
    DirectHandle<RegExpData> regexp_data,
    Handle<RegExpMatchInfo> last_match_array) {
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DCHECK_NE(has_capture, regexp_data->capture_count() == 0);
  DCHECK_IMPLIES(has_capture, Is<IrRegExpData>(*regexp_data));
  DCHECK(subject->IsFlat());

  // Force tier up to native code for global replaces. The global replace is
  // implemented differently for native code and bytecode execution, where the
  // native code expects an array to store all the matches, and the bytecode
  // matches one at a time, so it's easier to tier-up to native code from the
  // start.
  if (v8_flags.regexp_tier_up &&
      regexp_data->type_tag() == RegExpData::Type::IRREGEXP) {
    Cast<IrRegExpData>(regexp_data)->MarkTierUpForNextExec();
    if (v8_flags.trace_regexp_tier_up) {
      PrintF("Forcing tier-up of JSRegExp object %p in SearchRegExpMultiple\n",
             reinterpret_cast<void*>(regexp->ptr()));
    }
  }

  int capture_count = regexp_data->capture_count();
  int subject_length = subject->length();

  static const int kMinLengthToCache = 0x1000;

  if (subject_length > kMinLengthToCache) {
    Tagged<FixedArray> last_match_cache;
    Tagged<Object> cached_answer = RegExpResultsCache::Lookup(
        isolate->heap(), *subject, regexp_data->wrapper(), &last_match_cache,
        RegExpResultsCache::REGEXP_MULTIPLE_INDICES);
    if (IsFixedArray(cached_answer)) {
      int capture_registers = JSRegExp::RegistersForCaptureCount(capture_count);
      std::unique_ptr<int32_t[]> last_match(new int32_t[capture_registers]);
      int32_t* raw_last_match = last_match.get();
      for (int i = 0; i < capture_registers; i++) {
        raw_last_match[i] = Smi::ToInt(last_match_cache->get(i));
      }
      DirectHandle<FixedArray> cached_fixed_array(
          Cast<FixedArray>(cached_answer), isolate);
      // The cache FixedArray is a COW-array and we need to return a copy.
      DirectHandle<FixedArray> copied_fixed_array =
          isolate->factory()->CopyFixedArrayWithMap(
              cached_fixed_array, isolate->factory()->fixed_array_map());
      RegExp::SetLastMatchInfo(isolate, last_match_array, subject,
                               capture_count, raw_last_match);
      return *copied_fixed_array;
    }
  }

  RegExpGlobalExecRunner runner(handle(*regexp_data, isolate), subject,
                                isolate);
  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  FixedArrayBuilder builder = FixedArrayBuilder::Lazy(isolate);

  // Position to search from.
  int match_start = -1;
  int match_end = 0;
  bool first = true;

  // Two smis before and after the match, for very long strings.
  static const int kMaxBuilderEntriesPerRegExpMatch = 5;

  while (true) {
    int32_t* current_match = runner.FetchNext();
    if (current_match == nullptr) break;
    match_start = current_match[0];
    builder.EnsureCapacity(isolate, kMaxBuilderEntriesPerRegExpMatch);
    if (match_end < match_start) {
      ReplacementStringBuilder::AddSubjectSlice(&builder, match_end,
                                                match_start);
    }
    match_end = current_match[1];
    {
      // Avoid accumulating new handles inside loop.
      HandleScope temp_scope(isolate);
      DirectHandle<String> match;
      if (!first) {
        match = isolate->factory()->NewProperSubString(subject, match_start,
                                                       match_end);
      } else {
        match =
            isolate->factory()->NewSubString(subject, match_start, match_end);
        first = false;
      }

      if (has_capture) {
        // Arguments array to replace function is match, captures, index and
        // subject, i.e., 3 + capture count in total. If the RegExp contains
        // named captures, they are also passed as the last argument.

        // has_capture can only be true for IrRegExp.
        Tagged<IrRegExpData> re_data = Cast<IrRegExpData>(*regexp_data);
        Handle<Object> maybe_capture_map(re_data->capture_name_map(), isolate);
        const bool has_named_captures = IsFixedArray(*maybe_capture_map);

        const int argc =
            has_named_captures ? 4 + capture_count : 3 + capture_count;

        DirectHandle<FixedArray> elements =
            isolate->factory()->NewFixedArray(argc);
        int cursor = 0;

        elements->set(cursor++, *match);
        for (int i = 1; i <= capture_count; i++) {
          int start = current_match[i * 2];
          if (start >= 0) {
            int end = current_match[i * 2 + 1];
            DCHECK(start <= end);
            DirectHandle<String> substring =
                isolate->factory()->NewSubString(subject, start, end);
            elements->set(cursor++, *substring);
          } else {
            DCHECK_GT(0, current_match[i * 2 + 1]);
            elements->set(cursor++, ReadOnlyRoots(isolate).undefined_value());
          }
        }

        elements->set(cursor++, Smi::FromInt(match_start));
        elements->set(cursor++, *subject);

        if (has_named_captures) {
          Handle<FixedArray> capture_map = Cast<FixedArray>(maybe_capture_map);
          DirectHandle<JSObject> groups = ConstructNamedCaptureGroupsObject(
              isolate, capture_map, [=](int ix) { return elements->get(ix); });
          elements->set(cursor++, *groups);
        }

        DCHECK_EQ(cursor, argc);
        builder.Add(*isolate->factory()->NewJSArrayWithElements(elements));
      } else {
        builder.Add(*match);
      }
    }
  }

  if (runner.HasException()) return ReadOnlyRoots(isolate).exception();

  if (match_start >= 0) {
    // Finished matching, with at least one match.
    if (match_end < subject_length) {
      ReplacementStringBuilder::AddSubjectSlice(&builder, match_end,
                                                subject_length);
    }

    RegExp::SetLastMatchInfo(isolate, last_match_array, subject, capture_count,
                             runner.LastSuccessfulMatch());

    if (subject_length > kMinLengthToCache) {
      // Store the last successful match into the array for caching.
      int capture_registers = JSRegExp::RegistersForCaptureCount(capture_count);
      DirectHandle<FixedArray> last_match_cache =
          isolate->factory()->NewFixedArray(capture_registers);
      int32_t* last_match = runner.LastSuccessfulMatch();
      for (int i = 0; i < capture_registers; i++) {
        last_match_cache->set(i, Smi::FromInt(last_match[i]));
      }
      DirectHandle<FixedArray> result_fixed_array =
          FixedArray::RightTrimOrEmpty(
              isolate, indirect_handle(builder.array(), isolate),
              builder.length());
      // Cache the result and copy the FixedArray into a COW array.
      DirectHandle<FixedArray> copied_fixed_array =
          isolate->factory()->CopyFixedArrayWithMap(
              result_fixed_array, isolate->factory()->fixed_array_map());
      RegExpResultsCache::Enter(
          isolate, subject, handle(regexp->data(isolate)->wrapper(), isolate),
          copied_fixed_array, last_match_cache,
          RegExpResultsCache::REGEXP_MULTIPLE_INDICES);
    }
    return *builder.array();
  } else {
    return ReadOnlyRoots(isolate).null_value();  // No matches at all.
  }
}

// Legacy implementation of RegExp.prototype[Symbol.replace] which
// doesn't properly call the underlying exec method.
V8_WARN_UNUSED_RESULT MaybeHandle<String> RegExpReplace(
    Isolate* isolate, Handle<JSRegExp> regexp, Handle<String> string,
    Handle<String> replace) {
  // Functional fast-paths are dispatched directly by replace builtin.
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));

  Factory* factory = isolate->factory();

  const int flags = regexp->flags();
  const bool global = (flags & JSRegExp::kGlobal) != 0;
  const bool sticky = (flags & JSRegExp::kSticky) != 0;

  replace = String::Flatten(isolate, replace);

  Handle<RegExpMatchInfo> last_match_info = isolate->regexp_last_match_info();
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);

  if (!global) {
    // Non-global regexp search, string replace.

    uint32_t last_index = 0;
    if (sticky) {
      Handle<Object> last_index_obj(regexp->last_index(), isolate);
      ASSIGN_RETURN_ON_EXCEPTION(isolate, last_index_obj,
                                 Object::ToLength(isolate, last_index_obj));
      last_index = PositiveNumberToUint32(*last_index_obj);
    }

    Handle<Object> match_indices_obj(ReadOnlyRoots(isolate).null_value(),
                                     isolate);

    // A lastIndex exceeding the string length always returns null (signalling
    // failure) in RegExpBuiltinExec, thus we can skip the call.
    if (last_index <= static_cast<uint32_t>(string->length())) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, match_indices_obj,
          RegExp::Exec_Single(isolate, regexp, string, last_index,
                              last_match_info));
    }

    if (IsNull(*match_indices_obj, isolate)) {
      if (sticky) regexp->set_last_index(Smi::zero(), SKIP_WRITE_BARRIER);
      return string;
    }

    auto match_indices = Cast<RegExpMatchInfo>(match_indices_obj);

    const int start_index = match_indices->capture(0);
    const int end_index = match_indices->capture(1);

    if (sticky) {
      regexp->set_last_index(Smi::FromInt(end_index), SKIP_WRITE_BARRIER);
    }

    IncrementalStringBuilder builder(isolate);
    builder.AppendString(factory->NewSubString(string, 0, start_index));

    if (replace->length() > 0) {
      MatchInfoBackedMatch m(isolate, regexp, data, string, match_indices);
      Handle<String> replacement;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, replacement,
                                 String::GetSubstitution(isolate, &m, replace));
      builder.AppendString(replacement);
    }

    builder.AppendString(
        factory->NewSubString(string, end_index, string->length()));
    return indirect_handle(builder.Finish(), isolate);
  } else {
    // Global regexp search, string replace.
    DCHECK(global);
    RETURN_ON_EXCEPTION(isolate, RegExpUtils::SetLastIndex(isolate, regexp, 0));

    // Force tier up to native code for global replaces. The global replace is
    // implemented differently for native code and bytecode execution, where the
    // native code expects an array to store all the matches, and the bytecode
    // matches one at a time, so it's easier to tier-up to native code from the
    // start.
    if (v8_flags.regexp_tier_up &&
        data->type_tag() == RegExpData::Type::IRREGEXP) {
      Cast<IrRegExpData>(data)->MarkTierUpForNextExec();
      if (v8_flags.trace_regexp_tier_up) {
        PrintF("Forcing tier-up of JSRegExp object %p in RegExpReplace\n",
               reinterpret_cast<void*>(regexp->ptr()));
      }
    }

    if (replace->length() == 0) {
      if (string->IsOneByteRepresentation()) {
        Tagged<Object> result =
            StringReplaceGlobalRegExpWithEmptyString<SeqOneByteString>(
                isolate, string, regexp, data, last_match_info);
        return handle(Cast<String>(result), isolate);
      } else {
        Tagged<Object> result =
            StringReplaceGlobalRegExpWithEmptyString<SeqTwoByteString>(
                isolate, string, regexp, data, last_match_info);
        return handle(Cast<String>(result), isolate);
      }
    }

    Tagged<Object> result = StringReplaceGlobalRegExpWithString(
        isolate, string, regexp, data, replace, last_match_info);
    if (IsString(result)) {
      return handle(Cast<String>(result), isolate);
    } else {
      return MaybeHandle<String>();
    }
  }

  UNREACHABLE();
}

}  // namespace

// This is only called for StringReplaceGlobalRegExpWithFunction.
RUNTIME_FUNCTION(Runtime_RegExpExecMultiple) {
  HandleScope handles(isolate);
  DCHECK_EQ(3, args.length());

  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  Handle<String> subject = args.at<String>(1);
  Handle<RegExpMatchInfo> last_match_info = args.at<RegExpMatchInfo>(2);

  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DirectHandle<RegExpData> regexp_data =
      direct_handle(regexp->data(isolate), isolate);

  subject = String::Flatten(isolate, subject);
  CHECK(regexp->flags() & JSRegExp::kGlobal);

  Tagged<Object> result;
  if (regexp_data->capture_count() == 0) {
    result = SearchRegExpMultiple<false>(isolate, subject, regexp, regexp_data,
                                         last_match_info);
  } else {
    result = SearchRegExpMultiple<true>(isolate, subject, regexp, regexp_data,
                                        last_match_info);
  }
  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  return result;
}

RUNTIME_FUNCTION(Runtime_StringReplaceNonGlobalRegExpWithFunction) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> subject = args.at<String>(0);
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(1);
  Handle<JSReceiver> replace_obj = args.at<JSReceiver>(2);

  DCHECK(RegExpUtils::IsUnmodifiedRegExp(isolate, regexp));
  DCHECK(replace_obj->map()->is_callable());

  Factory* factory = isolate->factory();
  Handle<RegExpMatchInfo> last_match_info = isolate->regexp_last_match_info();
  DirectHandle<RegExpData> data = direct_handle(regexp->data(isolate), isolate);

  const int flags = regexp->flags();
  DCHECK_EQ(flags & JSRegExp::kGlobal, 0);

  // TODO(jgruber): This should be an easy port to CSA with massive payback.

  const bool sticky = (flags & JSRegExp::kSticky) != 0;
  uint32_t last_index = 0;
  if (sticky) {
    Handle<Object> last_index_obj(regexp->last_index(), isolate);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, last_index_obj, Object::ToLength(isolate, last_index_obj));
    last_index = PositiveNumberToUint32(*last_index_obj);
  }

  Handle<Object> match_indices_obj(ReadOnlyRoots(isolate).null_value(),
                                   isolate);

  // A lastIndex exceeding the string length always returns null (signalling
  // failure) in RegExpBuiltinExec, thus we can skip the call.
  if (last_index <= static_cast<uint32_t>(subject->length())) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, match_indices_obj,
        RegExp::Exec_Single(isolate, regexp, subject, last_index,
                            last_match_info));
  }

  if (IsNull(*match_indices_obj, isolate)) {
    if (sticky) regexp->set_last_index(Smi::zero(), SKIP_WRITE_BARRIER);
    return *subject;
  }

  auto match_indices = Cast<RegExpMatchInfo>(match_indices_obj);

  const int index = match_indices->capture(0);
  const int end_of_match = match_indices->capture(1);

  if (sticky) {
    regexp->set_last_index(Smi::FromInt(end_of_match), SKIP_WRITE_BARRIER);
  }

  IncrementalStringBuilder builder(isolate);
  builder.AppendString(factory->NewSubString(subject, 0, index));

  // Compute the parameter list consisting of the match, captures, index,
  // and subject for the replace function invocation. If the RegExp contains
  // named captures, they are also passed as the last argument.

  // The number of captures plus one for the match.
  const int m = match_indices->number_of_capture_registers() / 2;

  bool has_named_captures = false;
  DirectHandle<FixedArray> capture_map;
  if (m > 1) {
    SBXCHECK(Is<IrRegExpData>(*data));

    Tagged<Object> maybe_capture_map =
        Cast<IrRegExpData>(data)->capture_name_map();
    if (IsFixedArray(maybe_capture_map)) {
      has_named_captures = true;
      capture_map = direct_handle(Cast<FixedArray>(maybe_capture_map), isolate);
    }
  }

  const uint32_t argc = GetArgcForReplaceCallable(m, has_named_captures);
  if (argc == static_cast<uint32_t>(-1)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kTooManyArguments));
  }
  // TODO(42203211): This vector ends up in InvokeParams which is potentially
  // used by generated code. It will be replaced, when generated code starts
  // using direct handles.
  base::ScopedVector<IndirectHandle<Object>> argv(argc);

  int cursor = 0;
  for (int j = 0; j < m; j++) {
    bool ok;
    Handle<String> capture =
        RegExpUtils::GenericCaptureGetter(isolate, match_indices, j, &ok);
    if (ok) {
      argv[cursor++] = capture;
    } else {
      argv[cursor++] = factory->undefined_value();
    }
  }

  argv[cursor++] = handle(Smi::FromInt(index), isolate);
  argv[cursor++] = subject;

  if (has_named_captures) {
    argv[cursor++] = ConstructNamedCaptureGroupsObject(
        isolate, capture_map, [&argv](int ix) { return *argv[ix]; });
  }

  DCHECK_EQ(cursor, argc);

  Handle<Object> replacement_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, replacement_obj,
      Execution::Call(isolate, replace_obj, factory->undefined_value(), argc,
                      argv.begin()));

  Handle<String> replacement;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, replacement, Object::ToString(isolate, replacement_obj));

  builder.AppendString(replacement);
  builder.AppendString(
      factory->NewSubString(subject, end_of_match, subject->length()));

  RETURN_RESULT_OR_FAILURE(isolate, builder.Finish());
}

namespace {

V8_WARN_UNUSED_RESULT MaybeHandle<Object> ToUint32(Isolate* isolate,
                                                   Handle<Object> object,
                                                   uint32_t* out) {
  if (IsUndefined(*object, isolate)) {
    *out = kMaxUInt32;
    return object;
  }

  Handle<Object> number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, number,
                             Object::ToNumber(isolate, object));
  *out = NumberToUint32(*number);
  return object;
}

Handle<JSArray> NewJSArrayWithElements(Isolate* isolate,
                                       Handle<FixedArray> elems,
                                       int num_elems) {
  return isolate->factory()->NewJSArrayWithElements(
      FixedArray::RightTrimOrEmpty(isolate, elems, num_elems));
}

}  // namespace

// Slow path for:
// ES#sec-regexp.prototype-@@replace
// RegExp.prototype [ @@split ] ( string, limit )
RUNTIME_FUNCTION(Runtime_RegExpSplit) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<JSReceiver> recv = args.at<JSReceiver>(0);
  Handle<String> string = args.at<String>(1);
  Handle<Object> limit_obj = args.at(2);

  Factory* factory = isolate->factory();

  Handle<JSFunction> regexp_fun = isolate->regexp_function();
  Handle<Object> ctor;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, ctor, Object::SpeciesConstructor(isolate, recv, regexp_fun));

  Handle<Object> flags_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, flags_obj,
      JSObject::GetProperty(isolate, recv, factory->flags_string()));

  Handle<String> flags;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, flags,
                                     Object::ToString(isolate, flags_obj));

  Handle<String> u_str = factory->LookupSingleCharacterStringFromCode('u');
  const bool unicode = (String::IndexOf(isolate, flags, u_str, 0) >= 0);

  Handle<String> y_str = factory->LookupSingleCharacterStringFromCode('y');
  const bool sticky = (String::IndexOf(isolate, flags, y_str, 0) >= 0);

  Handle<String> new_flags = flags;
  if (!sticky) {
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_flags,
                                       factory->NewConsString(flags, y_str));
  }

  Handle<JSReceiver> splitter;
  {
    constexpr int argc = 2;
    std::array<Handle<Object>, argc> argv = {recv, new_flags};

    Handle<Object> splitter_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, splitter_obj,
        Execution::New(isolate, ctor, argc, argv.data()));

    splitter = Cast<JSReceiver>(splitter_obj);
  }

  uint32_t limit;
  RETURN_FAILURE_ON_EXCEPTION(isolate, ToUint32(isolate, limit_obj, &limit));

  const uint32_t length = string->length();

  if (limit == 0) return *factory->NewJSArray(0);

  if (length == 0) {
    Handle<Object> result;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        is
```