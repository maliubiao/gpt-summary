Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a functional summary of the C++ code and a JavaScript example illustrating its connection to JavaScript functionality.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for keywords and recognizable patterns. Keywords like "cache," "compilation," "script," "eval," "RegExp," "lookup," "put," "key," "hash," "SharedFunctionInfo," "FeedbackCell," "Context," etc., jump out. These suggest the code is about caching compiled code for various JavaScript constructs.

3. **Identify Core Data Structures:**  Notice the presence of classes like `EvalCacheKey`, `RegExpKey`, `CodeKey`, `ScriptCacheKey`. These clearly represent different types of keys used for caching. The class `CompilationCacheTable` itself is the central data structure for holding the cached information.

4. **Focus on Key Operations:**  Look for functions with names like `LookupScript`, `LookupEval`, `LookupRegExp`, `PutScript`, `PutEval`, `PutRegExp`, `RemoveEntry`. These are the primary actions the code performs: looking up and storing compiled code.

5. **Analyze Each Key Type:**
    * **`ScriptCacheKey`:** Pay attention to `MatchesScript`. It compares various script properties (source, name, line/column offsets, origin options, wrapped arguments, host-defined options). This indicates caching is based on script identity.
    * **`EvalCacheKey`:**  Note the components: source, shared function info, language mode, and position. This suggests caching compiled `eval()` or dynamically created function code, taking into account the context of the call.
    * **`RegExpKey`:**  Simple: source and flags. Caching regular expression compilation.
    * **`CodeKey`:**  Based on `SharedFunctionInfo`. Likely caching compiled functions directly.

6. **Understand the `CompilationCacheTable` Structure:**  The code mentions `WeakFixedArray` and `FixedArray`. The `kLiteral...` constants and related functions (`SearchLiteralsMapEntry`, `AddToFeedbackCellsMap`, `SearchLiteralsMap`) suggest a secondary caching mechanism for feedback related to `eval`.

7. **Infer the High-Level Functionality:** Based on the above points, the core functionality is caching compiled JavaScript code to improve performance by avoiding redundant compilation. Different types of code (scripts, eval, regexps) have different keying mechanisms.

8. **Connect to JavaScript:**  Now, think about how these C++ concepts map to JavaScript features.
    * **Scripts:**  Directly correspond to `<script>` tags or loaded JavaScript files.
    * **`eval()` and `Function()`:** These are the direct triggers for the `EvalCacheKey`.
    * **Regular Expressions:**  The `RegExp` object in JavaScript.
    * **Functions:**  The fundamental building blocks of JavaScript. While `CodeKey` isn't explicitly demonstrated in the example, it represents a more general caching of compiled functions.

9. **Construct JavaScript Examples:**  Choose simple, clear examples that demonstrate the C++ code's purpose.
    * **Scripts:** Show how the same script loaded multiple times might benefit from caching.
    * **`eval()`:** Demonstrate how `eval()` with the same source and in the same context can reuse cached compilation. Highlight the importance of context.
    * **Regular Expressions:** Show how creating the same regular expression multiple times can be optimized.

10. **Refine the Summary:**  Write a concise summary that captures the main points. Use clear language, avoid excessive technical jargon, and focus on the "why" and "what" of the code. Mention the benefits of caching (performance).

11. **Review and Iterate:**  Read through the summary and examples to ensure they are accurate, clear, and address the original request. Make sure the connection between the C++ code and JavaScript is explicit. For instance, initially, I might have focused too much on the internal data structures (`WeakFixedArray`). The review process would highlight the need to explain *why* these structures are used (caching) and *what* they are caching (compiled code for JavaScript features). Also, ensuring the JavaScript examples are correct and illustrative is crucial. For example, initially, I might have just shown `eval("1+1")` once. But showing it executed multiple times makes the caching benefit clearer.

This iterative process of scanning, analyzing, connecting, and refining leads to a comprehensive understanding and a well-structured answer.
这个C++源代码文件 `compilation-cache-table.cc` 实现了 V8 引擎中用于**缓存已编译的 JavaScript 代码**的功能，以提高性能。它维护着一个哈希表，用于存储不同类型的已编译代码，并能在后续执行中重用这些代码，避免重复编译。

**主要功能归纳:**

1. **缓存不同类型的已编译代码:**
   - **脚本 (Scripts):**  缓存整个脚本的编译结果。
   - **Eval 代码 (Eval Code):** 缓存 `eval()` 函数或者 `Function()` 构造函数动态生成的代码。
   - **正则表达式 (Regular Expressions):** 缓存正则表达式的编译结果。
   - **已编译的函数 (Compiled Functions - 通过 `CodeKey`):**  虽然代码中没有直接看到 `PutCode` 这样的函数，但 `CodeKey` 的存在表明可以基于 `SharedFunctionInfo` 来缓存已编译的函数。

2. **提供查找 (Lookup) 功能:** 针对不同类型的代码，提供了相应的查找函数 (`LookupScript`, `LookupEval`, `LookupRegExp`)，根据提供的键 (key) 来检索已缓存的编译结果。

3. **提供存储 (Put) 功能:**  提供了将编译结果存储到缓存中的函数 (`PutScript`, `PutEval`, `PutRegExp`)。

4. **使用不同的键 (Keys) 来区分缓存条目:**
   - **`ScriptCacheKey`:**  脚本的源字符串、脚本名称、行列偏移、来源选项、宿主定义选项以及包裹参数等信息。
   - **`EvalCacheKey`:**  `eval()` 或 `Function()` 的源代码字符串、包含该调用的函数的 `SharedFunctionInfo`、语言模式以及调用位置。
   - **`RegExpKey`:**  正则表达式的源字符串和标志 (flags)。
   - **`CodeKey`:**  函数的 `SharedFunctionInfo`。

5. **处理缓存的生命周期:**  代码中包含一些处理缓存容量和条目删除的逻辑 (`EnsureScriptTableCapacity`, `RemoveEntry`)。

6. **处理 `eval` 的特殊性:**  对于 `eval` 代码，除了缓存编译后的 `SharedFunctionInfo`，还维护了一个辅助的映射表 (`SearchLiteralsMap`, `AddToFeedbackCellsMap`) 来存储与特定上下文相关的 `FeedbackCell` 信息。这允许在不同的上下文中重用相同的 `eval` 代码。

**与 JavaScript 的功能关系及 JavaScript 示例:**

此文件直接影响 JavaScript 代码的执行性能。当 JavaScript 引擎需要编译一段代码时，它会首先检查编译缓存中是否存在该代码的已编译版本。如果存在，则直接使用缓存的版本，避免了耗时的重新编译过程。

**JavaScript 示例:**

**1. 缓存脚本 (Scripts):**

```javascript
// 假设这是在一个 HTML 文件中或者通过 Node.js 执行

// 第一次加载脚本，需要编译
console.time("First load");
// ... 一些 JavaScript 代码 ...
console.timeEnd("First load");

// 第二次加载相同的脚本 (例如刷新页面或者重新执行)，可能直接从缓存中加载
console.time("Second load");
// ... 完全相同的 JavaScript 代码 ...
console.timeEnd("Second load");
```

在 V8 引擎中，`CompilationCacheTable::LookupScript` 和 `CompilationCacheTable::PutScript` 就负责处理这种情况。当引擎首次遇到该脚本时，会编译它并将其结果存储在缓存中。当再次遇到相同的脚本时，`LookupScript` 会找到缓存的编译结果，从而跳过编译阶段。

**2. 缓存 `eval` 代码 (Eval Code):**

```javascript
function testEval() {
  let x = 10;
  console.time("First eval");
  eval("x = x + 5;");
  console.timeEnd("First eval");
  console.log(x); // 输出 15

  console.time("Second eval");
  eval("x = x + 5;");
  console.timeEnd("Second eval");
  console.log(x); // 输出 20
}

testEval();
```

在 V8 引擎中，当第一次执行 `eval("x = x + 5;")` 时，`CompilationCacheTable::LookupEval` 可能找不到缓存，引擎会编译该代码，并使用 `CompilationCacheTable::PutEval` 将编译结果（包括 `SharedFunctionInfo` 和相关的 `FeedbackCell`）存储起来。当第二次执行相同的 `eval` 调用时，`LookupEval` 可能会在相同的上下文中找到缓存的编译结果，从而加速执行。`EvalCacheKey` 会确保只有在相同的源代码、调用上下文和语言模式下，缓存才能被命中。

**3. 缓存正则表达式 (Regular Expressions):**

```javascript
console.time("First RegExp");
const regex1 = new RegExp("ab+c");
console.timeEnd("First RegExp");
regex1.test("abbc");

console.time("Second RegExp");
const regex2 = new RegExp("ab+c");
console.timeEnd("Second RegExp");
regex2.test("abbc");
```

当第一次创建 `new RegExp("ab+c")` 时，V8 引擎会编译该正则表达式，并通过 `CompilationCacheTable::PutRegExp` 将编译结果存储起来。后续创建相同的正则表达式时，`CompilationCacheTable::LookupRegExp` 可以找到缓存的结果，避免重复编译。

**总结:**

`v8/src/objects/compilation-cache-table.cc` 文件是 V8 引擎中一个关键的性能优化组件。它通过缓存已编译的 JavaScript 代码，显著提高了代码的执行效率，尤其是在重复执行相同代码片段的情况下（例如页面刷新、循环执行、多次调用相同的 `eval` 或创建相同的正则表达式）。它使用不同的键来区分缓存条目，并针对 `eval` 代码进行了特殊的上下文处理。 理解这个文件的功能有助于深入了解 V8 引擎的内部工作原理以及 JavaScript 的性能优化。

Prompt: 
```
这是目录为v8/src/objects/compilation-cache-table.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/compilation-cache-table.h"

#include "src/codegen/script-details.h"
#include "src/common/assert-scope.h"
#include "src/objects/compilation-cache-table-inl.h"

namespace v8 {
namespace internal {

namespace {

const int kLiteralEntryLength = 2;
const int kLiteralInitialLength = 2;
const int kLiteralContextOffset = 0;
const int kLiteralLiteralsOffset = 1;

int SearchLiteralsMapEntry(Tagged<CompilationCacheTable> cache,
                           InternalIndex cache_entry,
                           Tagged<Context> native_context) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsNativeContext(native_context));
  Tagged<Object> obj = cache->EvalFeedbackValueAt(cache_entry);

  // Check that there's no confusion between FixedArray and WeakFixedArray (the
  // object used to be a FixedArray here).
  DCHECK(!IsFixedArray(obj));
  if (IsWeakFixedArray(obj)) {
    Tagged<WeakFixedArray> literals_map = Cast<WeakFixedArray>(obj);
    int length = literals_map->length();
    for (int i = 0; i < length; i += kLiteralEntryLength) {
      DCHECK(literals_map->get(i + kLiteralContextOffset).IsWeakOrCleared());
      if (literals_map->get(i + kLiteralContextOffset) ==
          MakeWeak(native_context)) {
        return i;
      }
    }
  }
  return -1;
}

void AddToFeedbackCellsMap(DirectHandle<CompilationCacheTable> cache,
                           InternalIndex cache_entry,
                           DirectHandle<Context> native_context,
                           DirectHandle<FeedbackCell> feedback_cell) {
  Isolate* isolate = native_context->GetIsolate();
  DCHECK(IsNativeContext(*native_context));
  static_assert(kLiteralEntryLength == 2);
  DirectHandle<WeakFixedArray> new_literals_map;
  int entry;

  Tagged<Object> obj = cache->EvalFeedbackValueAt(cache_entry);

  // Check that there's no confusion between FixedArray and WeakFixedArray (the
  // object used to be a FixedArray here).
  DCHECK(!IsFixedArray(obj));
  if (!IsWeakFixedArray(obj) || Cast<WeakFixedArray>(obj)->length() == 0) {
    new_literals_map = isolate->factory()->NewWeakFixedArray(
        kLiteralInitialLength, AllocationType::kOld);
    entry = 0;
  } else {
    DirectHandle<WeakFixedArray> old_literals_map(Cast<WeakFixedArray>(obj),
                                                  isolate);
    entry = SearchLiteralsMapEntry(*cache, cache_entry, *native_context);
    if (entry >= 0) {
      // Just set the code of the entry.
      old_literals_map->set(entry + kLiteralLiteralsOffset,
                            MakeWeak(*feedback_cell));
      return;
    }

    // Can we reuse an entry?
    DCHECK_LT(entry, 0);
    int length = old_literals_map->length();
    for (int i = 0; i < length; i += kLiteralEntryLength) {
      if (old_literals_map->get(i + kLiteralContextOffset).IsCleared()) {
        new_literals_map = old_literals_map;
        entry = i;
        break;
      }
    }

    if (entry < 0) {
      // Copy old optimized code map and append one new entry.
      new_literals_map = isolate->factory()->CopyWeakFixedArrayAndGrow(
          old_literals_map, kLiteralEntryLength);
      entry = old_literals_map->length();
    }
  }

  new_literals_map->set(entry + kLiteralContextOffset,
                        MakeWeak(*native_context));
  new_literals_map->set(entry + kLiteralLiteralsOffset,
                        MakeWeak(*feedback_cell));

#ifdef DEBUG
  for (int i = 0; i < new_literals_map->length(); i += kLiteralEntryLength) {
    Tagged<MaybeObject> object =
        new_literals_map->get(i + kLiteralContextOffset);
    DCHECK(object.IsCleared() ||
           IsNativeContext(object.GetHeapObjectAssumeWeak()));
    object = new_literals_map->get(i + kLiteralLiteralsOffset);
    DCHECK(object.IsCleared() ||
           IsFeedbackCell(object.GetHeapObjectAssumeWeak()));
  }
#endif

  Tagged<Object> old_literals_map = cache->EvalFeedbackValueAt(cache_entry);
  if (old_literals_map != *new_literals_map) {
    cache->SetEvalFeedbackValueAt(cache_entry, *new_literals_map);
  }
}

Tagged<FeedbackCell> SearchLiteralsMap(Tagged<CompilationCacheTable> cache,
                                       InternalIndex cache_entry,
                                       Tagged<Context> native_context) {
  Tagged<FeedbackCell> result;
  int entry = SearchLiteralsMapEntry(cache, cache_entry, native_context);
  if (entry >= 0) {
    Tagged<WeakFixedArray> literals_map =
        Cast<WeakFixedArray>(cache->EvalFeedbackValueAt(cache_entry));
    DCHECK_LE(entry + kLiteralEntryLength, literals_map->length());
    Tagged<MaybeObject> object =
        literals_map->get(entry + kLiteralLiteralsOffset);

    if (!object.IsCleared()) {
      result = Cast<FeedbackCell>(object.GetHeapObjectAssumeWeak());
    }
  }
  DCHECK(result.is_null() || IsFeedbackCell(result));
  return result;
}

// EvalCacheKeys are used as keys in the eval cache.
class EvalCacheKey : public HashTableKey {
 public:
  // This tuple unambiguously identifies calls to eval() or
  // CreateDynamicFunction() (such as through the Function() constructor).
  // * source is the string passed into eval(). For dynamic functions, this is
  //   the effective source for the function, some of which is implicitly
  //   generated.
  // * shared is the shared function info for the function containing the call
  //   to eval(). for dynamic functions, shared is the native context closure.
  // * When positive, position is the position in the source where eval is
  //   called. When negative, position is the negation of the position in the
  //   dynamic function's effective source where the ')' ends the parameters.
  EvalCacheKey(Handle<String> source, Handle<SharedFunctionInfo> shared,
               LanguageMode language_mode, int position)
      : HashTableKey(CompilationCacheShape::EvalHash(*source, *shared,
                                                     language_mode, position)),
        source_(source),
        shared_(shared),
        language_mode_(language_mode),
        position_(position) {}

  bool IsMatch(Tagged<Object> other) override {
    DisallowGarbageCollection no_gc;
    if (!IsFixedArray(other)) {
      DCHECK(IsNumber(other));
      uint32_t other_hash = static_cast<uint32_t>(Object::NumberValue(other));
      return Hash() == other_hash;
    }
    Tagged<FixedArray> other_array = Cast<FixedArray>(other);
    DCHECK(IsSharedFunctionInfo(other_array->get(0)));
    if (*shared_ != other_array->get(0)) return false;
    int language_unchecked = Smi::ToInt(other_array->get(2));
    DCHECK(is_valid_language_mode(language_unchecked));
    LanguageMode language_mode = static_cast<LanguageMode>(language_unchecked);
    if (language_mode != language_mode_) return false;
    int position = Smi::ToInt(other_array->get(3));
    if (position != position_) return false;
    Tagged<String> source = Cast<String>(other_array->get(1));
    return source->Equals(*source_);
  }

  Handle<Object> AsHandle(Isolate* isolate) {
    Handle<FixedArray> array = isolate->factory()->NewFixedArray(4);
    array->set(0, *shared_);
    array->set(1, *source_);
    array->set(2, Smi::FromEnum(language_mode_));
    array->set(3, Smi::FromInt(position_));
    array->set_map(isolate, ReadOnlyRoots(isolate).fixed_cow_array_map());
    return array;
  }

 private:
  Handle<String> source_;
  Handle<SharedFunctionInfo> shared_;
  LanguageMode language_mode_;
  int position_;
};

// RegExpKey carries the source and flags of a regular expression as key.
class RegExpKey : public HashTableKey {
 public:
  RegExpKey(Isolate* isolate, Handle<String> string, JSRegExp::Flags flags)
      : HashTableKey(
            CompilationCacheShape::RegExpHash(*string, Smi::FromInt(flags))),
        isolate_(isolate),
        string_(string),
        flags_(flags) {}

  // Rather than storing the key in the hash table, a pointer to the
  // stored value is stored where the key should be.  IsMatch then
  // compares the search key to the found object, rather than comparing
  // a key to a key.
  // TODO(pthier): Loading the data via TrustedPointerTable on every key check
  // is not great.
  bool IsMatch(Tagged<Object> obj) override {
    Tagged<RegExpData> val = Cast<RegExpDataWrapper>(obj)->data(isolate_);
    return string_->Equals(val->source()) && (flags_ == val->flags());
  }

  Isolate* isolate_;
  Handle<String> string_;
  JSRegExp::Flags flags_;
};

// CodeKey carries the SharedFunctionInfo key associated with a
// Code object value.
class CodeKey : public HashTableKey {
 public:
  explicit CodeKey(Handle<SharedFunctionInfo> key)
      : HashTableKey(key->Hash()), key_(key) {}

  bool IsMatch(Tagged<Object> string) override { return *key_ == string; }

  Handle<SharedFunctionInfo> key_;
};

Tagged<Smi> ScriptHash(Tagged<String> source, MaybeHandle<Object> maybe_name,
                       int line_offset, int column_offset,
                       v8::ScriptOriginOptions origin_options,
                       Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  size_t hash = base::hash_combine(source->EnsureHash());
  if (Handle<Object> name;
      maybe_name.ToHandle(&name) && IsString(*name, isolate)) {
    hash =
        base::hash_combine(hash, Cast<String>(*name)->EnsureHash(), line_offset,
                           column_offset, origin_options.Flags());
  }
  // The upper bits of the hash are discarded so that the value fits in a Smi.
  return Smi::From31BitPattern(static_cast<int>(hash & (~(1u << 31))));
}

}  // namespace

// We only re-use a cached function for some script source code if the
// script originates from the same place. This is to avoid issues
// when reporting errors, etc.
bool ScriptCacheKey::MatchesScript(Tagged<Script> script) {
  DisallowGarbageCollection no_gc;

  // If the script name isn't set, the boilerplate script should have
  // an undefined name to have the same origin.
  Handle<Object> name;
  if (!name_.ToHandle(&name)) {
    return IsUndefined(script->name(), isolate_);
  }
  // Do the fast bailout checks first.
  if (line_offset_ != script->line_offset()) return false;
  if (column_offset_ != script->column_offset()) return false;
  // Check that both names are strings. If not, no match.
  if (!IsString(*name, isolate_) || !IsString(script->name(), isolate_))
    return false;
  // Are the origin_options same?
  if (origin_options_.Flags() != script->origin_options().Flags()) {
    return false;
  }
  // Compare the two name strings for equality.
  if (!Cast<String>(*name)->Equals(Cast<String>(script->name()))) {
    return false;
  }

  Handle<FixedArray> wrapped_arguments_handle;
  if (wrapped_arguments_.ToHandle(&wrapped_arguments_handle)) {
    if (!script->is_wrapped()) {
      return false;
    }
    Tagged<FixedArray> wrapped_arguments = *wrapped_arguments_handle;
    Tagged<FixedArray> other_wrapped_arguments = script->wrapped_arguments();
    int length = wrapped_arguments->length();
    if (length != other_wrapped_arguments->length()) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      Tagged<Object> arg = wrapped_arguments->get(i);
      Tagged<Object> other_arg = other_wrapped_arguments->get(i);
      DCHECK(IsString(arg));
      DCHECK(IsString(other_arg));
      if (!Cast<String>(arg)->Equals(Cast<String>(other_arg))) {
        return false;
      }
    }
  } else if (script->is_wrapped()) {
    return false;
  }

  // Don't compare host options if the script was deserialized because we didn't
  // serialize host options (see CodeSerializer::SerializeObjectImpl())
  if (script->deserialized() &&
      script->host_defined_options() ==
          ReadOnlyRoots(isolate_).empty_fixed_array()) {
    return true;
  }
  // TODO(cbruni, chromium:1244145): Remove once migrated to the context
  Handle<Object> maybe_host_defined_options;
  if (!host_defined_options_.ToHandle(&maybe_host_defined_options)) {
    maybe_host_defined_options = isolate_->factory()->empty_fixed_array();
  }
  Tagged<FixedArray> host_defined_options =
      Cast<FixedArray>(*maybe_host_defined_options);
  Tagged<FixedArray> script_options =
      Cast<FixedArray>(script->host_defined_options());
  int length = host_defined_options->length();
  if (length != script_options->length()) return false;

  for (int i = 0; i < length; i++) {
    // host-defined options is a v8::PrimitiveArray.
    DCHECK(IsPrimitive(host_defined_options->get(i)));
    DCHECK(IsPrimitive(script_options->get(i)));
    if (!Object::StrictEquals(host_defined_options->get(i),
                              script_options->get(i))) {
      return false;
    }
  }
  return true;
}

ScriptCacheKey::ScriptCacheKey(Handle<String> source,
                               const ScriptDetails* script_details,
                               Isolate* isolate)
    : ScriptCacheKey(source, script_details->name_obj,
                     script_details->line_offset, script_details->column_offset,
                     script_details->origin_options,
                     script_details->host_defined_options,
                     script_details->wrapped_arguments, isolate) {}

ScriptCacheKey::ScriptCacheKey(Handle<String> source, MaybeHandle<Object> name,
                               int line_offset, int column_offset,
                               v8::ScriptOriginOptions origin_options,
                               MaybeHandle<Object> host_defined_options,
                               MaybeHandle<FixedArray> maybe_wrapped_arguments,
                               Isolate* isolate)
    : HashTableKey(static_cast<uint32_t>(ScriptHash(*source, name, line_offset,
                                                    column_offset,
                                                    origin_options, isolate)
                                             .value())),
      source_(source),
      name_(name),
      line_offset_(line_offset),
      column_offset_(column_offset),
      origin_options_(origin_options),
      host_defined_options_(host_defined_options),
      wrapped_arguments_(maybe_wrapped_arguments),
      isolate_(isolate) {
  DCHECK(Smi::IsValid(static_cast<int>(Hash())));
#ifdef DEBUG
  Handle<FixedArray> wrapped_arguments;
  if (maybe_wrapped_arguments.ToHandle(&wrapped_arguments)) {
    int length = wrapped_arguments->length();
    for (int i = 0; i < length; i++) {
      Tagged<Object> arg = wrapped_arguments->get(i);
      DCHECK(IsString(arg));
    }
  }
#endif
}

bool ScriptCacheKey::IsMatch(Tagged<Object> other) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsWeakFixedArray(other));
  Tagged<WeakFixedArray> other_array = Cast<WeakFixedArray>(other);
  DCHECK_EQ(other_array->length(), kEnd);

  // A hash check can quickly reject many non-matches, even though this step
  // isn't strictly necessary.
  uint32_t other_hash =
      static_cast<uint32_t>(other_array->get(kHash).ToSmi().value());
  if (other_hash != Hash()) return false;

  Tagged<HeapObject> other_script_object;
  if (!other_array->get(kWeakScript)
           .GetHeapObjectIfWeak(&other_script_object)) {
    return false;
  }
  Tagged<Script> other_script = Cast<Script>(other_script_object);
  Tagged<String> other_source = Cast<String>(other_script->source());

  return other_source->Equals(*source_) && MatchesScript(other_script);
}

Handle<Object> ScriptCacheKey::AsHandle(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  Handle<WeakFixedArray> array = isolate->factory()->NewWeakFixedArray(kEnd);
  // Any SharedFunctionInfo being stored in the script cache should have a
  // Script.
  DCHECK(IsScript(shared->script()));
  array->set(kHash, Smi::FromInt(static_cast<int>(Hash())));
  array->set(kWeakScript, MakeWeak(shared->script()));
  return array;
}

CompilationCacheScriptLookupResult::RawObjects
CompilationCacheScriptLookupResult::GetRawObjects() const {
  RawObjects result;
  if (Handle<Script> script; script_.ToHandle(&script)) {
    result.first = *script;
  }
  if (Handle<SharedFunctionInfo> toplevel_sfi;
      toplevel_sfi_.ToHandle(&toplevel_sfi)) {
    result.second = *toplevel_sfi;
  }
  return result;
}

CompilationCacheScriptLookupResult
CompilationCacheScriptLookupResult::FromRawObjects(
    CompilationCacheScriptLookupResult::RawObjects raw, Isolate* isolate) {
  CompilationCacheScriptLookupResult result;
  if (!raw.first.is_null()) {
    result.script_ = handle(raw.first, isolate);
  }
  if (!raw.second.is_null()) {
    result.is_compiled_scope_ = raw.second->is_compiled_scope(isolate);
    if (result.is_compiled_scope_.is_compiled()) {
      result.toplevel_sfi_ = handle(raw.second, isolate);
    }
  }
  return result;
}

CompilationCacheScriptLookupResult CompilationCacheTable::LookupScript(
    DirectHandle<CompilationCacheTable> table, Handle<String> src,
    const ScriptDetails& script_details, Isolate* isolate) {
  src = String::Flatten(isolate, src);
  ScriptCacheKey key(src, &script_details, isolate);
  InternalIndex entry = table->FindEntry(isolate, &key);
  if (entry.is_not_found()) return {};

  DisallowGarbageCollection no_gc;
  Tagged<Object> key_in_table = table->KeyAt(entry);
  Tagged<Script> script = Cast<Script>(Cast<WeakFixedArray>(key_in_table)
                                           ->get(ScriptCacheKey::kWeakScript)
                                           .GetHeapObjectAssumeWeak());

  Tagged<Object> obj = table->PrimaryValueAt(entry);
  Tagged<SharedFunctionInfo> toplevel_sfi;
  if (!IsUndefined(obj, isolate)) {
    toplevel_sfi = Cast<SharedFunctionInfo>(obj);
    DCHECK_EQ(toplevel_sfi->script(), script);
  }

  return CompilationCacheScriptLookupResult::FromRawObjects(
      std::make_pair(script, toplevel_sfi), isolate);
}

InfoCellPair CompilationCacheTable::LookupEval(
    DirectHandle<CompilationCacheTable> table, Handle<String> src,
    Handle<SharedFunctionInfo> outer_info,
    DirectHandle<NativeContext> native_context, LanguageMode language_mode,
    int position) {
  InfoCellPair empty_result;
  Isolate* isolate = native_context->GetIsolate();
  src = String::Flatten(isolate, src);

  EvalCacheKey key(src, outer_info, language_mode, position);
  InternalIndex entry = table->FindEntry(isolate, &key);
  if (entry.is_not_found()) return empty_result;

  if (!IsFixedArray(table->KeyAt(entry))) return empty_result;
  Tagged<Object> obj = table->PrimaryValueAt(entry);
  if (!IsSharedFunctionInfo(obj)) return empty_result;

  static_assert(CompilationCacheShape::kEntrySize == 3);
  Tagged<FeedbackCell> feedback_cell =
      SearchLiteralsMap(*table, entry, *native_context);
  return InfoCellPair(isolate, Cast<SharedFunctionInfo>(obj), feedback_cell);
}

Handle<Object> CompilationCacheTable::LookupRegExp(Handle<String> src,
                                                   JSRegExp::Flags flags) {
  Isolate* isolate = GetIsolate();
  DisallowGarbageCollection no_gc;
  RegExpKey key(isolate, src, flags);
  InternalIndex entry = FindEntry(isolate, &key);
  if (entry.is_not_found()) return isolate->factory()->undefined_value();
  return Handle<Object>(PrimaryValueAt(entry), isolate);
}

Handle<CompilationCacheTable> CompilationCacheTable::EnsureScriptTableCapacity(
    Isolate* isolate, Handle<CompilationCacheTable> cache) {
  if (cache->HasSufficientCapacityToAdd(1)) return cache;

  // Before resizing, delete are any entries whose keys contain cleared weak
  // pointers.
  {
    DisallowGarbageCollection no_gc;
    for (InternalIndex entry : cache->IterateEntries()) {
      Tagged<Object> key;
      if (!cache->ToKey(isolate, entry, &key)) continue;
      if (Cast<WeakFixedArray>(key)
              ->get(ScriptCacheKey::kWeakScript)
              .IsCleared()) {
        DCHECK(IsUndefined(cache->PrimaryValueAt(entry)));
        cache->RemoveEntry(entry);
      }
    }
  }

  return EnsureCapacity(isolate, cache);
}

Handle<CompilationCacheTable> CompilationCacheTable::PutScript(
    Handle<CompilationCacheTable> cache, Handle<String> src,
    MaybeHandle<FixedArray> maybe_wrapped_arguments,
    DirectHandle<SharedFunctionInfo> value, Isolate* isolate) {
  src = String::Flatten(isolate, src);
  DirectHandle<Script> script(Cast<Script>(value->script()), isolate);
  MaybeHandle<Object> script_name;
  if (IsString(script->name(), isolate)) {
    script_name = handle(script->name(), isolate);
  }
  Handle<FixedArray> host_defined_options(script->host_defined_options(),
                                          isolate);
  ScriptCacheKey key(src, script_name, script->line_offset(),
                     script->column_offset(), script->origin_options(),
                     host_defined_options, maybe_wrapped_arguments, isolate);
  DirectHandle<Object> k = key.AsHandle(isolate, value);

  // Check whether there is already a matching entry. If so, we must overwrite
  // it. This allows an entry whose value is undefined to upgrade to contain a
  // SharedFunctionInfo.
  InternalIndex entry = cache->FindEntry(isolate, &key);
  bool found_existing = entry.is_found();
  if (!found_existing) {
    cache = EnsureScriptTableCapacity(isolate, cache);
    entry = cache->FindInsertionEntry(isolate, key.Hash());
  }
  // We might be tempted to DCHECK here that the Script in the existing entry
  // matches the Script in the new key. However, replacing an existing Script
  // can still happen in some edge cases that aren't common enough to be worth
  // fixing. Consider the following unlikely sequence of events:
  // 1. BackgroundMergeTask::SetUpOnMainThread finds a script S1 in the cache.
  // 2. DevTools is attached and clears the cache.
  // 3. DevTools is detached; the cache is reenabled.
  // 4. A new instance of the script, S2, is compiled and placed into the cache.
  // 5. The merge from step 1 finishes on the main thread, still using S1, and
  //    places S1 into the cache, replacing S2.
  cache->SetKeyAt(entry, *k);
  cache->SetPrimaryValueAt(entry, *value);
  if (!found_existing) {
    cache->ElementAdded();
  }
  return cache;
}

Handle<CompilationCacheTable> CompilationCacheTable::PutEval(
    Handle<CompilationCacheTable> cache, Handle<String> src,
    Handle<SharedFunctionInfo> outer_info,
    DirectHandle<SharedFunctionInfo> value,
    DirectHandle<NativeContext> native_context,
    DirectHandle<FeedbackCell> feedback_cell, int position) {
  Isolate* isolate = native_context->GetIsolate();
  src = String::Flatten(isolate, src);
  EvalCacheKey key(src, outer_info, value->language_mode(), position);

  // This block handles 'real' insertions, i.e. the initial dummy insert
  // (below) has already happened earlier.
  {
    DirectHandle<Object> k = key.AsHandle(isolate);
    InternalIndex entry = cache->FindEntry(isolate, &key);
    if (entry.is_found()) {
      cache->SetKeyAt(entry, *k);
      if (cache->PrimaryValueAt(entry) != *value) {
        cache->SetPrimaryValueAt(entry, *value);
        // The SFI is changing because the code was aged. Nuke existing feedback
        // since it can't be reused after this point.
        cache->SetEvalFeedbackValueAt(entry,
                                      ReadOnlyRoots(isolate).the_hole_value());
      }
      // AddToFeedbackCellsMap may allocate a new sub-array to live in the
      // entry, but it won't change the cache array. Therefore EntryToIndex
      // and entry remains correct.
      AddToFeedbackCellsMap(cache, entry, native_context, feedback_cell);
      // Add hash again even on cache hit to avoid unnecessary cache delay in
      // case of hash collisions.
    }
  }

  // Create a dummy entry to mark that this key has already been inserted once.
  cache = EnsureCapacity(isolate, cache);
  InternalIndex entry = cache->FindInsertionEntry(isolate, key.Hash());
  DirectHandle<Object> k =
      isolate->factory()->NewNumber(static_cast<double>(key.Hash()));
  cache->SetKeyAt(entry, *k);
  cache->SetPrimaryValueAt(entry, Smi::FromInt(kHashGenerations));
  cache->ElementAdded();
  return cache;
}

Handle<CompilationCacheTable> CompilationCacheTable::PutRegExp(
    Isolate* isolate, Handle<CompilationCacheTable> cache, Handle<String> src,
    JSRegExp::Flags flags, DirectHandle<RegExpData> value) {
  RegExpKey key(isolate, src, flags);
  cache = EnsureCapacity(isolate, cache);
  InternalIndex entry = cache->FindInsertionEntry(isolate, key.Hash());
  // We store the value in the key slot, and compare the search key
  // to the stored value with a custom IsMatch function during lookups.
  cache->SetKeyAt(entry, value->wrapper());
  cache->SetPrimaryValueAt(entry, value->wrapper());
  cache->ElementAdded();
  return cache;
}

void CompilationCacheTable::Remove(Tagged<Object> value) {
  DisallowGarbageCollection no_gc;
  for (InternalIndex entry : IterateEntries()) {
    if (PrimaryValueAt(entry) == value) {
      RemoveEntry(entry);
    }
  }
}

void CompilationCacheTable::RemoveEntry(InternalIndex entry) {
  int entry_index = EntryToIndex(entry);
  Tagged<Object> the_hole_value = GetReadOnlyRoots().the_hole_value();
  for (int i = 0; i < kEntrySize; i++) {
    this->set(entry_index + i, the_hole_value, SKIP_WRITE_BARRIER);
  }
  ElementRemoved();

  // This table does not shrink upon deletion. The script cache depends on that
  // fact, because EnsureScriptTableCapacity calls RemoveEntry at a time when
  // shrinking the table would be counterproductive.
}

}  // namespace internal
}  // namespace v8

"""

```