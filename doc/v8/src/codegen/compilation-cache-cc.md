Response:
Let's break down the thought process for analyzing the `compilation-cache.cc` file.

1. **Identify the Core Purpose:** The name "compilation-cache" immediately suggests its primary function: to store and retrieve previously compiled code to avoid redundant compilation. This improves performance by reusing compiled code.

2. **Examine the Class Structure:**  The code defines a `CompilationCache` class and several nested helper classes (`CompilationCacheScript`, `CompilationCacheEval`, `CompilationCacheRegExp`, `CompilationCacheEvalOrScript`). This structure implies different caching strategies or data structures for different types of compilations (scripts, eval code, regular expressions).

3. **Analyze Member Variables:**
    * `isolate_`:  This is a fundamental V8 concept. It confirms the class operates within a specific V8 isolate (a sandboxed instance of the engine).
    * `script_`, `eval_global_`, `eval_contextual_`, `reg_exp_`: These members, being instances of the nested classes, strongly reinforce the idea of separate caches for scripts, global `eval`, contextual `eval`, and regular expressions.
    * `enabled_script_and_eval_`: This boolean flag suggests the possibility of enabling/disabling caching for scripts and eval.

4. **Investigate Key Methods:**  Focus on methods that seem crucial for cache operations:
    * `Lookup*`: Methods like `LookupScript`, `LookupEval`, `LookupRegExp` clearly handle retrieving compiled code from the cache. They take source code and potentially other contextual information as input.
    * `Put*`:  Methods like `PutScript`, `PutEval`, `PutRegExp` are responsible for adding compiled code to the cache.
    * `Clear`: This method likely clears all entries from the cache.
    * `Age`: This is an interesting method. The name suggests a mechanism for managing the lifetime of cached entries, potentially removing older or less frequently used entries.
    * `Remove`: This method allows for the removal of specific compiled code entries.
    * `Iterate`:  This method hints at the possibility of iterating over the contents of the cache, likely for debugging or garbage collection purposes.
    * `EnableScriptAndEval`, `DisableScriptAndEval`: These methods control the overall caching behavior.

5. **Delve into Nested Classes:**  Examine the specific functionalities of `CompilationCacheScript`, `CompilationCacheEval`, and `CompilationCacheRegExp`. Notice how each has its own `GetTable`, `Lookup`, and `Put` methods, tailored to the type of code being cached. The `CompilationCacheTable` type mentioned suggests an underlying data structure (likely a hash table) for storing the cached items. The different `Age` implementations in these classes reveal distinct aging strategies.

6. **Look for Connections to JavaScript:**
    * **Scripts:**  Directly related to `<script>` tags or loading JavaScript files.
    * **`eval()`:** The `CompilationCacheEval` class makes the connection to the `eval()` function in JavaScript.
    * **Regular Expressions:** The `CompilationCacheRegExp` class clearly handles caching for regular expression compilation.

7. **Identify Potential Logic and Data Flow:** Trace the flow of information in `Lookup` and `Put` methods. Notice how keys (like source code) and values (like `SharedFunctionInfo` or `RegExpData`) are involved. The `Lookup` methods check for existing entries, and the `Put` methods add new ones.

8. **Consider Edge Cases and Error Scenarios:** Think about what could go wrong:
    * **Cache misses:**  The requested compiled code is not in the cache.
    * **Outdated cache entries:** Compiled code might become invalid due to changes in the environment or dependencies. The `Age` method addresses this.
    * **Memory management:**  The cache needs to be managed to avoid excessive memory consumption.

9. **Connect to Common Programming Errors:** Relate the cache's function to common JavaScript development issues:
    * **Slow page load times:**  Caching helps mitigate this.
    * **Performance issues with `eval()`:** Caching can improve `eval()` performance, although excessive use of `eval()` is generally discouraged.
    * **Regular expression performance:** Caching can significantly speed up repeated use of the same regular expressions.

10. **Formulate Hypotheses for Input/Output and Examples:** Based on the understanding of the code, create simple scenarios to illustrate the cache's behavior. For example, compiling and running the same function twice should result in a cache hit on the second execution.

11. **Refine and Structure the Answer:** Organize the findings into logical sections (functionality, Torque, JavaScript examples, logic, common errors). Use clear and concise language.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Perhaps all compilation types share the same cache.
* **Correction:** The nested classes and separate `Lookup`/`Put` methods clearly indicate separate caches for scripts, eval, and regexes.

* **Initial thought:** The `Age` method simply removes entries randomly.
* **Correction:**  Closer inspection reveals different aging strategies (e.g., checking for flushed bytecode in `CompilationCacheScript`, decrementing a counter in `CompilationCacheEval`).

By following this thought process, systematically examining the code, and connecting it to JavaScript concepts, we can arrive at a comprehensive understanding of the `compilation-cache.cc` file's functionality.
This C++ source file, `v8/src/codegen/compilation-cache.cc`, implements the **compilation cache** for the V8 JavaScript engine. Its main function is to **store and reuse the results of compiling JavaScript code** (scripts, eval code, and regular expressions) to avoid redundant compilation and improve performance.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Caching Compiled Code:**  The primary purpose is to store compiled code artifacts (like `SharedFunctionInfo` for scripts and eval, and `RegExpData` for regular expressions) along with the source code and relevant context information.

2. **Lookup:** It provides mechanisms to efficiently look up previously compiled code based on the source code and context.

3. **Storage Management:** It manages different caches for different types of compiled code:
    * **Scripts:**  Caches compiled top-level scripts.
    * **Eval (Global & Contextual):**  Caches code compiled via the `eval()` function. It distinguishes between global eval (evaluated in the global scope) and contextual eval (evaluated within a function's scope).
    * **Regular Expressions:** Caches compiled regular expressions.

4. **Cache Invalidation and Aging:** It includes mechanisms to invalidate or age out stale or less relevant cached entries:
    * **Bytecode Flushing:**  For scripts and eval, entries are removed when the underlying bytecode has been flushed (e.g., due to memory pressure).
    * **Generational Aging (Regular Expressions):**  Uses multiple generations of caches for regular expressions. Less recently used regexps are moved to older generations and eventually discarded.
    * **Explicit Clearing:** Provides methods to clear the entire cache.

5. **Performance Counters:**  Tracks cache hits and misses to monitor the effectiveness of the compilation cache.

6. **Enabling/Disabling:**  Allows for enabling or disabling the compilation cache.

**Regarding the `.tq` extension:**

The comment explicitly states:

> If v8/src/codegen/compilation-cache.cc以.tq结尾，那它是个v8 torque源代码

**Therefore, since `v8/src/codegen/compilation-cache.cc` ends with `.cc`, it is a standard C++ source file, not a V8 Torque source file.** Torque files typically have the `.tq` extension.

**Relationship with JavaScript and Examples:**

The compilation cache directly impacts the performance of JavaScript execution. Here are examples illustrating how it works:

**1. Caching Scripts:**

```javascript
// First execution of this script: compilation occurs, and the result is cached.
function myFunction() {
  console.log("Hello from myFunction");
}
myFunction();

// Subsequent executions of the same script (or if the function is called again later):
// The engine can potentially retrieve the compiled code from the cache,
// skipping the compilation step.
myFunction();
```

**2. Caching `eval()`:**

```javascript
// First execution of eval with this string: compilation happens, result cached.
eval("console.log('Evaluated code');");

// Subsequent execution of the same eval string in a similar context:
// The cached compiled code can be reused.
eval("console.log('Evaluated code');");
```

**3. Caching Regular Expressions:**

```javascript
// First use of this regex: compilation occurs, and the compiled RegExpData is cached.
const regex = /abc/g;
"abcadef".match(regex);

// Subsequent uses of the same regular expression:
// The engine can reuse the cached compiled RegExpData.
"xyzabcghi".match(regex);
```

**Code Logic Reasoning with Hypothetical Input and Output:**

**Scenario: Script Compilation and Caching**

**Input:**

* `source`:  A JavaScript string: `"function add(a, b) { return a + b; } add(5, 3);"`
* `script_details`: Information about the script (e.g., name, line offset).
* The compilation cache is initially empty for scripts.

**Process:**

1. `CompilationCache::LookupScript()` is called with the `source` and `script_details`.
2. The script cache (`script_`) is checked. Since it's empty, a **cache miss** occurs.
3. The source code is compiled, generating `SharedFunctionInfo` for the `add` function and potentially for the top-level code.
4. `CompilationCache::PutScript()` is called, storing the `source` and the generated `SharedFunctionInfo` in the script cache.

**Output (After First Execution):**

* The script cache now contains an entry associated with the given `source` and `script_details`, pointing to the compiled `SharedFunctionInfo`.
* The function `add(5, 3)` will execute and return `8`.

**Input (Second Execution):**

* The same `source` and `script_details` are used.

**Process:**

1. `CompilationCache::LookupScript()` is called.
2. The script cache is checked. This time, a **cache hit** occurs, and the previously compiled `SharedFunctionInfo` is retrieved.
3. Compilation is skipped.

**Output (After Second Execution):**

* The function `add(5, 3)` will execute using the cached compiled code, potentially faster than the first execution.

**User-Visible Programming Errors and How the Cache Relates:**

The compilation cache itself doesn't directly cause user-visible programming *errors* in the sense of syntax or runtime errors. However, understanding its behavior can help debug performance issues and understand unexpected behavior in certain scenarios.

**Example of a potential misconception:**

* **Scenario:** A user modifies a script but forgets to reload the page or clear the browser cache in a web development context.

* **Problem:** The browser might still be using the older, cached version of the compiled script. This can lead to confusion if the changes are not reflected.

* **How the cache is involved:** The browser's JavaScript engine likely has its own compilation cache (similar in principle to V8's).

**Example related to `eval()`:**

* **Common Error:** Using `eval()` with dynamically generated strings can lead to performance bottlenecks because the engine might not be able to effectively cache the compiled code.

```javascript
function executeCode(input) {
  // If 'input' changes frequently, the compiled code for each 'eval' call
  // might not be cacheable or the cache might be less effective.
  eval(input);
}

executeCode("console.log('Dynamic code 1');");
executeCode("console.log('Dynamic code 2');");
executeCode("console.log('Dynamic code 1');"); // Might get a cache hit, but depends on the engine's heuristics.
```

**Key Takeaways:**

* `v8/src/codegen/compilation-cache.cc` is a core component of V8 for optimizing JavaScript execution speed.
* It caches compiled code for scripts, `eval()`, and regular expressions.
* Understanding its functionality helps in comprehending how V8 manages and reuses compiled code.
* While not directly causing programming errors, its behavior can influence performance and should be considered in certain development scenarios (especially with `eval()` and dynamic code generation).

### 提示词
```
这是目录为v8/src/codegen/compilation-cache.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compilation-cache.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/compilation-cache.h"

#include "src/common/globals.h"
#include "src/heap/factory.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/objects/compilation-cache-table-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/slots.h"
#include "src/objects/visitors.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// Initial size of each compilation cache table allocated.
static const int kInitialCacheSize = 64;

CompilationCache::CompilationCache(Isolate* isolate)
    : isolate_(isolate),
      script_(isolate),
      eval_global_(isolate),
      eval_contextual_(isolate),
      reg_exp_(isolate),
      enabled_script_and_eval_(true) {}

Handle<CompilationCacheTable> CompilationCacheEvalOrScript::GetTable() {
  if (IsUndefined(table_, isolate())) {
    return CompilationCacheTable::New(isolate(), kInitialCacheSize);
  }
  return handle(Cast<CompilationCacheTable>(table_), isolate());
}

Handle<CompilationCacheTable> CompilationCacheRegExp::GetTable(int generation) {
  DCHECK_LT(generation, kGenerations);
  Handle<CompilationCacheTable> result;
  if (IsUndefined(tables_[generation], isolate())) {
    result = CompilationCacheTable::New(isolate(), kInitialCacheSize);
    tables_[generation] = *result;
  } else {
    Tagged<CompilationCacheTable> table =
        Cast<CompilationCacheTable>(tables_[generation]);
    result = Handle<CompilationCacheTable>(table, isolate());
  }
  return result;
}

void CompilationCacheRegExp::Age() {
  static_assert(kGenerations > 1);

  // Age the generations implicitly killing off the oldest.
  for (int i = kGenerations - 1; i > 0; i--) {
    tables_[i] = tables_[i - 1];
  }

  // Set the first generation as unborn.
  tables_[0] = ReadOnlyRoots(isolate()).undefined_value();
}

void CompilationCacheScript::Age() {
  DisallowGarbageCollection no_gc;
  if (IsUndefined(table_, isolate())) return;
  Tagged<CompilationCacheTable> table = Cast<CompilationCacheTable>(table_);

  for (InternalIndex entry : table->IterateEntries()) {
    Tagged<Object> key;
    if (!table->ToKey(isolate(), entry, &key)) continue;
    DCHECK(IsWeakFixedArray(key));

    Tagged<Object> value = table->PrimaryValueAt(entry);
    if (!IsUndefined(value, isolate())) {
      Tagged<SharedFunctionInfo> info = Cast<SharedFunctionInfo>(value);
      // Clear entries after Bytecode was flushed from SFI.
      if (!info->HasBytecodeArray()) {
        table->SetPrimaryValueAt(entry,
                                 ReadOnlyRoots(isolate()).undefined_value(),
                                 SKIP_WRITE_BARRIER);
      }
    }
  }
}

void CompilationCacheEval::Age() {
  DisallowGarbageCollection no_gc;
  if (IsUndefined(table_, isolate())) return;
  Tagged<CompilationCacheTable> table = Cast<CompilationCacheTable>(table_);

  for (InternalIndex entry : table->IterateEntries()) {
    Tagged<Object> key;
    if (!table->ToKey(isolate(), entry, &key)) continue;

    if (IsNumber(key, isolate())) {
      // The ageing mechanism for the initial dummy entry in the eval cache.
      // The 'key' is the hash represented as a Number. The 'value' is a smi
      // counting down from kHashGenerations. On reaching zero, the entry is
      // cleared.
      // Note: The following static assert only establishes an explicit
      // connection between initialization- and use-sites of the smi value
      // field.
      static_assert(CompilationCacheTable::kHashGenerations);
      const int new_count = Smi::ToInt(table->PrimaryValueAt(entry)) - 1;
      if (new_count == 0) {
        table->RemoveEntry(entry);
      } else {
        DCHECK_GT(new_count, 0);
        table->SetPrimaryValueAt(entry, Smi::FromInt(new_count),
                                 SKIP_WRITE_BARRIER);
      }
    } else {
      DCHECK(IsFixedArray(key));
      // The ageing mechanism for eval caches.
      Tagged<SharedFunctionInfo> info =
          Cast<SharedFunctionInfo>(table->PrimaryValueAt(entry));
      // Clear entries after Bytecode was flushed from SFI.
      if (!info->HasBytecodeArray()) {
        table->RemoveEntry(entry);
      }
    }
  }
}

void CompilationCacheEvalOrScript::Iterate(RootVisitor* v) {
  v->VisitRootPointer(Root::kCompilationCache, nullptr,
                      FullObjectSlot(&table_));
}

void CompilationCacheRegExp::Iterate(RootVisitor* v) {
  v->VisitRootPointers(Root::kCompilationCache, nullptr,
                       FullObjectSlot(&tables_[0]),
                       FullObjectSlot(&tables_[kGenerations]));
}

void CompilationCacheEvalOrScript::Clear() {
  table_ = ReadOnlyRoots(isolate()).undefined_value();
}

void CompilationCacheRegExp::Clear() {
  MemsetPointer(reinterpret_cast<Address*>(tables_),
                ReadOnlyRoots(isolate()).undefined_value().ptr(), kGenerations);
}

void CompilationCacheEvalOrScript::Remove(
    DirectHandle<SharedFunctionInfo> function_info) {
  if (IsUndefined(table_, isolate())) return;
  Cast<CompilationCacheTable>(table_)->Remove(*function_info);
}

CompilationCacheScript::LookupResult CompilationCacheScript::Lookup(
    Handle<String> source, const ScriptDetails& script_details) {
  LookupResult result;
  LookupResult::RawObjects raw_result_for_escaping_handle_scope;

  // Probe the script table. Make sure not to leak handles
  // into the caller's handle scope.
  {
    HandleScope scope(isolate());
    DirectHandle<CompilationCacheTable> table = GetTable();
    LookupResult probe = CompilationCacheTable::LookupScript(
        table, source, script_details, isolate());
    raw_result_for_escaping_handle_scope = probe.GetRawObjects();
  }
  result = LookupResult::FromRawObjects(raw_result_for_escaping_handle_scope,
                                        isolate());

  // Once outside the manacles of the handle scope, we need to recheck
  // to see if we actually found a cached script. If so, we return a
  // handle created in the caller's handle scope.
  Handle<Script> script;
  if (result.script().ToHandle(&script)) {
    Handle<SharedFunctionInfo> sfi;
    if (result.toplevel_sfi().ToHandle(&sfi)) {
      isolate()->counters()->compilation_cache_hits()->Increment();
      LOG(isolate(), CompilationCacheEvent("hit", "script", *sfi));
    } else {
      isolate()->counters()->compilation_cache_partial_hits()->Increment();
    }
  } else {
    isolate()->counters()->compilation_cache_misses()->Increment();
  }
  return result;
}

void CompilationCacheScript::Put(
    Handle<String> source, DirectHandle<SharedFunctionInfo> function_info) {
  HandleScope scope(isolate());
  Handle<CompilationCacheTable> table = GetTable();
  table_ = *CompilationCacheTable::PutScript(table, source, kNullMaybeHandle,
                                             function_info, isolate());
}

InfoCellPair CompilationCacheEval::Lookup(
    Handle<String> source, Handle<SharedFunctionInfo> outer_info,
    DirectHandle<NativeContext> native_context, LanguageMode language_mode,
    int position) {
  HandleScope scope(isolate());
  // Make sure not to leak the table into the surrounding handle
  // scope. Otherwise, we risk keeping old tables around even after
  // having cleared the cache.
  InfoCellPair result;
  DirectHandle<CompilationCacheTable> table = GetTable();
  result = CompilationCacheTable::LookupEval(
      table, source, outer_info, native_context, language_mode, position);
  if (result.has_shared()) {
    isolate()->counters()->compilation_cache_hits()->Increment();
  } else {
    isolate()->counters()->compilation_cache_misses()->Increment();
  }
  return result;
}

void CompilationCacheEval::Put(Handle<String> source,
                               Handle<SharedFunctionInfo> outer_info,
                               DirectHandle<SharedFunctionInfo> function_info,
                               DirectHandle<NativeContext> native_context,
                               DirectHandle<FeedbackCell> feedback_cell,
                               int position) {
  HandleScope scope(isolate());
  Handle<CompilationCacheTable> table = GetTable();
  table_ =
      *CompilationCacheTable::PutEval(table, source, outer_info, function_info,
                                      native_context, feedback_cell, position);
}

MaybeHandle<RegExpData> CompilationCacheRegExp::Lookup(Handle<String> source,
                                                       JSRegExp::Flags flags) {
  HandleScope scope(isolate());
  // Make sure not to leak the table into the surrounding handle
  // scope. Otherwise, we risk keeping old tables around even after
  // having cleared the cache.
  Handle<Object> result = isolate()->factory()->undefined_value();
  int generation;
  for (generation = 0; generation < kGenerations; generation++) {
    DirectHandle<CompilationCacheTable> table = GetTable(generation);
    result = table->LookupRegExp(source, flags);
    if (IsRegExpDataWrapper(*result)) break;
  }
  if (IsRegExpDataWrapper(*result)) {
    Handle<RegExpData> data(Cast<RegExpDataWrapper>(result)->data(isolate()),
                            isolate());
    if (generation != 0) {
      Put(source, flags, data);
    }
    isolate()->counters()->compilation_cache_hits()->Increment();
    return scope.CloseAndEscape(data);
  } else {
    isolate()->counters()->compilation_cache_misses()->Increment();
    return MaybeHandle<RegExpData>();
  }
}

void CompilationCacheRegExp::Put(Handle<String> source, JSRegExp::Flags flags,
                                 DirectHandle<RegExpData> data) {
  HandleScope scope(isolate());
  Handle<CompilationCacheTable> table = GetTable(0);
  tables_[0] =
      *CompilationCacheTable::PutRegExp(isolate(), table, source, flags, data);
}

void CompilationCache::Remove(DirectHandle<SharedFunctionInfo> function_info) {
  if (!IsEnabledScriptAndEval()) return;

  eval_global_.Remove(function_info);
  eval_contextual_.Remove(function_info);
  script_.Remove(function_info);
}

CompilationCacheScript::LookupResult CompilationCache::LookupScript(
    Handle<String> source, const ScriptDetails& script_details,
    LanguageMode language_mode) {
  if (!IsEnabledScript(language_mode)) return {};
  return script_.Lookup(source, script_details);
}

InfoCellPair CompilationCache::LookupEval(Handle<String> source,
                                          Handle<SharedFunctionInfo> outer_info,
                                          DirectHandle<Context> context,
                                          LanguageMode language_mode,
                                          int position) {
  InfoCellPair result;
  if (!IsEnabledScriptAndEval()) return result;

  const char* cache_type;

  DirectHandle<NativeContext> native_context;
  if (TryCast<NativeContext>(context, &native_context)) {
    result = eval_global_.Lookup(source, outer_info, native_context,
                                 language_mode, position);
    cache_type = "eval-global";

  } else {
    DCHECK_NE(position, kNoSourcePosition);
    DirectHandle<NativeContext> native_context(context->native_context(),
                                               isolate());
    result = eval_contextual_.Lookup(source, outer_info, native_context,
                                     language_mode, position);
    cache_type = "eval-contextual";
  }

  if (result.has_shared()) {
    LOG(isolate(), CompilationCacheEvent("hit", cache_type, result.shared()));
  }

  return result;
}

MaybeHandle<RegExpData> CompilationCache::LookupRegExp(Handle<String> source,
                                                       JSRegExp::Flags flags) {
  return reg_exp_.Lookup(source, flags);
}

void CompilationCache::PutScript(
    Handle<String> source, LanguageMode language_mode,
    DirectHandle<SharedFunctionInfo> function_info) {
  if (!IsEnabledScript(language_mode)) return;
  LOG(isolate(), CompilationCacheEvent("put", "script", *function_info));

  script_.Put(source, function_info);
}

void CompilationCache::PutEval(Handle<String> source,
                               Handle<SharedFunctionInfo> outer_info,
                               DirectHandle<Context> context,
                               DirectHandle<SharedFunctionInfo> function_info,
                               DirectHandle<FeedbackCell> feedback_cell,
                               int position) {
  if (!IsEnabledScriptAndEval()) return;

  const char* cache_type;
  HandleScope scope(isolate());
  DirectHandle<NativeContext> native_context;
  if (TryCast<NativeContext>(context, &native_context)) {
    eval_global_.Put(source, outer_info, function_info, native_context,
                     feedback_cell, position);
    cache_type = "eval-global";
  } else {
    DCHECK_NE(position, kNoSourcePosition);
    DirectHandle<NativeContext> native_context(context->native_context(),
                                               isolate());
    eval_contextual_.Put(source, outer_info, function_info, native_context,
                         feedback_cell, position);
    cache_type = "eval-contextual";
  }
  LOG(isolate(), CompilationCacheEvent("put", cache_type, *function_info));
}

void CompilationCache::PutRegExp(Handle<String> source, JSRegExp::Flags flags,
                                 DirectHandle<RegExpData> data) {
  reg_exp_.Put(source, flags, data);
}

void CompilationCache::Clear() {
  script_.Clear();
  eval_global_.Clear();
  eval_contextual_.Clear();
  reg_exp_.Clear();
}

void CompilationCache::Iterate(RootVisitor* v) {
  script_.Iterate(v);
  eval_global_.Iterate(v);
  eval_contextual_.Iterate(v);
  reg_exp_.Iterate(v);
}

void CompilationCache::MarkCompactPrologue() {
  // Drop SFI entries with flushed bytecode.
  script_.Age();
  eval_global_.Age();
  eval_contextual_.Age();

  // Drop entries in oldest generation.
  reg_exp_.Age();
}

void CompilationCache::EnableScriptAndEval() {
  enabled_script_and_eval_ = true;
}

void CompilationCache::DisableScriptAndEval() {
  enabled_script_and_eval_ = false;
  Clear();
}

}  // namespace internal
}  // namespace v8
```