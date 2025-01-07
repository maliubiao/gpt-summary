Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Understanding the Core Purpose:**

The very first lines are crucial: "This file defines all of the flags." and the comment about sections for "Debug, Release, Logging and Profiling, etc."  This immediately tells us the file's central role: *configuration*. It's the place where V8's behavior can be tweaked via command-line flags.

**2. Recognizing the Template Mechanism:**

The comments about `FLAG_MODE_DECLARE`, `FLAG_MODE_DEFINE_DEFAULTS`, etc., are key. They indicate a template-like approach. The file isn't meant to be included directly as-is, but rather with a specific "mode" defined. This allows the same *definitions* of the flags to be used for different purposes (declaring variables, defining defaults, creating metadata, etc.).

**3. Deconstructing the Macros:**

The file is heavily reliant on macros (`DEFINE_BOOL`, `DEFINE_INT`, `DEFINE_IMPLICATION`). Understanding what these macros *do* is essential. Let's take a few examples:

* **`DEFINE_BOOL(nam, def, cmt)`:** This seems to define a boolean flag. The `nam` is likely the flag's name, `def` is the default value, and `cmt` is the comment/description. The `FLAG(BOOL, bool, ...)` part suggests a lower-level macro is being invoked.

* **`DEFINE_IMPLICATION(whenflag, thenflag)`:** This clearly establishes a dependency between flags. If `whenflag` is true, then `thenflag` is also implicitly set to true. The variants like `DEFINE_WEAK_IMPLICATION` and `DEFINE_NEG_IMPLICATION` hint at different strengths and negation of these dependencies.

* **`FLAG_FULL(ftype, ctype, nam, def, cmt)`:** This is the core macro that gets expanded differently depending on the `FLAG_MODE_...` defined. By examining the different `FLAG_MODE_...` blocks, we can see how this macro is used to:
    * Declare variables in `FlagValues` (`FLAG_MODE_DECLARE`).
    * Define default values (`FLAG_MODE_DEFINE_DEFAULTS`).
    * Create metadata entries (`FLAG_MODE_META`).
    * Define implication logic (`FLAG_MODE_DEFINE_IMPLICATIONS`).

**4. Identifying Key Sections and Concepts:**

Scanning the content reveals logical groupings of flags:

* **Experimental Features:** Flags starting with `DEFINE_EXPERIMENTAL_FEATURE`.
* **Language Modes (Strict Mode, Harmony/JavaScript features):**  Flags like `use_strict`, `harmony`, `js_staging`. The comments about updating `bootstrapper.cc` are a valuable clue.
* **Performance and Memory Management:** Flags related to JIT, GC (`incremental_marking`, `stress_snapshot`, `lite_mode`), and code optimization (`maglev`, `turbofan`).
* **Debugging and Testing:**  Flags like `abort_on_contradictory_flags`, various `trace_...` flags, and `print_...` flags.

**5. Inferring Functionality from Flag Names and Comments:**

Many flag names are self-explanatory, or their purpose becomes clear from the accompanying comments. For example, `trace_temporal` likely traces activity related to the Temporal API. `stress_snapshot` probably disables snapshot sharing for testing purposes.

**6. Considering the ".tq" Extension:**

The prompt specifically asks about the `.tq` extension. Knowing that Torque is V8's internal language for implementing built-ins, if this file *were* a `.tq` file, it would imply it was written in Torque. However, the current file is a `.h` (header) file, so this part of the prompt is a bit of a distractor or a test of understanding.

**7. Relating to JavaScript (with examples):**

The file directly influences JavaScript behavior. The language mode flags (`use_strict`, `harmony`) are prime examples. Features behind in-progress/staged flags will eventually impact the JavaScript language. The optimization flags affect how efficiently JavaScript code runs.

* **`use_strict`:**  Easy to illustrate with a simple example.
* **`harmony_temporal`:** Requires understanding what the Temporal API is (or at least knowing it's a newer JavaScript feature).
* **`maglev`:** More abstract, but the example shows how it affects performance without changing the code's functionality.

**8. Code Logic Inference (with assumptions):**

The `DEFINE_IMPLICATION` macros represent conditional logic. To illustrate this, we need to make assumptions about the initial state of flags.

* **Assumption:**  `experimental` is initially false.
* **Input:** Set `harmony_temporal` to true.
* **Output:** `experimental` will also become true due to the implication.

**9. Common Programming Errors (related to flags):**

The "contradictory flags" are the most obvious source of errors. Users might accidentally set flags that conflict with each other. The `abort_on_contradictory_flags` flag itself highlights this potential problem.

**10. Structuring the Summary:**

Finally, organize the findings into logical categories:

* **Core Function:** What the file *is*.
* **Mechanism:** How it works (macros, modes).
* **Impact on JavaScript:** Concrete examples.
* **Code Logic:**  Implications.
* **Common Errors:** Flag conflicts.
* **".tq" Note:** Address that part of the prompt.

**Self-Correction/Refinement During the Process:**

* Initially, I might have just listed all the macros. Then I'd realize it's more useful to *explain* what they do.
* I might have initially missed the significance of the `FLAG_MODE_...` definitions and would go back to analyze them more deeply.
* When thinking about JavaScript examples, I'd try to choose examples that directly relate to the flag names, rather than very complex scenarios.
* I'd double-check the prompt's specific questions to ensure I've addressed all of them.

By following these steps, focusing on understanding the core purpose and mechanisms, and using the provided information to infer functionality, we can arrive at a comprehensive analysis of the `flag-definitions.h` file.
好的，让我们来分析一下 `v8/src/flags/flag-definitions.h` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/flags/flag-definitions.h` 是 V8 引擎中一个至关重要的头文件，它定义了所有可以用来配置 V8 行为的命令行标志（flags）。  这个文件使用预处理宏定义了一套机制，使得同一个标志定义可以在不同的编译阶段和目的下生成不同的代码。

**更详细的功能点:**

1. **定义命令行标志:**  这个文件的核心功能是定义了大量的命令行标志，这些标志可以控制 V8 引擎的各种特性，例如：
    * **语言特性:**  是否启用实验性的 JavaScript 语法特性 (`--harmony`, `--js_staging`)，是否启用严格模式 (`--use_strict`)。
    * **优化和性能:**  启用或禁用不同的优化编译器 (Sparkplug, Maglev, TurboFan)，调整内联策略，控制垃圾回收的行为 (`--incremental_marking`, `--stress_snapshot`)。
    * **调试和诊断:**  启用各种跟踪和日志输出 (`--trace_gc`, `--print_code`)，设置断点 (`--maglev_break_on_entry`)。
    * **内存管理:**  控制堆的大小，启用某些内存管理策略。
    * **内部设置:**  调整 V8 内部的一些参数和阈值。

2. **分段组织:** 文件将标志按照功能模块进行划分，例如 "Flags in all modes", "Experimental features", "Flags for language modes", "Flags for optimization"，方便查找和管理。

3. **模板化定义:**  该文件使用预处理宏 (`#define`) 和条件编译 (`#if defined(...)`) 实现了一种模板化的定义方式。  通过定义不同的 `FLAG_MODE_...` 宏，同一个 `DEFINE_BOOL`, `DEFINE_INT` 等宏会被展开成不同的代码：
    * `FLAG_MODE_DECLARE`:  声明 `FlagValues` 结构体中的成员变量，用于存储标志的值。
    * `FLAG_MODE_DEFINE_DEFAULTS`: 定义标志的默认值常量。
    * `FLAG_MODE_META`:  生成标志的元数据，用于标志解析、打印帮助信息等。
    * `FLAG_MODE_DEFINE_IMPLICATIONS`: 定义标志之间的隐含关系 (implications)，当一个标志被设置时，可以自动设置或修改其他标志的值。
    * `FLAG_MODE_APPLY`:  用于应用一些通用的宏操作到所有标志上。

4. **标志类型:** 支持多种标志类型，如布尔型 (`DEFINE_BOOL`)、整型 (`DEFINE_INT`)、浮点型 (`DEFINE_FLOAT`)、字符串型 (`DEFINE_STRING`) 等。

5. **标志别名:**  允许为某些标志定义别名 (`DEFINE_ALIAS_BOOL`)，方便用户使用。

6. **标志隐含关系 (Implications):**  可以定义标志之间的依赖关系，例如：
    * `DEFINE_IMPLICATION(whenflag, thenflag)`:  当 `whenflag` 为真时，`thenflag` 也自动设置为真。
    * `DEFINE_NEG_IMPLICATION(whenflag, thenflag)`: 当 `whenflag` 为真时，`thenflag` 自动设置为假。
    * `DEFINE_WEAK_IMPLICATION`: 弱隐含关系，可以被后续的强隐含关系或显式设置覆盖。

**关于 `.tq` 结尾:**

如果 `v8/src/flags/flag-definitions.h` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是 V8 内部使用的一种领域特定语言 (DSL)，用于定义 V8 的内置函数和运行时代码。  然而，根据你提供的文件路径，它的结尾是 `.h`，所以它是一个 C++ 头文件，而不是 Torque 文件。

**与 JavaScript 的关系及示例:**

`v8/src/flags/flag-definitions.h` 中定义的标志直接影响着 V8 引擎如何执行 JavaScript 代码。以下是一些例子：

* **`--use_strict`:**  启用 JavaScript 的严格模式。
   ```javascript
   // 正常模式下，允许意外创建全局变量
   function normalMode() {
     undeclaredVariable = 10; // 不会报错
     console.log(undeclaredVariable); // 输出 10
   }
   normalMode();

   // 严格模式下，不允许意外创建全局变量
   function strictMode() {
     "use strict";
     undeclaredVariable = 10; // ReferenceError: undeclaredVariable is not defined
   }
   // 运行 V8 时加上 --use_strict 标志将会使 strictMode 函数抛出错误
   // (当然，在 JavaScript 代码中使用 "use strict" 也能达到相同的效果)
   ```

* **`--harmony_temporal`:**  启用尚未完全标准化的 Temporal API (用于处理日期和时间)。
   ```javascript
   // 需要在运行 V8 时加上 --harmony_temporal 标志
   const now = Temporal.Now.instant();
   console.log(now.toString());
   ```

* **`--maglev` / `--turbofan`:**  控制 V8 使用哪个优化编译器。这不会改变 JavaScript 代码的语法或行为，但会显著影响代码的执行性能。
   ```javascript
   function add(a, b) {
     return a + b;
   }

   // 在没有优化编译器的情况下，add 函数可能以解释执行的方式运行。
   // 启用 --maglev 或 --turbofan 后，V8 会尝试将 add 函数编译成更高效的机器码。
   console.time("add");
   for (let i = 0; i < 1000000; i++) {
     add(i, i + 1);
   }
   console.timeEnd("add");
   ```
   运行上面的代码，你会发现加上 `--maglev` 或 `--turbofan` 标志后，执行时间会显著减少。

**代码逻辑推理及示例:**

标志的隐含关系定义了当某些标志被设置时，其他标志会如何自动调整。

**假设输入:**

假设我们运行 V8 时设置了以下标志：

```bash
./d8 --experimental --harmony_temporal
```

**代码逻辑推理:**

根据 `flag-definitions.h` 中的定义：

* `DEFINE_BOOL(experimental, false, ...)` 定义了 `experimental` 标志，默认值为 `false`。
* `DEFINE_EXPERIMENTAL_FEATURE(harmony_temporal, ...)` 定义了 `harmony_temporal` 标志，并且：
    * `FLAG(BOOL, bool, nam, false, cmt " (experimental)")`  表明 `harmony_temporal` 默认为 `false`。
    * `DEFINE_IMPLICATION(nam, experimental)` 表示当 `harmony_temporal` 被设置为 `true` 时，`experimental` 也会被设置为 `true`。

**输出:**

在这种情况下：

1. `--experimental` 显式设置为 `true`。
2. `--harmony_temporal` 显式设置为 `true`。
3. 由于 `DEFINE_IMPLICATION(harmony_temporal, experimental)` 的存在，即使没有显式设置 `--experimental`，设置 `--harmony_temporal` 也会导致 `experimental` 变为 `true`。

**用户常见的编程错误:**

用户在使用 V8 标志时可能会犯以下错误：

1. **标志拼写错误:**  输入了不存在的标志名称，V8 通常会忽略这些未知的标志。
   ```bash
   ./d8 --harmny  // 正确的应该是 --harmony
   ```

2. **标志值类型错误:**  为需要特定类型的标志提供了错误的值。例如，一个需要整数的标志，你提供了字符串。
   ```bash
   ./d8 --stack_size="large"  // --stack_size 通常需要一个整数值
   ```

3. **标志冲突:**  设置了相互冲突的标志，导致 V8 的行为不确定或报错 (取决于 `--abort_on_contradictory_flags` 的设置)。
   ```bash
   ./d8 --jitless --turbofan  // jitless 禁用优化编译器，turbofan 是一个优化编译器，两者冲突
   ```

4. **不理解标志的含义:**  盲目地设置一些标志，而不清楚它们的功能，可能会导致性能下降或程序行为异常。

**总结一下它的功能（第 1 部分）：**

`v8/src/flags/flag-definitions.h` 的主要功能是作为 V8 引擎配置的核心入口点，它使用宏定义的方式声明了所有可用的命令行标志，并描述了这些标志的功能、默认值以及它们之间的隐含关系。这个文件为 V8 提供了强大的可配置性，允许开发者和用户根据不同的需求调整引擎的行为，例如启用实验性特性、控制优化策略、进行调试等。  它通过模板化的宏定义，使得相同的标志定义可以服务于不同的编译阶段和目的。

Prompt: 
```
这是目录为v8/src/flags/flag-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/flags/flag-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file defines all of the flags.  It is separated into different section,
// for Debug, Release, Logging and Profiling, etc.  To add a new flag, find the
// correct section, and use one of the DEFINE_ macros, without a trailing ';'.
//
// This include does not have a guard, because it is a template-style include,
// which can be included multiple times in different modes.  It expects to have
// a mode defined before it's included.  The modes are FLAG_MODE_... below:
//
// PRESUBMIT_INTENTIONALLY_MISSING_INCLUDE_GUARD

#define DEFINE_IMPLICATION(whenflag, thenflag) \
  DEFINE_VALUE_IMPLICATION(whenflag, thenflag, true)

// A weak implication will be overwritten by a normal implication or by an
// explicit flag.
#define DEFINE_WEAK_IMPLICATION(whenflag, thenflag) \
  DEFINE_WEAK_VALUE_IMPLICATION(whenflag, thenflag, true)

#define DEFINE_WEAK_NEG_IMPLICATION(whenflag, thenflag) \
  DEFINE_WEAK_VALUE_IMPLICATION(whenflag, thenflag, false)

#define DEFINE_NEG_IMPLICATION(whenflag, thenflag) \
  DEFINE_VALUE_IMPLICATION(whenflag, thenflag, false)

#define DEFINE_NEG_NEG_IMPLICATION(whenflag, thenflag) \
  DEFINE_NEG_VALUE_IMPLICATION(whenflag, thenflag, false)

// With FLAG_MODE_DECLARE we declare the fields in the {FlagValues} struct.
// Read-only flags are static constants instead of fields.
#if defined(FLAG_MODE_DECLARE)
#define FLAG_FULL(ftype, ctype, nam, def, cmt) FlagValue<ctype> nam{def};
#define FLAG_READONLY(ftype, ctype, nam, def, cmt) \
  static constexpr FlagValue<ctype> nam{def};

// We need to define all of our default values so that the Flag structure can
// access them by pointer.  These are just used internally inside of one .cc,
// for MODE_META, so there is no impact on the flags interface.
#elif defined(FLAG_MODE_DEFINE_DEFAULTS)
#define FLAG_FULL(ftype, ctype, nam, def, cmt) \
  static constexpr ctype FLAGDEFAULT_##nam{def};
#define FLAG_READONLY(ftype, ctype, nam, def, cmt) \
  static constexpr ctype FLAGDEFAULT_##nam{def};

// We want to write entries into our meta data table, for internal parsing and
// printing / etc in the flag parser code.
#elif defined(FLAG_MODE_META)
#define FLAG_FULL(ftype, ctype, nam, def, cmt) \
  {Flag::TYPE_##ftype, #nam, &v8_flags.nam, &FLAGDEFAULT_##nam, cmt, false},
// Readonly flags don't pass the value pointer since the struct expects a
// mutable value. That's okay since the value always equals the default.
#define FLAG_READONLY(ftype, ctype, nam, def, cmt) \
  {Flag::TYPE_##ftype, #nam, nullptr, &FLAGDEFAULT_##nam, cmt, false},
#define FLAG_ALIAS(ftype, ctype, alias, nam)                       \
  {Flag::TYPE_##ftype,  #alias, &v8_flags.nam, &FLAGDEFAULT_##nam, \
   "alias for --" #nam, false},  // NOLINT(whitespace/indent)

// We produce the code to set flags when it is implied by another flag.
#elif defined(FLAG_MODE_DEFINE_IMPLICATIONS)
#define DEFINE_VALUE_IMPLICATION(whenflag, thenflag, value)   \
  changed |= TriggerImplication(v8_flags.whenflag, #whenflag, \
                                &v8_flags.thenflag, #thenflag, value, false);

// A weak implication will be overwritten by a normal implication or by an
// explicit flag.
#define DEFINE_WEAK_VALUE_IMPLICATION(whenflag, thenflag, value) \
  changed |= TriggerImplication(v8_flags.whenflag, #whenflag,    \
                                &v8_flags.thenflag, #thenflag, value, true);

#define DEFINE_GENERIC_IMPLICATION(whenflag, statement) \
  if (v8_flags.whenflag) statement;

#define DEFINE_NEG_VALUE_IMPLICATION(whenflag, thenflag, value)    \
  changed |= TriggerImplication(!v8_flags.whenflag, "!" #whenflag, \
                                &v8_flags.thenflag, #thenflag, value, false);

#define DEFINE_NEG_VALUE_VALUE_IMPLICATION(whenflag, whenvalue, thenflag, \
                                           thenvalue)                     \
  changed |=                                                              \
      TriggerImplication(v8_flags.whenflag != whenvalue, #whenflag,       \
                         &v8_flags.thenflag, #thenflag, thenvalue, false);

#define DEFINE_MIN_VALUE_IMPLICATION(flag, min_value)             \
  changed |= TriggerImplication(v8_flags.flag < min_value, #flag, \
                                &v8_flags.flag, #flag, min_value, false);

#define DEFINE_DISABLE_FLAG_IMPLICATION(whenflag, thenflag) \
  if (v8_flags.whenflag && v8_flags.thenflag) {             \
    PrintF(stderr, "Warning: disabling flag --" #thenflag   \
                   " due to conflicting flags\n");          \
  }                                                         \
  DEFINE_VALUE_IMPLICATION(whenflag, thenflag, false)

// We apply a generic macro to the flags.
#elif defined(FLAG_MODE_APPLY)

#define FLAG_FULL FLAG_MODE_APPLY

#else
#error No mode supplied when including flags.defs
#endif

// Dummy defines for modes where it is not relevant.
#ifndef FLAG_FULL
#define FLAG_FULL(ftype, ctype, nam, def, cmt)
#endif

#ifndef FLAG_READONLY
#define FLAG_READONLY(ftype, ctype, nam, def, cmt)
#endif

#ifndef FLAG_ALIAS
#define FLAG_ALIAS(ftype, ctype, alias, nam)
#endif

#ifndef DEFINE_VALUE_IMPLICATION
#define DEFINE_VALUE_IMPLICATION(whenflag, thenflag, value)
#endif

#ifndef DEFINE_WEAK_VALUE_IMPLICATION
#define DEFINE_WEAK_VALUE_IMPLICATION(whenflag, thenflag, value)
#endif

#ifndef DEFINE_GENERIC_IMPLICATION
#define DEFINE_GENERIC_IMPLICATION(whenflag, statement)
#endif

#ifndef DEFINE_NEG_VALUE_IMPLICATION
#define DEFINE_NEG_VALUE_IMPLICATION(whenflag, thenflag, value)
#endif
#ifndef DEFINE_NEG_VALUE_VALUE_IMPLICATION
#define DEFINE_NEG_VALUE_VALUE_IMPLICATION(whenflag, whenvalue, thenflag, \
                                           thenvalue)
#endif

#ifndef DEFINE_MIN_VALUE_IMPLICATION
#define DEFINE_MIN_VALUE_IMPLICATION(flag, min_value)
#endif

#ifndef DEFINE_DISABLE_FLAG_IMPLICATION
#define DEFINE_DISABLE_FLAG_IMPLICATION(whenflag, thenflag)
#endif

#ifndef DEBUG_BOOL
#error DEBUG_BOOL must be defined at this point.
#endif  // DEBUG_BOOL

#if V8_ENABLE_SPARKPLUG
#define ENABLE_SPARKPLUG_BY_DEFAULT true
#else
#define ENABLE_SPARKPLUG_BY_DEFAULT false
#endif

// Supported ARM configurations are:
//  "armv6":       ARMv6 + VFPv2
//  "armv7":       ARMv7 + VFPv3-D32 + NEON
//  "armv7+sudiv": ARMv7 + VFPv4-D32 + NEON + SUDIV
//  "armv8":       ARMv8 (including all of the above)
#if !defined(ARM_TEST_NO_FEATURE_PROBE) ||                            \
    (defined(CAN_USE_ARMV8_INSTRUCTIONS) &&                           \
     defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_SUDIV) && \
     defined(CAN_USE_NEON) && defined(CAN_USE_VFP3_INSTRUCTIONS))
#define ARM_ARCH_DEFAULT "armv8"
#elif defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_SUDIV) && \
    defined(CAN_USE_NEON) && defined(CAN_USE_VFP3_INSTRUCTIONS)
#define ARM_ARCH_DEFAULT "armv7+sudiv"
#elif defined(CAN_USE_ARMV7_INSTRUCTIONS) && defined(CAN_USE_NEON) && \
    defined(CAN_USE_VFP3_INSTRUCTIONS)
#define ARM_ARCH_DEFAULT "armv7"
#else
#define ARM_ARCH_DEFAULT "armv6"
#endif

#ifdef V8_OS_WIN
#define ENABLE_LOG_COLOUR false
#else
#define ENABLE_LOG_COLOUR true
#endif

#define DEFINE_BOOL(nam, def, cmt) FLAG(BOOL, bool, nam, def, cmt)
#define DEFINE_BOOL_READONLY(nam, def, cmt) \
  FLAG_READONLY(BOOL, bool, nam, def, cmt)
#define DEFINE_MAYBE_BOOL(nam, cmt) \
  FLAG(MAYBE_BOOL, std::optional<bool>, nam, std::nullopt, cmt)
#define DEFINE_INT(nam, def, cmt) FLAG(INT, int, nam, def, cmt)
#define DEFINE_UINT(nam, def, cmt) FLAG(UINT, unsigned int, nam, def, cmt)
#define DEFINE_UINT_READONLY(nam, def, cmt) \
  FLAG_READONLY(UINT, unsigned int, nam, def, cmt)
#define DEFINE_UINT64(nam, def, cmt) FLAG(UINT64, uint64_t, nam, def, cmt)
#define DEFINE_FLOAT(nam, def, cmt) FLAG(FLOAT, double, nam, def, cmt)
#define DEFINE_SIZE_T(nam, def, cmt) FLAG(SIZE_T, size_t, nam, def, cmt)
#define DEFINE_STRING(nam, def, cmt) FLAG(STRING, const char*, nam, def, cmt)
#define DEFINE_ALIAS_BOOL(alias, nam) FLAG_ALIAS(BOOL, bool, alias, nam)
#define DEFINE_ALIAS_INT(alias, nam) FLAG_ALIAS(INT, int, alias, nam)
#define DEFINE_ALIAS_FLOAT(alias, nam) FLAG_ALIAS(FLOAT, double, alias, nam)
#define DEFINE_ALIAS_SIZE_T(alias, nam) FLAG_ALIAS(SIZE_T, size_t, alias, nam)
#define DEFINE_ALIAS_STRING(alias, nam) \
  FLAG_ALIAS(STRING, const char*, alias, nam)

#ifdef DEBUG
#define DEFINE_DEBUG_BOOL DEFINE_BOOL
#else
#define DEFINE_DEBUG_BOOL DEFINE_BOOL_READONLY
#endif

//
// Flags in all modes.
//
#define FLAG FLAG_FULL

// Experimental features.
// Features that are still considered experimental and which are not ready for
// fuzz testing should be defined using this macro. The feature will then imply
// --experimental, which will indicate to the user that they are running an
// experimental configuration of V8. Experimental features are always disabled
// by default. When these features mature, the flag should first turn into a
// regular feature flag (still disabled by default) and then ideally be staged
// behind (for example) --future before being enabled by default.
DEFINE_BOOL(experimental, false,
            "Indicates that V8 is running with experimental features enabled. "
            "This flag is typically not set explicitly but instead enabled as "
            "an implication of other flags which enable experimental features.")
#define DEFINE_EXPERIMENTAL_FEATURE(nam, cmt)         \
  FLAG(BOOL, bool, nam, false, cmt " (experimental)") \
  DEFINE_IMPLICATION(nam, experimental)

// ATTENTION: This is set to true by default in d8. But for API compatibility,
// it generally defaults to false.
DEFINE_BOOL(abort_on_contradictory_flags, false,
            "Disallow flags or implications overriding each other.")
// This implication is also hard-coded into the flags processing to make sure it
// becomes active before we even process subsequent flags.
DEFINE_NEG_IMPLICATION(fuzzing, abort_on_contradictory_flags)
// As abort_on_contradictory_flags, but it will simply exit with return code 0.
DEFINE_BOOL(exit_on_contradictory_flags, false,
            "Exit with return code 0 on contradictory flags.")
// We rely on abort_on_contradictory_flags to turn on the analysis.
DEFINE_WEAK_IMPLICATION(exit_on_contradictory_flags,
                        abort_on_contradictory_flags)
// This is not really a flag, it affects the interpretation of the next flag but
// doesn't become permanently true when specified. This only works for flags
// defined in this file, but not for d8 flags defined in src/d8/d8.cc.
DEFINE_BOOL(allow_overwriting_for_next_flag, false,
            "temporary disable flag contradiction to allow overwriting just "
            "the next flag")

// Flags for language modes and experimental language features.
DEFINE_BOOL(use_strict, false, "enforce strict mode")

DEFINE_BOOL(trace_temporal, false, "trace temporal code")

DEFINE_BOOL(harmony, false, "enable all completed harmony features")
DEFINE_BOOL(harmony_shipping, true, "enable all shipped harmony features")

DEFINE_BOOL(js_staging, false, "enable all completed JavaScript features")
DEFINE_BOOL(js_shipping, true, "enable all shipped JavaScript features")

// Update bootstrapper.cc whenever adding a new feature flag.

// Features that are still work in progress (behind individual flags).
//
// The "harmony" naming is now outdated and will no longer be used for new JS
// features. Use the JAVASCRIPT macros instead.
//
// TODO(v8:14214): Remove --harmony flags once transition is complete.
#define HARMONY_INPROGRESS_BASE(V)                                             \
  V(harmony_weak_refs_with_cleanup_some,                                       \
    "harmony weak references with FinalizationRegistry.prototype.cleanupSome") \
  V(harmony_temporal, "Temporal")                                              \
  V(harmony_shadow_realm, "harmony ShadowRealm")                               \
  V(harmony_struct, "harmony structs, shared structs, and shared arrays")

#define JAVASCRIPT_INPROGRESS_FEATURES_BASE(V)                               \
  V(js_decorators, "decorators")                                             \
  V(js_source_phase_imports, "source phase imports")

#ifdef V8_INTL_SUPPORT
#define HARMONY_INPROGRESS(V) \
  HARMONY_INPROGRESS_BASE(V)  \
  V(harmony_intl_best_fit_matcher, "Intl BestFitMatcher")
#define JAVASCRIPT_INPROGRESS_FEATURES(V) JAVASCRIPT_INPROGRESS_FEATURES_BASE(V)
#else
#define HARMONY_INPROGRESS(V) HARMONY_INPROGRESS_BASE(V)
#define JAVASCRIPT_INPROGRESS_FEATURES(V) JAVASCRIPT_INPROGRESS_FEATURES_BASE(V)
#endif

// Features that are complete (but still behind the --harmony flag).
#define HARMONY_STAGED_BASE(V)
#define JAVASCRIPT_STAGED_FEATURES_BASE(V)                           \
  V(js_explicit_resource_management, "explicit resource management") \
  V(js_float16array,                                                 \
    "Float16Array, Math.f16round, DataView.getFloat16, DataView.setFloat16")

#ifdef V8_INTL_SUPPORT
#define HARMONY_STAGED(V)                    \
  HARMONY_STAGED_BASE(V)                     \
  V(harmony_remove_intl_locale_info_getters, \
    "Remove Obsoleted Intl Locale Info getters")
#define JAVASCRIPT_STAGED_FEATURES(V) JAVASCRIPT_STAGED_FEATURES_BASE(V)
#else
#define HARMONY_STAGED(V) HARMONY_STAGED_BASE(V)
#define JAVASCRIPT_STAGED_FEATURES(V) JAVASCRIPT_STAGED_FEATURES_BASE(V)
#endif

// Features that are shipping (turned on by default, but internal flag remains).
#define HARMONY_SHIPPING_BASE(V)                             \
  V(harmony_iterator_helpers, "JavaScript iterator helpers") \
  V(harmony_set_methods, "harmony Set Methods")              \
  V(harmony_import_attributes, "harmony import attributes")

#define JAVASCRIPT_SHIPPING_FEATURES_BASE(V)                           \
  V(js_regexp_duplicate_named_groups, "RegExp duplicate named groups") \
  V(js_regexp_modifiers, "RegExp modifiers")                           \
  V(js_promise_try, "Promise.try")                                     \
  V(js_atomics_pause, "Atomics.pause")

#ifdef V8_INTL_SUPPORT
#define HARMONY_SHIPPING(V) HARMONY_SHIPPING_BASE(V)
#define JAVASCRIPT_SHIPPING_FEATURES(V) JAVASCRIPT_SHIPPING_FEATURES_BASE(V)
#else
#define HARMONY_SHIPPING(V) HARMONY_SHIPPING_BASE(V)
#define JAVASCRIPT_SHIPPING_FEATURES(V) JAVASCRIPT_SHIPPING_FEATURES_BASE(V)
#endif

// Once a shipping feature has proved stable in the wild, it will be dropped
// from HARMONY_SHIPPING, all occurrences of the FLAG_ variable are removed,
// and associated tests are moved from the harmony directory to the appropriate
// esN directory.
//
// In-progress features are not code complete and are considered experimental,
// i.e. not ready for fuzz testing.

#define FLAG_INPROGRESS_FEATURES(id, description)                     \
  DEFINE_BOOL(id, false,                                              \
              "enable " #description " (in progress / experimental)") \
  DEFINE_IMPLICATION(id, experimental)
HARMONY_INPROGRESS(FLAG_INPROGRESS_FEATURES)
JAVASCRIPT_INPROGRESS_FEATURES(FLAG_INPROGRESS_FEATURES)
#undef FLAG_INPROGRESS_FEATURES

#define FLAG_STAGED_FEATURES(id, description)    \
  DEFINE_BOOL(id, false, "enable " #description) \
  DEFINE_IMPLICATION(harmony, id)                \
  DEFINE_IMPLICATION(js_staging, id)
HARMONY_STAGED(FLAG_STAGED_FEATURES)
JAVASCRIPT_STAGED_FEATURES(FLAG_STAGED_FEATURES)
DEFINE_IMPLICATION(harmony, js_staging)
#undef FLAG_STAGED_FEATURES

#define FLAG_SHIPPING_FEATURES(id, description)    \
  DEFINE_BOOL(id, true, "enable " #description)    \
  DEFINE_NEG_NEG_IMPLICATION(harmony_shipping, id) \
  DEFINE_NEG_NEG_IMPLICATION(js_shipping, id)
HARMONY_SHIPPING(FLAG_SHIPPING_FEATURES)
JAVASCRIPT_SHIPPING_FEATURES(FLAG_SHIPPING_FEATURES)
DEFINE_NEG_NEG_IMPLICATION(harmony_shipping, js_shipping)
#undef FLAG_SHIPPING_FEATURES

DEFINE_BOOL(builtin_subclassing, true,
            "subclassing support in built-in methods")

// If the following flag is set to `true`, the SharedArrayBuffer constructor is
// enabled per context depending on the callback set via
// `SetSharedArrayBufferConstructorEnabledCallback`. If no callback is set, the
// SharedArrayBuffer constructor is disabled.
DEFINE_BOOL(enable_sharedarraybuffer_per_context, false,
            "enable the SharedArrayBuffer constructor per context")

#ifdef V8_INTL_SUPPORT
DEFINE_BOOL(icu_timezone_data, true, "get information about timezones from ICU")
#endif

#ifdef V8_ENABLE_DOUBLE_CONST_STORE_CHECK
#define V8_ENABLE_DOUBLE_CONST_STORE_CHECK_BOOL true
#else
#define V8_ENABLE_DOUBLE_CONST_STORE_CHECK_BOOL false
#endif

#ifdef V8_ENABLE_LAZY_SOURCE_POSITIONS
#define V8_LAZY_SOURCE_POSITIONS_BOOL true
#else
#define V8_LAZY_SOURCE_POSITIONS_BOOL false
#endif

#ifdef V8_SHARED_RO_HEAP
#define V8_SHARED_RO_HEAP_BOOL true
#else
#define V8_SHARED_RO_HEAP_BOOL false
#endif

DEFINE_BOOL(stress_snapshot, false,
            "disables sharing of the read-only heap for testing")
// Incremental marking is incompatible with the stress_snapshot mode;
// specifically, serialization may clear bytecode arrays from shared function
// infos which the MarkCompactCollector (running concurrently) may still need.
// See also https://crbug.com/v8/10882.
//
// Note: This is not an issue in production because we don't clear SFI's
// there (that only happens in mksnapshot and in --stress-snapshot mode).
DEFINE_NEG_IMPLICATION(stress_snapshot, incremental_marking)

#ifdef V8_LITE_MODE
#define V8_LITE_MODE_BOOL true
#else
#define V8_LITE_MODE_BOOL false
#endif

DEFINE_BOOL(lite_mode, V8_LITE_MODE_BOOL,
            "enables trade-off of performance for memory savings")

// Lite mode implies other flags to trade-off performance for memory.
DEFINE_IMPLICATION(lite_mode, jitless)
DEFINE_IMPLICATION(lite_mode, optimize_for_size)

#ifdef V8_ALLOCATION_FOLDING
#define V8_ALLOCATION_FOLDING_BOOL true
#else
#define V8_ALLOCATION_FOLDING_BOOL false
#endif

DEFINE_BOOL_READONLY(enable_allocation_folding, V8_ALLOCATION_FOLDING_BOOL,
                     "Use allocation folding globally")
DEFINE_NEG_NEG_IMPLICATION(enable_allocation_folding, turbo_allocation_folding)

#ifdef V8_DISABLE_WRITE_BARRIERS
#define V8_DISABLE_WRITE_BARRIERS_BOOL true
#else
#define V8_DISABLE_WRITE_BARRIERS_BOOL false
#endif

DEFINE_BOOL_READONLY(disable_write_barriers, V8_DISABLE_WRITE_BARRIERS_BOOL,
                     "disable write barriers when GC is non-incremental "
                     "and heap contains single generation.")

// Disable incremental marking barriers
DEFINE_NEG_IMPLICATION(disable_write_barriers, incremental_marking)
DEFINE_NEG_IMPLICATION(disable_write_barriers, concurrent_marking)
DEFINE_NEG_IMPLICATION(disable_write_barriers, cppheap_incremental_marking)
DEFINE_NEG_IMPLICATION(disable_write_barriers, cppheap_concurrent_marking)

#ifdef V8_ENABLE_UNCONDITIONAL_WRITE_BARRIERS
#define V8_ENABLE_UNCONDITIONAL_WRITE_BARRIERS_BOOL true
#else
#define V8_ENABLE_UNCONDITIONAL_WRITE_BARRIERS_BOOL false
#endif

DEFINE_BOOL_READONLY(enable_unconditional_write_barriers,
                     V8_ENABLE_UNCONDITIONAL_WRITE_BARRIERS_BOOL,
                     "always use full write barriers")

#ifdef V8_ENABLE_SINGLE_GENERATION
#define V8_SINGLE_GENERATION_BOOL true
#else
#define V8_SINGLE_GENERATION_BOOL false
#endif

DEFINE_BOOL_READONLY(
    single_generation, V8_SINGLE_GENERATION_BOOL,
    "allocate all objects from young generation to old generation")

#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
#define V8_ENABLE_CONSERVATIVE_STACK_SCANNING_BOOL true
#else
#define V8_ENABLE_CONSERVATIVE_STACK_SCANNING_BOOL false
#endif
DEFINE_BOOL_READONLY(conservative_stack_scanning,
                     V8_ENABLE_CONSERVATIVE_STACK_SCANNING_BOOL,
                     "use conservative stack scanning")
DEFINE_IMPLICATION(conservative_stack_scanning, minor_ms)
DEFINE_NEG_IMPLICATION(conservative_stack_scanning, compact_with_stack)

#ifdef V8_ENABLE_DIRECT_HANDLE
#define V8_ENABLE_DIRECT_HANDLE_BOOL true
#else
#define V8_ENABLE_DIRECT_HANDLE_BOOL false
#endif
DEFINE_BOOL_READONLY(direct_handle, V8_ENABLE_DIRECT_HANDLE_BOOL,
                     "use direct handles with conservative stack scanning")
// Do not use direct handles without conservative stack scanning, as this would
// break the correctness of the GC.
DEFINE_NEG_NEG_IMPLICATION(conservative_stack_scanning, direct_handle)

#ifdef V8_ENABLE_LOCAL_OFF_STACK_CHECK
#define V8_ENABLE_LOCAL_OFF_STACK_CHECK_BOOL true
#else
#define V8_ENABLE_LOCAL_OFF_STACK_CHECK_BOOL false
#endif
DEFINE_BOOL_READONLY(local_off_stack_check,
                     V8_ENABLE_LOCAL_OFF_STACK_CHECK_BOOL,
                     "check for off-stack allocation of v8::Local")

#ifdef V8_ENABLE_FUTURE
#define FUTURE_BOOL true
#else
#define FUTURE_BOOL false
#endif
DEFINE_BOOL(future, FUTURE_BOOL,
            "Implies all staged features that we want to ship in the "
            "not-too-far future")

DEFINE_BOOL(force_emit_interrupt_budget_checks, false,
            "force emit tier-up logic from all non-turbofan code, even if it "
            "is the top enabled tier")
#ifdef V8_ENABLE_MAGLEV
DEFINE_BOOL(maglev, true, "enable the maglev optimizing compiler")
#if !ENABLE_MAGLEV
// Enable Maglev on Future for platforms in which it's not enabled by default
// (eg, Android).
DEFINE_WEAK_IMPLICATION(future, maglev)
#endif
DEFINE_EXPERIMENTAL_FEATURE(
    maglev_future,
    "enable maglev features that we want to ship in the not-too-far future")
DEFINE_IMPLICATION(maglev_future, maglev)
DEFINE_BOOL(
    optimize_on_next_call_optimizes_to_maglev, false,
    "make OptimizeFunctionOnNextCall optimize to maglev instead of turbofan")

// We stress maglev by setting a very low interrupt budget for maglev. This
// way, we still gather *some* feedback before compiling optimized code.
DEFINE_BOOL(stress_maglev, false, "trigger maglev compilation earlier")
DEFINE_IMPLICATION(stress_maglev, maglev)
DEFINE_WEAK_VALUE_IMPLICATION(stress_maglev, invocation_count_for_maglev, 4)

#else
DEFINE_BOOL_READONLY(maglev, false, "enable the maglev optimizing compiler")
DEFINE_BOOL_READONLY(
    maglev_future, false,
    "enable maglev features that we want to ship in the not-too-far future")
DEFINE_BOOL_READONLY(stress_maglev, false, "trigger maglev compilation earlier")
DEFINE_BOOL_READONLY(
    optimize_on_next_call_optimizes_to_maglev, false,
    "make OptimizeFunctionOnNextCall optimize to maglev instead of turbofan")
#endif  //  V8_ENABLE_MAGLEV

DEFINE_BOOL(maglev_inlining, true,
            "enable inlining in the maglev optimizing compiler")
DEFINE_BOOL(maglev_loop_peeling, true,
            "enable loop peeling in the maglev optimizing compiler")
DEFINE_BOOL(maglev_optimistic_peeled_loops, true,
            "enable aggressive optimizations for loops (loop SPeeling) in the "
            "maglev optimizing compiler")
DEFINE_INT(maglev_loop_peeling_max_size, 400,
           "max loop size for loop peeling in the maglev optimizing compiler")
DEFINE_INT(
    maglev_loop_peeling_max_size_cumulative, 900,
    "max cumulative size for loop peeling in the maglev optimizing compiler")
DEFINE_BOOL(maglev_deopt_data_on_background, true,
            "Generate deopt data on background thread")
DEFINE_BOOL(maglev_build_code_on_background, true,
            "Generate code on background thread")
DEFINE_WEAK_IMPLICATION(maglev_build_code_on_background,
                        maglev_deopt_data_on_background)
DEFINE_BOOL(maglev_destroy_on_background, true,
            "Destroy compilation jobs on background thread")
DEFINE_BOOL(maglev_inline_api_calls, false,
            "Inline CallApiCallback builtin into generated code")
DEFINE_EXPERIMENTAL_FEATURE(maglev_licm, "loop invariant code motion")
DEFINE_WEAK_IMPLICATION(maglev_future, maglev_speculative_hoist_phi_untagging)
DEFINE_WEAK_IMPLICATION(maglev_future, maglev_inline_api_calls)
DEFINE_WEAK_IMPLICATION(maglev_future, maglev_escape_analysis)
DEFINE_WEAK_IMPLICATION(maglev_future, maglev_licm)
// This might be too big of a hammer but we must prohibit moving the C++
// trampolines while we are executing a C++ code.
DEFINE_NEG_IMPLICATION(maglev_inline_api_calls, compact_code_space_with_stack)

DEFINE_UINT(
    concurrent_maglev_max_threads, 2,
    "max number of threads that concurrent Maglev can use (0 for unbounded)")
DEFINE_BOOL(concurrent_maglev_high_priority_threads, false,
            "use high priority compiler threads for concurrent Maglev")

DEFINE_INT(
    max_maglev_inline_depth, 1,
    "max depth of functions that Maglev will inline excl. small functions")
DEFINE_INT(
    max_maglev_hard_inline_depth, 10,
    "max depth of functions that Maglev will inline incl. small functions")
DEFINE_INT(max_maglev_inlined_bytecode_size, 460,
           "maximum size of bytecode for a single inlining")
DEFINE_INT(max_maglev_inlined_bytecode_size_cumulative, 920,
           "maximum cumulative size of bytecode considered for inlining excl. "
           "small functions")
DEFINE_INT(max_maglev_inlined_bytecode_size_small, 27,
           "maximum size of bytecode considered for small function inlining")
DEFINE_FLOAT(min_maglev_inlining_frequency, 0.10,
             "minimum frequency for inlining")
DEFINE_WEAK_VALUE_IMPLICATION(turbofan, max_maglev_inline_depth, 1)
DEFINE_WEAK_VALUE_IMPLICATION(turbofan, max_maglev_inlined_bytecode_size, 100)
DEFINE_WEAK_VALUE_IMPLICATION(turbofan,
                              max_maglev_inlined_bytecode_size_cumulative, 920)
DEFINE_WEAK_VALUE_IMPLICATION(turbofan, min_maglev_inlining_frequency, 0.95)
DEFINE_BOOL(maglev_reuse_stack_slots, true,
            "reuse stack slots in the maglev optimizing compiler")
DEFINE_BOOL(maglev_untagged_phis, true,
            "enable phi untagging in the maglev optimizing compiler")
DEFINE_BOOL(maglev_hoist_osr_value_phi_untagging, true,
            "enable phi untagging to hoist untagging of osr values")
DEFINE_EXPERIMENTAL_FEATURE(
    maglev_speculative_hoist_phi_untagging,
    "enable phi untagging to hoist untagging of loop phi inputs (could "
    "still cause deopt loops)")
DEFINE_BOOL(maglev_cse, true, "common subexpression elimination")

DEFINE_STRING(maglev_filter, "*", "optimization filter for the maglev compiler")
DEFINE_STRING(maglev_print_filter, "*",
              "filter for maglev's tracing/printing options")
DEFINE_BOOL(maglev_assert, false, "insert extra assertion in maglev code")
DEFINE_DEBUG_BOOL(maglev_assert_stack_size, true,
                  "insert stack size checks before every IR node")
DEFINE_BOOL(maglev_break_on_entry, false, "insert an int3 on maglev entries")
DEFINE_BOOL(maglev_print_feedback, true,
            "print feedback vector for maglev compiled code")
DEFINE_BOOL(maglev_print_inlined, true,
            "print bytecode / feedback vectors also for inlined code")

DEFINE_BOOL(print_maglev_code, false, "print maglev code")
DEFINE_BOOL(trace_maglev_graph_building, false, "trace maglev graph building")
DEFINE_BOOL(trace_maglev_loop_speeling, false, "trace maglev loop SPeeling")
DEFINE_WEAK_IMPLICATION(trace_maglev_graph_building, trace_maglev_loop_speeling)
DEFINE_BOOL(trace_maglev_inlining, false, "trace maglev inlining")
DEFINE_BOOL(trace_maglev_inlining_verbose, false,
            "trace maglev inlining (verbose)")
DEFINE_IMPLICATION(trace_maglev_inlining_verbose, trace_maglev_inlining)

#ifdef V8_ENABLE_MAGLEV_GRAPH_PRINTER
DEFINE_BOOL(print_maglev_deopt_verbose, false, "print verbose deopt info")
DEFINE_WEAK_IMPLICATION(trace_deopt_verbose, print_maglev_deopt_verbose)
DEFINE_BOOL(print_maglev_graph, false, "print the final maglev graph")
DEFINE_BOOL(print_maglev_graphs, false, "print maglev graph across all phases")
DEFINE_BOOL(trace_maglev_phi_untagging, false, "trace maglev phi untagging")
DEFINE_BOOL(trace_maglev_regalloc, false, "trace maglev register allocation")
#else
DEFINE_BOOL_READONLY(print_maglev_deopt_verbose, false,
                     "print verbose deopt info")
DEFINE_BOOL_READONLY(print_maglev_graph, false, "print the final maglev graph")
DEFINE_BOOL_READONLY(print_maglev_graphs, false,
                     "print maglev graph across all phases")
DEFINE_BOOL_READONLY(trace_maglev_phi_untagging, false,
                     "trace maglev phi untagging")
DEFINE_BOOL_READONLY(trace_maglev_regalloc, false,
                     "trace maglev register allocation")
#endif  // V8_ENABLE_MAGLEV_GRAPH_PRINTER

DEFINE_BOOL(maglev_stats, false, "print Maglev statistics")
DEFINE_BOOL(maglev_stats_nvp, false,
            "print Maglev statistics in machine-readable format")

// TODO(v8:7700): Remove once stable.
DEFINE_BOOL(maglev_function_context_specialization, true,
            "enable function context specialization in maglev")

DEFINE_BOOL(maglev_skip_migration_check_for_polymorphic_access, false,
            "skip generating a migration check when some maps of polymorpic "
            "property access are migration targets")

#ifdef V8_ENABLE_SPARKPLUG
DEFINE_WEAK_IMPLICATION(future, flush_baseline_code)
#endif

DEFINE_BOOL(
    enable_enumerated_keyed_access_bytecode, true,
    "enable generating GetEnumeratedKeyedProperty bytecode for keyed access")

DEFINE_BOOL_READONLY(dict_property_const_tracking,
                     V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                     "Use const tracking on dictionary properties")

DEFINE_BOOL(const_tracking_let, true,
            "Use const tracking on top-level `let` variables")

DEFINE_BOOL(script_context_mutable_heap_number, false,
            "Use mutable heap numbers in script contexts")
DEFINE_WEAK_IMPLICATION(future, script_context_mutable_heap_number)

DEFINE_BOOL(empty_context_extension_dep, true,
            "Use compilation dependency to avoid dynamic checks for "
            "non-empty context extensions")

DEFINE_UINT(max_opt, 999,
            "Set the maximal optimisation tier: "
            "> 3 == any, 0 == ignition/interpreter, 1 == sparkplug/baseline, "
            "2 == maglev, 3 == turbofan")

#ifdef V8_ENABLE_TURBOFAN
DEFINE_WEAK_VALUE_IMPLICATION(max_opt < 3, turbofan, false)
#endif  // V8_ENABLE_TURBOFAN
#ifdef V8_ENABLE_MAGLEV
DEFINE_WEAK_VALUE_IMPLICATION(max_opt < 2, maglev, false)
#endif  // V8_ENABLE_MAGLEV
#ifdef V8_ENABLE_SPARKPLUG
DEFINE_WEAK_VALUE_IMPLICATION(max_opt < 1, sparkplug, false)
#endif  // V8_ENABLE_SPARKPLUG

// Flags to override efficiency and battery saver mode settings for debugging
// and testing.
DEFINE_MAYBE_BOOL(efficiency_mode,
                  "Forces efficiency mode on or off, disregarding any dynamic "
                  "signals. Efficiency mode is optimized for situations with "
                  "no latency requirements and uses fewer threads.")
DEFINE_MAYBE_BOOL(
    battery_saver_mode,
    "Forces battery saver mode on or off, disregarding any dynamic signals. "
    "Battery saver tries to conserve overal cpu cycles spent.")

// Flags to experiment with the new efficiency mode
DEFINE_BOOL(efficiency_mode_for_tiering_heuristics, true,
            "Use efficiency mode in tiering heuristics.")
DEFINE_BOOL(efficiency_mode_disable_turbofan, false,
            "Defer tier-up to turbofan while in efficiency mode.")
DEFINE_INT(efficiency_mode_delay_turbofan, 15000,
           "Delay tier-up to turbofan to a certain invocation count while in "
           "efficiency mode.")

// Flag to select wasm trace mark type
DEFINE_STRING(
    wasm_trace_native, nullptr,
    "Select which native code sequence to use for wasm trace instruction: "
    "default or cpuid")

#ifdef V8_JITLESS
#define V8_JITLESS_BOOL true
DEFINE_BOOL_READONLY(jitless, true,
                     "Disable runtime allocation of executable memory.")
#else
#define V8_JITLESS_BOOL false
DEFINE_BOOL(jitless, V8_LITE_MODE_BOOL,
            "Disable runtime allocation of executable memory.")
#endif  // V8_JITLESS

// Jitless V8 has a few implications:
// Field type tracking is only used by TurboFan.
DEFINE_NEG_IMPLICATION(jitless, track_field_types)
// No code generation at runtime.
DEFINE_IMPLICATION(jitless, regexp_interpret_all)
DEFINE_NEG_IMPLICATION(jitless, turbofan)
#ifdef V8_ENABLE_SPARKPLUG
DEFINE_NEG_IMPLICATION(jitless, sparkplug)
DEFINE_NEG_IMPLICATION(jitless, always_sparkplug)
#endif  // V8_ENABLE_SPARKPLUG
#ifdef V8_ENABLE_MAGLEV
DEFINE_NEG_IMPLICATION(jitless, maglev)
#endif  // V8_ENABLE_MAGLEV
// Doesn't work without an executable code space.
DEFINE_NEG_IMPLICATION(jitless, interpreted_frames_native_stack)

DEFINE_BOOL(
    disable_optimizing_compilers, false,
    "Disable all optimizing compilers while leaving baseline compilers enabled")
// Disable all optimizing JavaScript compilers.
// JavaScript code can execute either in Ign
"""


```