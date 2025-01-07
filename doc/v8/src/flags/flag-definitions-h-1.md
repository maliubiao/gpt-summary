Response:
The user wants a summary of the functionalities defined in the provided C++ header file `v8/src/flags/flag-definitions.h`. This is the *second* part of a larger file. The summary should consider:

1. **Core Functionality:** What are the main categories of flags defined in this section?
2. **`.tq` Extension:**  The file does *not* end with `.tq`, so it's not a Torque file.
3. **JavaScript Relevance with Examples:** If a flag impacts JavaScript behavior, provide a JavaScript example.
4. **Code Logic Inference (Hypothetical Input/Output):** Identify flags that control program behavior and illustrate their impact with hypothetical inputs and outputs.
5. **Common User Programming Errors:** If a flag relates to potential programming errors, explain the error and how the flag might help or relate to it.

**Mental Walkthrough:**

*   **Scan for `DEFINE_*` macros:**  These are the core elements defining the flags. Group them by related concepts.
*   **Identify key areas:**  The current section seems to focus on compiler optimizations (TurboFan, Sparkplug, Maglev), memory management (allocation site tracking, page promotion), and tiering (transitions between different compilers).
*   **`.tq` check:** This is straightforward. The filename doesn't match.
*   **JavaScript examples:** This requires understanding how the flags affect V8's execution of JavaScript. Focus on flags that control optimization levels, which directly impact performance characteristics observable in JavaScript.
*   **Logic Inference:** Look for flags that act as switches or have implications on other flags. Consider how changing a flag might alter the compilation or execution path.
*   **Programming errors:** Think about how some flags might expose or mitigate common JavaScript performance issues or type errors.

**Constraint Checklist & Confidence Score:**

1. List functionality? Yes.
2. `.tq` check? Yes.
3. JavaScript relation? Yes.
4. JavaScript examples? Yes.
5. Code logic inference? Yes.
6. Hypothetical input/output? Yes.
7. Common errors? Yes.
8. Illustrative examples? Yes (within the constraints).
9. Part 2 of 5? Yes, focus on this section's content.
10.归纳功能? Yes, synthesize the information.

Confidence Score: 5/5 - I am confident I can address all requirements.

**Overall Strategy:**

1. Start by stating the file is not a Torque file.
2. Categorize the flags into logical groups based on their names and descriptions.
3. For each significant category, explain its purpose and provide JavaScript examples where applicable. Focus on observable effects like execution speed or triggering optimizations.
4. For flags with implications or dependencies, illustrate the logic with hypothetical scenarios (e.g., if `--disable-optimizing-compilers` is set, what other flags are affected?).
5. Highlight how certain flags might relate to debugging or understanding performance issues in JavaScript.
6. Conclude with a concise summary of the overall functionality covered in this section of the header file.

Strategizing complete. Proceeding with response generation.
这是 `v8/src/flags/flag-definitions.h` 文件的第二部分，它定义了 V8 引擎的命令行标志（flags）。这些标志用于配置 V8 引擎的各种行为，尤其是在编译和优化方面。

**功能归纳:**

这部分代码主要关注以下几个方面的功能配置：

1. **编译优化控制:**  定义了控制不同优化编译器（如 TurboFan, Turboshaft, Maglev, Sparkplug）启用和禁用的标志。以及它们之间的依赖关系和互斥关系。
2. **WebAssembly 支持:**  定义了与 WebAssembly 编译和优化相关的标志，如禁用优化 Wasm 编译器、禁用 asm.js 到 Wasm 的转换等。
3. **类型跟踪与断言:**  定义了用于类型跟踪和运行时类型断言的标志，主要用于测试类型系统。
4. **代码依赖追踪:** 定义了追踪代码编译依赖的标志。
5. **内存管理与垃圾回收 (GC) 相关:**  定义了与内存保护键、分配站点跟踪、页提升策略、新生代大小控制等相关的标志，这些都影响着 V8 的内存管理和垃圾回收行为。
6. **字符串优化:** 定义了与字符串切片和字符串内部化相关的标志。
7. **分层编译 (Tiering):**  定义了控制不同编译层级（Ignition, Sparkplug, Maglev, TurboFan）之间切换的阈值，例如函数被调用多少次后会触发优化。
8. **JIT Fuzzing:**  定义了用于 JIT 模糊测试的标志，可以降低编译和优化的阈值，以便更快地触发不同的 JIT 层级。
9. **内联缓存 (IC) 和反馈向量:** 定义了与内联缓存和反馈向量分配相关的标志。
10. **Ignition 解释器:** 定义了控制 Ignition 解释器行为的标志，例如字节码省略、寄存器等价优化、源码位置处理等。
11. **Sparkplug 基线编译器:** 定义了控制 Sparkplug 基线编译器启用、并发编译、批量编译等行为的标志。
12. **共享堆:**  定义了与共享堆和共享字符串表相关的标志，用于在多个 Isolate 之间共享数据。
13. **并发重编译:**  定义了控制并发重编译行为的标志，允许在后台线程进行函数优化。
14. **编译器压力测试:** 定义了用于压力测试编译器的标志，例如设置运行次数、强制去优化等。
15. **TurboFan 优化编译器:** 定义了大量与 TurboFan 优化编译器相关的标志，包括启用/禁用、过滤优化函数、追踪 IR 生成、图输出、类型跟踪、调度、内联、OSR（On-Stack Replacement）等。
16. **Turboshaft 优化编译器:**  定义了启用 Turboshaft 的标志。
17. **Maglev 优化编译器:** 定义了与 Maglev 优化编译器相关的标志，包括调用计数阈值和 OSR。

**关于文件类型和 Torque:**

由于提供的代码是 `.h` 文件，而不是 `.tq` 文件，因此它不是 V8 Torque 源代码。`.h` 文件是 C++ 头文件。

**与 JavaScript 功能的关系及示例:**

这部分定义的标志直接影响 V8 引擎执行 JavaScript 代码的方式，尤其是在性能方面。以下是一些例子：

*   **`--turbofan` (启用/禁用 TurboFan):** TurboFan 是 V8 的主要优化编译器。禁用它可以显著降低 JavaScript 代码的执行速度，但有时可以用于调试。

    ```javascript
    // 假设有如下 JavaScript 代码
    function add(a, b) {
      return a + b;
    }

    for (let i = 0; i < 10000; i++) {
      add(i, i + 1);
    }
    ```

    *   如果 `--turbofan` 启用（默认情况），V8 会将 `add` 函数编译成高度优化的机器码，循环执行会非常快。
    *   如果 `--noturbo_fan` 启用，V8 可能只会使用 Ignition 解释器或 Sparkplug 基线编译器，循环执行速度会慢很多。

*   **`--sparkplug` (启用/禁用 Sparkplug):** Sparkplug 是一个轻量级的基线编译器，比解释器快，但不如 TurboFan 优化。

    ```javascript
    function multiply(x, y) {
      return x * y;
    }

    for (let j = 0; j < 500; j++) {
      multiply(j, j * 2);
    }
    ```

    *   如果 `--sparkplug` 启用，`multiply` 函数可能会被 Sparkplug 编译，提高执行效率。
    *   如果 `--nosparkplug` 启用，`multiply` 函数可能只会被 Ignition 解释执行。

*   **`--use_ic` (启用/禁用内联缓存):** 内联缓存是 V8 优化属性访问的关键技术。禁用它会导致属性访问变慢。

    ```javascript
    const obj = { value: 10 };

    for (let k = 0; k < 1000; k++) {
      obj.value; // 访问对象属性
    }
    ```

    *   如果 `--use_ic` 启用，V8 会缓存 `obj.value` 的访问路径，后续访问会更快。
    *   如果 `--nouse_ic` 启用，每次访问 `obj.value` 都需要进行查找，效率较低。

*   **分层编译相关的标志 (如 `--invocation_count_for_turbofan`):**  这些标志控制函数需要被调用多少次才会触发 TurboFan 优化。

    ```javascript
    function complexCalculation(n) {
      let result = 0;
      for (let i = 0; i < n; i++) {
        result += Math.sqrt(i) * Math.random();
      }
      return result;
    }

    // 如果 --invocation_count_for_turbofan 设置为较低的值，
    // 那么 complexCalculation 函数在被调用几次后就可能被 TurboFan 优化。
    for (let m = 0; m < 10; m++) {
      complexCalculation(1000);
    }
    ```

**代码逻辑推理 (假设输入与输出):**

很多标志之间存在依赖关系（implication）和互斥关系（negation implication）。

*   **`DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, turbofan)`:**  这意味着如果设置了 `--disable-optimizing-compilers`，那么 `--turbofan` 也会被隐式地设置为 false (即禁用)。

    *   **假设输入:**  命令行参数 `--disable-optimizing-compilers`
    *   **输出:** V8 内部标志 `turbofan` 的值为 `false`。

*   **`DEFINE_IMPLICATION(trace_compilation_dependencies, trace_deopt_verbose)`:**  这意味着如果设置了 `--trace-compilation-dependencies`，那么 `--trace-deopt-verbose` 也会被隐式地设置为 true。

    *   **假设输入:** 命令行参数 `--trace-compilation-dependencies`
    *   **输出:** V8 内部标志 `trace_deopt_verbose` 的值为 `true`。

**用户常见的编程错误:**

某些标志与帮助识别或缓解常见编程错误有关：

*   **`--assert_types` 和 `--turboshaft_assert_types`:** 这些标志会在运行时生成类型断言，可以帮助开发者发现类型相关的错误。

    ```javascript
    function addNumbers(a, b) {
      return a + b;
    }

    // 常见错误：传递了非数字类型的参数
    addNumbers("hello", 5); // 在启用类型断言的情况下可能会抛出错误
    ```

    如果启用了 `--assert_types` 或 `--turboshaft_assert_types`，V8 可能会在运行时检查参数类型，如果类型不符合预期，可能会抛出错误，从而帮助开发者尽早发现这类类型错误。

**总结这部分的功能:**

这部分 `flag-definitions.h` 文件主要负责定义和配置 V8 引擎在编译、优化和内存管理等方面的行为。它提供了大量的命令行标志，允许开发者和 V8 开发者精细地控制引擎的内部工作方式，用于性能调优、调试、实验性功能开启以及压力测试等目的。 这些标志直接影响 JavaScript 代码的执行效率和行为。

Prompt: 
```
这是目录为v8/src/flags/flag-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/flags/flag-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
ition or Sparkplug.
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, turbofan)
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, turboshaft)
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, maglev)
#if V8_ENABLE_WEBASSEMBLY
// Disable optimizing Wasm compilers. Wasm code must execute with Liftoff.
DEFINE_IMPLICATION(disable_optimizing_compilers, liftoff)
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, wasm_tier_up)
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, wasm_dynamic_tiering)
// Disable translation of asm.js to Wasm
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, validate_asm)
#endif  // V8_ENABLE_WEBASSEMBLY
// Field type tracking is only used by TurboFan, so can be disabled.
DEFINE_NEG_IMPLICATION(disable_optimizing_compilers, track_field_types)

DEFINE_BOOL(memory_protection_keys, true,
            "protect code memory with PKU if available")

DEFINE_BOOL(assert_types, false,
            "generate runtime type assertions to test the typer")
// TODO(tebbi): Support allocating types from background thread.
DEFINE_NEG_IMPLICATION(assert_types, concurrent_recompilation)
DEFINE_EXPERIMENTAL_FEATURE(
    turboshaft_assert_types,
    "generate runtime type assertions to test the turboshaft type system")
DEFINE_NEG_IMPLICATION(turboshaft_assert_types, concurrent_recompilation)

// Enable verification of SimplifiedLowering in debug builds.
DEFINE_BOOL(verify_simplified_lowering, DEBUG_BOOL,
            "verify graph generated by simplified lowering")

DEFINE_BOOL(trace_compilation_dependencies, false, "trace code dependencies")
// Depend on --trace-deopt-verbose for reporting dependency invalidations.
DEFINE_IMPLICATION(trace_compilation_dependencies, trace_deopt_verbose)

#ifdef V8_ALLOCATION_SITE_TRACKING
#define V8_ALLOCATION_SITE_TRACKING_BOOL true
#else
#define V8_ALLOCATION_SITE_TRACKING_BOOL false
#endif

DEFINE_BOOL_READONLY(allocation_site_tracking, V8_ALLOCATION_SITE_TRACKING_BOOL,
                     "Enable allocation site tracking")
DEFINE_NEG_NEG_IMPLICATION(allocation_site_tracking,
                           allocation_site_pretenuring)

// Flags for experimental implementation features.
DEFINE_BOOL(allocation_site_pretenuring, true,
            "pretenure with allocation sites")
DEFINE_BOOL(page_promotion, true, "promote pages based on utilization")
DEFINE_INT(page_promotion_threshold, 70,
           "min percentage of live bytes on a page to enable fast evacuation "
           "in full GCs")
DEFINE_INT(minor_ms_page_promotion_threshold, 50,
           "min percentage of live bytes on a page to enable fast evacuation "
           "in MinorMS")
DEFINE_INT(minor_ms_page_promotion_max_lab_threshold, 30,
           "max percentage of labs out of a page to still be considered for "
           "page promotion")
DEFINE_UINT(minor_ms_max_page_age, 4,
            "max age for a page after which it is force promoted to old space")
DEFINE_UINT(minor_ms_max_new_space_capacity_mb, 72,
            "max new space capacity in MBs when using MinorMS. When pointer "
            "compression is disabled, twice the capacity is used.")

#if defined(ANDROID)
#define DEFAULT_SCAVENGER_MAX_NEW_SPACE_CAPACITY_MB 8
#else
#define DEFAULT_SCAVENGER_MAX_NEW_SPACE_CAPACITY_MB 32
#endif
DEFINE_UINT(scavenger_max_new_space_capacity_mb,
            DEFAULT_SCAVENGER_MAX_NEW_SPACE_CAPACITY_MB,
            "max new space capacity in MBs when using Scavenger. When pointer "
            "compression is disabled, twice the capacity is used.")
#undef DEFAULT_SCAVENGER_MAX_NEW_SPACE_CAPACITY_MB

DEFINE_BOOL(trace_page_promotions, false, "trace page promotion decisions")
DEFINE_BOOL(trace_pretenuring, false,
            "trace pretenuring decisions of HAllocate instructions")
DEFINE_BOOL(trace_pretenuring_statistics, false,
            "trace allocation site pretenuring statistics")
DEFINE_BOOL(track_field_types, true, "track field types")
DEFINE_BOOL(trace_block_coverage, false,
            "trace collected block coverage information")
DEFINE_BOOL(trace_protector_invalidation, false,
            "trace protector cell invalidations")
DEFINE_BOOL(decommit_pooled_pages, true,
            "decommit, rather than discard pooled pages")
DEFINE_BOOL(
    zero_unused_memory, false,
    "Zero unused memory (except for memory which was discarded) on memory "
    "reducing GCs.")

#ifdef V8_MINORMS_STRING_SHORTCUTTING
DEFINE_BOOL(minor_ms_shortcut_strings, false,
            "short cut strings during marking")
// String shortcutting currently doesn't work with concurrent marking.
DEFINE_NEG_IMPLICATION(minor_ms_shortcut_strings, concurrent_minor_ms_marking)
#else
DEFINE_BOOL_READONLY(minor_ms_shortcut_strings, false,
                     "short cut strings during marking")
#endif

DEFINE_EXPERIMENTAL_FEATURE(feedback_normalization,
                            "feed back normalization to constructors")
// TODO(jkummerow): This currently adds too much load on the stub cache.
DEFINE_BOOL_READONLY(internalize_on_the_fly, true,
                     "internalize string keys for generic keyed ICs on the fly")

// Flag for sealed, frozen elements kind instead of dictionary elements kind
DEFINE_BOOL_READONLY(enable_sealed_frozen_elements_kind, true,
                     "Enable sealed, frozen elements kind")

// Flags for data representation optimizations
DEFINE_BOOL(unbox_double_arrays, true, "automatically unbox arrays of doubles")
DEFINE_BOOL_READONLY(string_slices, true, "use string slices")

// Tiering: Sparkplug / feedback vector allocation.
DEFINE_INT(invocation_count_for_feedback_allocation, 8,
           "invocation count required for allocating feedback vectors")

// Tiering: Maglev.
#if defined(ANDROID)
DEFINE_INT(invocation_count_for_maglev, 1000,
           "invocation count required for optimizing with Maglev")
#else
DEFINE_INT(invocation_count_for_maglev, 400,
           "invocation count required for optimizing with Maglev")
#endif  // ANDROID
DEFINE_INT(invocation_count_for_maglev_osr, 100,
           "invocation count required for maglev OSR")
DEFINE_BOOL(osr_from_maglev, false,
            "whether we try to OSR to Turbofan from OSR'd Maglev")
DEFINE_FLOAT(
    osr_from_maglev_interrupt_scale_factor, 0.8,
    "Scale interrupt budget reduction for OSR from Maglev vs. OSR to Maglev")
DEFINE_BOOL(always_osr_from_maglev, false,
            "whether we try to OSR to Turbofan from any Maglev")
DEFINE_VALUE_IMPLICATION(always_osr_from_maglev, osr_from_maglev, true)

// Tiering: Turbofan.
DEFINE_INT(invocation_count_for_turbofan, 3000,
           "invocation count required for optimizing with TurboFan")
DEFINE_INT(invocation_count_for_osr, 500, "invocation count required for OSR")
DEFINE_INT(osr_to_tierup, 1,
           "number to decrease the invocation budget by when we follow OSR")
DEFINE_INT(minimum_invocations_after_ic_update, 500,
           "How long to minimally wait after IC update before tier up")
DEFINE_INT(minimum_invocations_before_optimization, 2,
           "Minimum number of invocations we need before non-OSR optimization")

// Tiering: JIT fuzzing.
//
// When --jit-fuzzing is enabled, various tiering related thresholds are
// lowered so that the different JIT tiers are reached roughly within a few
// dozen executions of the code instead of a few hundred or thousand. As a rule
// of thumb, aiming for things to happen 5x to 10x sooner in this mode than
// they otherwise would is probably not unreasonable.
DEFINE_BOOL(jit_fuzzing, false,
            "Set JIT tiering thresholds suitable for JIT fuzzing")
// Tier up to Sparkplug should happen after a handful o executions in ignition.
DEFINE_NEG_IMPLICATION(jit_fuzzing, lazy_feedback_allocation)
DEFINE_NEG_IMPLICATION(jit_fuzzing, baseline_batch_compilation)
// Tier up to Maglev should happen soon afterwards.
DEFINE_VALUE_IMPLICATION(jit_fuzzing, invocation_count_for_maglev, 10)
// And tier up to Turbofan should happen after a couple dozen or so executions.
DEFINE_VALUE_IMPLICATION(jit_fuzzing, invocation_count_for_turbofan, 20)
// Additionally, some other JIT-related thresholds should also be lowered.
DEFINE_VALUE_IMPLICATION(jit_fuzzing, invocation_count_for_osr, 5)
DEFINE_VALUE_IMPLICATION(jit_fuzzing, invocation_count_for_maglev_osr, 1)
DEFINE_VALUE_IMPLICATION(jit_fuzzing, minimum_invocations_after_ic_update, 5)

#if V8_ENABLE_WEBASSEMBLY
// Wasm tiering thresholds.
DEFINE_VALUE_IMPLICATION(jit_fuzzing, wasm_wrapper_tiering_budget, 1)
DEFINE_VALUE_IMPLICATION(jit_fuzzing, wasm_tiering_budget, 1)
DEFINE_IMPLICATION(jit_fuzzing, wasm_inlining_ignore_call_counts)
#endif  // V8_ENABLE_WEBASSEMBLY

DEFINE_BOOL(use_std_math_pow, false,
            "use std::pow instead of our custom implementation")

// Flags for inline caching and feedback vectors.
DEFINE_BOOL(use_ic, true, "use inline caching")
DEFINE_BOOL(lazy_feedback_allocation, true, "Allocate feedback vectors lazily")
DEFINE_BOOL(stress_ic, false, "exercise interesting paths in ICs more often")

// Flags for Ignition.
DEFINE_BOOL(ignition_elide_noneffectful_bytecodes, true,
            "elide bytecodes which won't have any external effect")
DEFINE_BOOL(ignition_reo, true, "use ignition register equivalence optimizer")
DEFINE_BOOL(ignition_filter_expression_positions, true,
            "filter expression positions before the bytecode pipeline")
DEFINE_BOOL(ignition_share_named_property_feedback, true,
            "share feedback slots when loading the same named property from "
            "the same object")
DEFINE_BOOL(ignition_elide_redundant_tdz_checks, true,
            "elide TDZ checks dominated by other TDZ checks")
DEFINE_BOOL(print_bytecode, false,
            "print bytecode generated by ignition interpreter")
DEFINE_BOOL(enable_lazy_source_positions, V8_LAZY_SOURCE_POSITIONS_BOOL,
            "skip generating source positions during initial compile but "
            "regenerate when actually required")
DEFINE_BOOL(stress_lazy_source_positions, false,
            "collect lazy source positions immediately after lazy compile")
DEFINE_STRING(print_bytecode_filter, "*",
              "filter for selecting which functions to print bytecode")
DEFINE_BOOL(omit_default_ctors, true, "omit calling default ctors in bytecode")
#ifdef V8_TRACE_UNOPTIMIZED
DEFINE_BOOL(trace_unoptimized, false,
            "trace the bytecodes executed by all unoptimized execution")
DEFINE_BOOL(trace_ignition, false,
            "trace the bytecodes executed by the ignition interpreter")
DEFINE_BOOL(trace_baseline_exec, false,
            "trace the bytecodes executed by the baseline code")
DEFINE_WEAK_IMPLICATION(trace_unoptimized, trace_ignition)
DEFINE_WEAK_IMPLICATION(trace_unoptimized, trace_baseline_exec)
#endif
#ifdef V8_TRACE_FEEDBACK_UPDATES
DEFINE_BOOL(
    trace_feedback_updates, false,
    "trace updates to feedback vectors during ignition interpreter execution.")
#endif
DEFINE_BOOL(trace_ignition_codegen, false,
            "trace the codegen of ignition interpreter bytecode handlers")
DEFINE_STRING(
    trace_ignition_dispatches_output_file, nullptr,
    "write the bytecode handler dispatch table to the specified file (d8 only) "
    "(requires building with v8_enable_ignition_dispatch_counting)")

DEFINE_BOOL(trace_track_allocation_sites, false,
            "trace the tracking of allocation sites")
DEFINE_BOOL(trace_migration, false, "trace object migration")
DEFINE_BOOL(trace_generalization, false, "trace map generalization")

DEFINE_BOOL(reuse_scope_infos, true, "reuse scope infos from previous compiles")

DEFINE_IMPLICATION(fuzzing, reuse_scope_infos)

// Flags for Sparkplug
#undef FLAG
#if V8_ENABLE_SPARKPLUG
#define FLAG FLAG_FULL
#else
#define FLAG FLAG_READONLY
#endif
DEFINE_BOOL(sparkplug, ENABLE_SPARKPLUG_BY_DEFAULT,
            "enable Sparkplug baseline compiler")
DEFINE_BOOL(always_sparkplug, false, "directly tier up to Sparkplug code")
#if V8_ENABLE_SPARKPLUG
DEFINE_IMPLICATION(always_sparkplug, sparkplug)
DEFINE_BOOL(baseline_batch_compilation, true, "batch compile Sparkplug code")
#if defined(V8_OS_DARWIN) && defined(V8_HOST_ARCH_ARM64) && \
    !V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT &&               \
    !V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT
// M1 requires W^X.
DEFINE_BOOL_READONLY(concurrent_sparkplug, false,
                     "compile Sparkplug code in a background thread")
#else
DEFINE_BOOL(concurrent_sparkplug, ENABLE_SPARKPLUG_BY_DEFAULT,
            "compile Sparkplug code in a background thread")
DEFINE_WEAK_IMPLICATION(future, concurrent_sparkplug)
DEFINE_NEG_IMPLICATION(predictable, concurrent_sparkplug)
DEFINE_NEG_IMPLICATION(single_threaded, concurrent_sparkplug)
DEFINE_NEG_IMPLICATION(jitless, concurrent_sparkplug)
#endif
DEFINE_UINT(
    concurrent_sparkplug_max_threads, 1,
    "max number of threads that concurrent Sparkplug can use (0 for unbounded)")
DEFINE_BOOL(concurrent_sparkplug_high_priority_threads, false,
            "use high priority compiler threads for concurrent Sparkplug")
#else
DEFINE_BOOL(baseline_batch_compilation, false, "batch compile Sparkplug code")
DEFINE_BOOL_READONLY(concurrent_sparkplug, false,
                     "compile Sparkplug code in a background thread")
#endif
DEFINE_STRING(sparkplug_filter, "*", "filter for Sparkplug baseline compiler")
DEFINE_BOOL(sparkplug_needs_short_builtins, false,
            "only enable Sparkplug baseline compiler when "
            "--short-builtin-calls are also enabled")
DEFINE_INT(baseline_batch_compilation_threshold, 4 * KB,
           "the estimated instruction size of a batch to trigger compilation")
DEFINE_BOOL(trace_baseline, false, "trace baseline compilation")
DEFINE_BOOL(trace_baseline_batch_compilation, false,
            "trace baseline batch compilation")
DEFINE_WEAK_IMPLICATION(trace_baseline, trace_baseline_batch_compilation)
#undef FLAG
#define FLAG FLAG_FULL

// Internalize into a shared string table in the shared isolate
DEFINE_BOOL(shared_string_table, false, "internalize strings into shared table")
DEFINE_IMPLICATION(harmony_struct, shared_string_table)
DEFINE_IMPLICATION(shared_string_table, shared_heap)
DEFINE_BOOL_READONLY(always_use_string_forwarding_table, false,
                     "use string forwarding table instead of thin strings for "
                     "all strings (experimental)")
DEFINE_IMPLICATION(always_use_string_forwarding_table, experimental)
// With --always-use-string-forwarding-table, we can have young generation
// string entries in the forwarding table, requiring table updates when these
// strings get promoted to old space. Parallel GCs in client isolates
// (enabled by --shared-string-table) are not supported using a single shared
// forwarding table.
DEFINE_NEG_IMPLICATION(shared_string_table, always_use_string_forwarding_table)

DEFINE_BOOL(transition_strings_during_gc_with_stack, false,
            "Transition strings during a full GC with stack")

DEFINE_SIZE_T(initial_shared_heap_size, 0,
              "initial size of the shared heap (in Mbytes); "
              "other heap size flags (e.g. initial_heap_size) take precedence")
DEFINE_SIZE_T(
    max_shared_heap_size, 0,
    "max size of the shared heap (in Mbytes); "
    "other heap size flags (e.g. max_shared_heap_size) take precedence")

// Flags for concurrent recompilation.
DEFINE_BOOL(concurrent_recompilation, true,
            "optimizing hot functions asynchronously on a separate thread")
DEFINE_BOOL(trace_concurrent_recompilation, false,
            "track concurrent recompilation")
DEFINE_INT(concurrent_recompilation_queue_length, 8,
           "the length of the concurrent compilation queue")
DEFINE_INT(concurrent_recompilation_delay, 0,
           "artificial compilation delay in ms")
DEFINE_BOOL(concurrent_recompilation_front_running, true,
            "move compile jobs to the front if recompilation is requested "
            "multiple times")
DEFINE_UINT(
    concurrent_turbofan_max_threads, 4,
    "max number of threads that concurrent Turbofan can use (0 for unbounded)")
DEFINE_BOOL(
    stress_concurrent_inlining, false,
    "create additional concurrent optimization jobs but throw away result")
DEFINE_IMPLICATION(stress_concurrent_inlining, concurrent_recompilation)
DEFINE_IMPLICATION(stress_concurrent_inlining, turbofan)
DEFINE_NEG_IMPLICATION(stress_concurrent_inlining, lazy_feedback_allocation)
DEFINE_WEAK_VALUE_IMPLICATION(stress_concurrent_inlining,
                              invocation_count_for_turbofan, 150)
DEFINE_BOOL(maglev_overwrite_budget, false,
            "whether maglev resets the interrupt budget")
DEFINE_WEAK_IMPLICATION(maglev, maglev_overwrite_budget)
DEFINE_NEG_IMPLICATION(stress_concurrent_inlining, maglev_overwrite_budget)
DEFINE_WEAK_VALUE_IMPLICATION(maglev_overwrite_budget,
                              invocation_count_for_turbofan, 6000)
DEFINE_BOOL(maglev_overwrite_osr_budget, false,
            "whether maglev resets the OSR interrupt budget")
DEFINE_WEAK_IMPLICATION(maglev_osr, maglev_overwrite_osr_budget)
DEFINE_NEG_IMPLICATION(stress_concurrent_inlining, maglev_overwrite_osr_budget)
DEFINE_WEAK_VALUE_IMPLICATION(maglev_overwrite_osr_budget,
                              invocation_count_for_osr, 800)
DEFINE_BOOL(stress_concurrent_inlining_attach_code, false,
            "create additional concurrent optimization jobs")
DEFINE_IMPLICATION(stress_concurrent_inlining_attach_code,
                   stress_concurrent_inlining)
DEFINE_INT(max_serializer_nesting, 25,
           "maximum levels for nesting child serializers")
DEFINE_BOOL(trace_heap_broker_verbose, false,
            "trace the heap broker verbosely (all reports)")
DEFINE_BOOL(trace_heap_broker, false,
            "trace the heap broker (reports on missing data only)")
DEFINE_IMPLICATION(trace_heap_broker_verbose, trace_heap_broker)
DEFINE_IMPLICATION(trace_heap_broker, trace_pending_allocations)

// Flags for stress-testing the compiler.
DEFINE_INT(stress_runs, 0, "number of stress runs")
DEFINE_INT(deopt_every_n_times, 0,
           "deoptimize every n times a deopt point is passed")
DEFINE_BOOL(print_deopt_stress, false, "print number of possible deopt points")

// Flags for TurboFan.
#ifdef V8_ENABLE_TURBOFAN
#define V8_ENABLE_TURBOFAN_BOOL true
DEFINE_BOOL(turbofan, true, "use the Turbofan optimizing compiler")
// TODO(leszeks): Temporary alias until we make sure all our infra is passing
// --turbofan instead of --opt.
DEFINE_ALIAS_BOOL(opt, turbofan)
#else
#define V8_ENABLE_TURBOFAN_BOOL false
DEFINE_BOOL_READONLY(turbofan, false, "use the Turbofan optimizing compiler")
DEFINE_BOOL_READONLY(opt, false, "use the Turbofan optimizing compiler")
#endif  // V8_ENABLE_TURBOFAN

DEFINE_BOOL(
    stress_turbo_late_spilling, false,
    "optimize placement of all spill instructions, not just loop-top phis")

DEFINE_BOOL(turbo_wasm_address_reassociation, true,
            "refactor address components for immediate indexing")

DEFINE_STRING(turbo_filter, "*", "optimization filter for TurboFan compiler")
DEFINE_BOOL(trace_turbo, false, "trace generated TurboFan IR")
DEFINE_STRING(trace_turbo_path, nullptr,
              "directory to dump generated TurboFan IR to")
DEFINE_STRING(trace_turbo_filter, "*",
              "filter for tracing turbofan compilation")
DEFINE_BOOL(trace_turbo_graph, false, "trace generated TurboFan graphs")
DEFINE_BOOL(trace_turbo_scheduled, false, "trace TurboFan IR with schedule")
DEFINE_IMPLICATION(trace_turbo_scheduled, trace_turbo_graph)
DEFINE_STRING(trace_turbo_file_prefix, "turbo",
              "trace turbo graph to a file with given prefix")
DEFINE_STRING(trace_turbo_cfg_file, nullptr,
              "trace turbo cfg graph (for C1 visualizer) to a given file name")
DEFINE_BOOL(trace_turbo_types, true, "trace TurboFan's types")
DEFINE_BOOL(trace_turbo_scheduler, false, "trace TurboFan's scheduler")
DEFINE_BOOL(trace_turbo_reduction, false, "trace TurboFan's various reducers")
#ifdef V8_ENABLE_SLOW_TRACING
#define DEFINE_SLOW_TRACING_BOOL DEFINE_BOOL
#else
#define DEFINE_SLOW_TRACING_BOOL DEFINE_BOOL_READONLY
#endif  // V8_ENABLE_SLOW_TRACING
DEFINE_SLOW_TRACING_BOOL(trace_turbo_trimming, false,
                         "trace TurboFan's graph trimmer")
DEFINE_SLOW_TRACING_BOOL(trace_turbo_jt, false,
                         "trace TurboFan's jump threading")
DEFINE_SLOW_TRACING_BOOL(trace_turbo_ceq, false,
                         "trace TurboFan's control equivalence")
DEFINE_SLOW_TRACING_BOOL(trace_turbo_loop, false,
                         "trace TurboFan's loop optimizations")
DEFINE_SLOW_TRACING_BOOL(trace_turbo_alloc, false,
                         "trace TurboFan's register allocator")
DEFINE_SLOW_TRACING_BOOL(trace_all_uses, false, "trace all use positions")
DEFINE_SLOW_TRACING_BOOL(trace_representation, false,
                         "trace representation types")
DEFINE_BOOL(
    trace_turbo_stack_accesses, false,
    "trace stack load/store counters for optimized code in run-time (x64 only)")

// When fuzzing and concurrent compilation is enabled, disable Turbofan
// tracing flags since reading/printing heap state is not thread-safe and
// leads to false positives on TSAN bots.
// TODO(chromium:1205289): Teach relevant fuzzers to not pass TF tracing
// flags instead, and remove this section.
DEFINE_BOOL(fuzzing_and_concurrent_recompilation, true,
            "fuzzing && concurrent_recompilation")
DEFINE_NEG_NEG_IMPLICATION(fuzzing, fuzzing_and_concurrent_recompilation)
DEFINE_NEG_NEG_IMPLICATION(concurrent_recompilation,
                           fuzzing_and_concurrent_recompilation)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_graph)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_scheduled)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_reduction)
#ifdef V8_ENABLE_SLOW_TRACING
// If expensive tracing is disabled via a build flag, the following flags
// cannot be disabled (because they are already).
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_trimming)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_jt)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_ceq)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_loop)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_alloc)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_all_uses)
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_representation)
#endif
DEFINE_DISABLE_FLAG_IMPLICATION(fuzzing_and_concurrent_recompilation,
                                trace_turbo_stack_accesses)

DEFINE_BOOL(turbo_verify, DEBUG_BOOL, "verify TurboFan graphs at each phase")
DEFINE_STRING(turbo_verify_machine_graph, nullptr,
              "verify TurboFan machine graph before instruction selection")
#ifdef ENABLE_VERIFY_CSA
DEFINE_BOOL(verify_csa, DEBUG_BOOL,
            "verify TurboFan machine graph of code stubs")
#else
// Define the flag as read-only-false so that code still compiles even in the
// non-ENABLE_VERIFY_CSA configuration.
DEFINE_BOOL_READONLY(verify_csa, false,
                     "verify TurboFan machine graph of code stubs")
#endif  // ENABLE_VERIFY_CSA
DEFINE_BOOL(trace_verify_csa, false, "trace code stubs verification")
DEFINE_STRING(csa_trap_on_node, nullptr,
              "trigger break point when a node with given id is created in "
              "given stub. The format is: StubName,NodeId")
DEFINE_BOOL_READONLY(fixed_array_bounds_checks, true,
                     "enable FixedArray bounds checks")
DEFINE_BOOL(turbo_stats, false, "print TurboFan statistics")
DEFINE_BOOL(turbo_stats_nvp, false,
            "print TurboFan statistics in machine-readable format")
DEFINE_BOOL(turbo_stats_wasm, false,
            "print TurboFan statistics of wasm compilations")
DEFINE_BOOL(turbo_splitting, true, "split nodes during scheduling in TurboFan")
DEFINE_BOOL(turbo_inlining, true, "enable inlining in TurboFan")
DEFINE_INT(max_inlined_bytecode_size, 460,
           "maximum size of bytecode for a single inlining")
DEFINE_INT(max_inlined_bytecode_size_cumulative, 920,
           "maximum cumulative size of bytecode considered for inlining")
DEFINE_INT(max_inlined_bytecode_size_absolute, 4600,
           "maximum absolute size of bytecode considered for inlining")
DEFINE_FLOAT(
    reserve_inline_budget_scale_factor, 1.2,
    "scale factor of bytecode size used to calculate the inlining budget")
DEFINE_INT(max_inlined_bytecode_size_small, 27,
           "maximum size of bytecode considered for small function inlining")
DEFINE_INT(max_optimized_bytecode_size, 60 * KB,
           "maximum bytecode size to "
           "be considered for turbofan optimization; too high values may cause "
           "the compiler to hit (release) assertions")
DEFINE_FLOAT(min_inlining_frequency, 0.15, "minimum frequency for inlining")
DEFINE_BOOL(polymorphic_inlining, true, "polymorphic inlining")
DEFINE_BOOL(stress_inline, false,
            "set high thresholds for inlining to inline as much as possible")
DEFINE_VALUE_IMPLICATION(stress_inline, max_inlined_bytecode_size, 999999)
DEFINE_VALUE_IMPLICATION(stress_inline, max_inlined_bytecode_size_cumulative,
                         999999)
DEFINE_VALUE_IMPLICATION(stress_inline, max_inlined_bytecode_size_absolute,
                         999999)
DEFINE_VALUE_IMPLICATION(stress_inline, min_inlining_frequency, 0.)
DEFINE_IMPLICATION(stress_inline, polymorphic_inlining)
DEFINE_BOOL(trace_turbo_inlining, false, "trace TurboFan inlining")
DEFINE_BOOL(turbo_inline_array_builtins, true,
            "inline array builtins in TurboFan code")
DEFINE_BOOL(use_osr, true, "use on-stack replacement")
DEFINE_BOOL(maglev_osr, true, "use maglev as on-stack replacement target")

// When using maglev as OSR target allow us to tier up further
DEFINE_WEAK_VALUE_IMPLICATION(maglev_osr, osr_from_maglev, true)
DEFINE_NEG_VALUE_IMPLICATION(use_osr, maglev_osr, false)
DEFINE_NEG_VALUE_IMPLICATION(turbofan, osr_from_maglev, false)
DEFINE_BOOL(concurrent_osr, true, "enable concurrent OSR")

DEFINE_BOOL(maglev_escape_analysis, true,
            "avoid inlined allocation of objects that cannot escape")
DEFINE_BOOL(trace_maglev_escape_analysis, false, "trace maglev escape analysis")
DEFINE_EXPERIMENTAL_FEATURE(maglev_object_tracking,
                            "track object changes to avoid escaping them")
DEFINE_WEAK_IMPLICATION(maglev_future, maglev_object_tracking)
DEFINE_BOOL(trace_maglev_object_tracking, false,
            "trace load/stores from maglev virtual objects")
DEFINE_WEAK_IMPLICATION(trace_maglev_graph_building,
                        trace_maglev_object_tracking)

// TODO(dmercadier): fix and re-enable string builder.
DEFINE_BOOL_READONLY(turbo_string_builder, false,
                     "use TurboFan fast string builder")

DEFINE_BOOL(trace_osr, false, "trace on-stack replacement")
DEFINE_BOOL(log_or_trace_osr, false,
            "internal helper flag, please use --trace-osr instead.")
DEFINE_IMPLICATION(trace_osr, log_or_trace_osr)
DEFINE_IMPLICATION(log_function_events, log_or_trace_osr)

DEFINE_BOOL(analyze_environment_liveness, true,
            "analyze liveness of environment slots and zap dead values")
DEFINE_BOOL(trace_environment_liveness, false,
            "trace liveness of local variable slots")
DEFINE_BOOL(turbo_load_elimination, true, "enable load elimination in TurboFan")
DEFINE_BOOL(trace_turbo_load_elimination, false,
            "trace TurboFan load elimination")
DEFINE_BOOL(turbo_profiling, false, "enable basic block profiling in TurboFan")
DEFINE_BOOL(turbo_profiling_verbose, false,
            "enable basic block profiling in TurboFan, and include each "
            "function's schedule and disassembly in the output")
DEFINE_IMPLICATION(turbo_profiling_verbose, turbo_profiling)
DEFINE_STRING(
    turbo_profiling_output, nullptr,
    "emit data about basic block usage in builtins to this file "
    "(requires that V8 was built with v8_enable_builtins_profiling=true)")
DEFINE_BOOL(reorder_builtins, false,
            "enable builtin reordering when run mksnapshot.")

DEFINE_BOOL(abort_on_bad_builtin_profile_data, false,
            "flag for mksnapshot, abort if builtins profile can't be applied")
DEFINE_BOOL(
    warn_about_builtin_profile_data, false,
    "flag for mksnapshot, emit warnings when applying builtin profile data")
DEFINE_STRING(
    dump_builtins_hashes_to_file, nullptr,
    "flag for mksnapshot, dump CSA builtins graph hashes to this file")

DEFINE_BOOL(turbo_verify_allocation, DEBUG_BOOL,
            "verify register allocation in TurboFan")
DEFINE_BOOL(turbo_move_optimization, true, "optimize gap moves in TurboFan")
DEFINE_BOOL(turbo_jt, true, "enable jump threading in TurboFan")
DEFINE_BOOL(turbo_loop_peeling, true, "TurboFan loop peeling")
DEFINE_BOOL(turbo_loop_variable, true, "TurboFan loop variable optimization")
DEFINE_BOOL(turbo_loop_rotation, true, "TurboFan loop rotation")
DEFINE_BOOL(turbo_cf_optimization, true, "optimize control flow in TurboFan")
DEFINE_BOOL(turbo_escape, true, "enable escape analysis")
DEFINE_BOOL(turbo_allocation_folding, true, "TurboFan allocation folding")
DEFINE_BOOL(turbo_instruction_scheduling, false,
            "enable instruction scheduling in TurboFan")
DEFINE_BOOL(turbo_stress_instruction_scheduling, false,
            "randomly schedule instructions to stress dependency tracking")
DEFINE_IMPLICATION(turbo_stress_instruction_scheduling,
                   turbo_instruction_scheduling)
DEFINE_BOOL(turbo_store_elimination, true,
            "enable store-store elimination in TurboFan")
DEFINE_BOOL(trace_store_elimination, false, "trace store elimination")
DEFINE_BOOL_READONLY(turbo_typer_hardening, true,
                     "extra bounds checks to protect against some known typer "
                     "mismatch exploit techniques (best effort)")

#if defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_IA32)
DEFINE_BOOL(turbo_rewrite_far_jumps, true,
            "rewrite far to near jumps (ia32,x64)")
#else
DEFINE_BOOL_READONLY(turbo_rewrite_far_jumps, false,
                     "rewrite far to near jumps (ia32,x64)")
#endif

DEFINE_BOOL(
    stress_gc_during_compilation, false,
    "simulate GC/compiler thread race related to https://crbug.com/v8/8520")
DEFINE_BOOL(turbo_fast_api_calls, true, "enable fast API calls from TurboFan")

DEFINE_BOOL(fast_api_allow_float_in_sim, false,
            "allow float parameters to be passed in simulator mode")

// Float parameters in fast API calls don't work in the simulator in general,
// only for some specially prepared test functions. With this flag implication
// we want to make sure that the fuzzer does not enable float parameters also
// for other tests, which would just lead to errors or crashes.
DEFINE_NEG_IMPLICATION(fuzzing, fast_api_allow_float_in_sim)

#ifdef V8_USE_ZLIB
DEFINE_BOOL(turbo_compress_frame_translations, false,
            "compress deoptimization frame translations (experimental)")
#else
DEFINE_BOOL_READONLY(
    turbo_compress_frame_translations, false,
    "compress deoptimization frame translations (experimental)")
#endif  // V8_USE_ZLIB
DEFINE_BOOL(
    turbo_inline_js_wasm_calls, true,
    "inline JS->Wasm calls (specifically: inline JS-to-Wasm wrappers and then "
    "the body of the Wasm function, if applicable)")

DEFINE_BOOL(turbo_optimize_inlined_js_wasm_wrappers, false,
            "Run additional optimizations (especially load-elimination) on "
            "inlined JS-to-Wasm wrappers")
DEFINE_NEG_NEG_IMPLICATION(turbo_inline_js_wasm_calls,
                           turbo_optimize_inlined_js_wasm_wrappers)
DEFINE_WEAK_IMPLICATION(future, turbo_optimize_inlined_js_wasm_wrappers)

DEFINE_BOOL(turbo_optimize_apply, true, "optimize Function.prototype.apply")
DEFINE_BOOL(turbo_optimize_math_minmax, true,
            "optimize call math.min/max with double array")

DEFINE_BOOL(turbo_collect_feedback_in_generic_lowering, false,
            "enable experimental feedback collection in generic lowering.")

DEFINE_BOOL(turboshaft, true, "enable TurboFan's Turboshaft phases for JS")

// Can't use Turbofan without Turboshaft
"""


```