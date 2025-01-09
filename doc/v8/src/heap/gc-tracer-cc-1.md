Response:
My thinking process for summarizing the functionality of `v8/src/heap/gc-tracer.cc` based on the provided code snippet goes like this:

1. **Initial Scan for Keywords and Structure:** I first skim the code, looking for recurring patterns, key variables, and overall structure. I notice a lot of `PrintWithTimestamp`, numerous variables with names like `duration`, `spent_in_mutator`, different `Scope` enums, and size-related variables (`total_size_before`, `total_size_after`). The presence of `case` statements based on `Event::Type` is also prominent.

2. **Focus on the `PrintWithTimestamp` Calls:** The numerous calls to `heap_->isolate()->PrintWithTimestamp` immediately suggest that this code is responsible for logging or recording detailed information about garbage collection events. The format strings within these calls are rich with data points, giving clues about what's being measured.

3. **Deciphering the Format Strings:** I then analyze the format strings within the `PrintWithTimestamp` calls for each `Event::Type`. This is where the core functionality becomes apparent. I see measurements related to:
    * **Time:** `pause`, `mutator`, various scoped timings (e.g., `mark`, `sweep`, `evacuate`), `time_to_safepoint`.
    * **GC Type:**  The `%s` format specifier is used to print the GC type (e.g., "ms", "mms").
    * **Memory:** `total_size_before`, `total_size_after`, `holes_size_before`, `holes_size_after`, `allocated`, `promoted`, `new_space_survived`.
    * **Counts:** `nodes_died_in_new`, `nodes_copied_in_new`, `nodes_promoted`, `incremental.steps_count`.
    * **Rates and Ratios:** `promotion_ratio`, `average_survival_ratio`, `promotion_rate`, `new_space_survive_rate_`, `new_space_allocation_throughput`, `compaction_speed`.
    * **Flags:** `reduce_memory`.
    * **Specific GC Phases:** The nested structure of the format strings and the `current_scope` function clearly indicate the tracking of time spent in various phases of garbage collection (e.g., marking, sweeping, evacuation).

4. **Identifying the `Event::Type` Cases:** The `switch` statement based on `Event::Type` reveals the different types of garbage collection events being tracked: `SCAVENGER`, `MINOR_MARK_SWEEPER`, `INCREMENTAL_MINOR_MARK_SWEEPER`, `MARK_COMPACTOR`, `INCREMENTAL_MARK_COMPACTOR`, and `START`. This tells me the tracer is capable of handling different GC algorithms.

5. **Inferring Functionality from Variable Names and Calculations:**  Variables like `allocated_since_last_gc`, `heap_->promoted_objects_size()`, and calculations like `YoungGenerationSpeedInBytesPerMillisecond()` suggest that the code is not just logging, but also performing some calculations to derive metrics related to GC performance and memory management.

6. **Connecting to User-Level Concepts (Based on Hints):** The prompt mentions a potential relationship with JavaScript. While the provided code is C++, the concepts of "allocation," "garbage collection," and "performance" are directly relevant to how JavaScript engines function. I can infer that the data being logged by this code could be used to understand and optimize JavaScript execution. However, the provided snippet doesn't offer concrete JavaScript examples.

7. **Considering Potential Errors (Based on Context):**  The focus on memory management and performance suggests that common programming errors leading to memory leaks or performance issues would be relevant in this context.

8. **Synthesizing the Summary:** Based on the above observations, I formulate a summary that emphasizes the core functionalities: detailed logging of GC events, tracking time spent in different phases, recording memory usage, calculating performance metrics, and handling different GC types. I also note the lack of direct JavaScript examples in the provided snippet.

9. **Addressing Specific Instructions:** I then revisit the prompt to ensure I've addressed all specific points: checking for `.tq` (not present), mentioning the lack of direct JavaScript examples, acknowledging the code logic inference (through the format strings and calculations), and considering potential user errors (related to memory management).

10. **Focusing on Part 2:** Finally, I specifically address the "归纳一下它的功能" (summarize its functionality) instruction for this part of the code, focusing on the logging and detailed metrics generation aspects evident in the provided snippet.

This iterative process of scanning, analyzing, inferring, and synthesizing allows me to understand the high-level functionality of the code even without detailed knowledge of the entire V8 codebase.

根据提供的代码片段，`v8/src/heap/gc-tracer.cc` 的功能可以归纳如下：

**核心功能：详细记录和输出垃圾回收（GC）事件的性能数据。**

这段代码的主要作用是当 V8 引擎进行垃圾回收时，记录各种细粒度的性能指标，并将这些指标格式化输出。  它针对不同类型的 GC 事件（如 Scavenger, Minor Mark-Sweeper, Mark-Compactor 等）记录不同的指标。

**具体功能点:**

* **记录 GC 事件的类型和基本信息:**  例如，是 Scavenger GC 还是 Mark-Compactor GC，是否启用了内存缩减模式 (`reduce_memory`)。
* **记录 GC 暂停时间 (pause) 和 mutator 时间 (mutator):**  `pause` 指的是 GC 暂停应用程序执行的时间，`mutator` 指的是应用程序执行的时间。
* **记录 GC 各个阶段的耗时:**  代码中大量使用了 `current_scope(Scope::...)` 和 `incremental_scope(GCTracer::Scope::...)` 来记录 GC 过程中各个子阶段的耗时，例如：
    * **Scavenger:**  扫描根、处理弱引用、并行处理等。
    * **Minor Mark-Sweeper:**  标记、清除、扫描 ArrayBuffer 等。
    * **Mark-Compactor:**  清除、弱处理、疏散、标记、扫描等更细致的阶段。
* **记录内存使用情况:**  记录 GC 前后的堆大小 (`total_size_before`, `total_size_after`)，空洞大小 (`holes_size_before`, `holes_size_after`)，以及分配量 (`allocated`)，晋升量 (`promoted`)，新生代存活量 (`new_space_survived`) 等。
* **记录对象数量变化:**  例如，新生代中死亡的节点数 (`nodes_died_in_new`)，复制的节点数 (`nodes_copied_in_new`)，晋升的节点数 (`nodes_promoted`)。
* **计算和记录吞吐量和比率:**  例如，Scavenge 吞吐量 (`scavenge_throughput`)，晋升率 (`promotion_ratio`)，平均存活率 (`average_survival_ratio`)，新生代存活率 (`new_space_survive_rate_`)，以及内存分配吞吐量 (`new_space_allocation_throughput`)。
* **记录增量式 GC 的步数和耗时:** 对于增量式 GC，会记录执行的步数 (`incremental.steps_count`) 和耗时 (`incremental.steps_took`)。
* **区分前台和后台 GC:**  会分别记录前台和后台 GC 阶段的耗时，例如 `background.mark`, `background.sweep`。
* **记录保守堆栈扫描时间:** `conservative_stack_scanning`。
* **记录内存池 chunk 的数量:** `pool_chunks`。
* **对于 Mark-Compactor，还记录了更细粒度的阶段:**  例如疏散阶段的候选对象查找、清理、复制等。
* **输出格式化的字符串:** 使用 `heap_->isolate()->PrintWithTimestamp` 将记录的指标以易于解析的格式输出。

**关于 .tq 后缀和 JavaScript 关系：**

* 代码片段是 `.cc` 文件，因此它是 C++ 源代码，而不是 Torque 源代码。
* 这段代码直接与 V8 引擎的垃圾回收机制相关，而垃圾回收是 JavaScript 引擎的核心组成部分。  虽然这段代码本身是 C++，但它直接影响 JavaScript 程序的性能和内存管理。

**代码逻辑推理：**

**假设输入：**  一次 Scavenger 垃圾回收事件完成。

**预期输出：**  会输出类似于以下格式的字符串，其中包含了本次 Scavenger GC 的各种性能指标：

```
pause=1.2 mutator=98.8 gc=ms reduce_memory=0 time_to_safepoint=0.1 heap.prologue=0.0 heap.epilogue=0.0 heap.external.prologue=0.0 heap.external.epilogue=0.0 heap.external.weak_global_handles=0.0 complete.sweep_array_buffers=0.0 scavenge=0.8 free_remembered_set=0.1 scavenge.roots=0.1 scavenge.weak=0.0 scavenge.weak_global_handles.identify=0.0 scavenge.weak_global_handles.process=0.0 scavenge.parallel=0.2 scavenge.update_refs=0.0 scavenge.sweep_array_buffers=0.0 background.scavenge.parallel=0.0 incremental.steps_count=0 incremental.steps_took=0.0 scavenge_throughput=123456 total_size_before=1000000 total_size_after=900000 holes_size_before=10000 holes_size_after=5000 allocated=50000 promoted=20000 new_space_survived=30000 nodes_died_in_new=100 nodes_copied_in_new=50 nodes_promoted=20 promotion_ratio=20.0% average_survival_ratio=30.0% promotion_rate=15.0% new_space_survive_rate_=40.0% new_space_allocation_throughput=5000 pool_chunks=10
```

**用户常见的编程错误（与这段代码的功能间接相关）：**

虽然这段代码本身不直接处理用户代码，但它记录的 GC 数据可以帮助开发者识别与内存管理相关的编程错误：

* **内存泄漏:**  如果 `total_size_after` 在多次 GC 后持续增长，可能表明存在内存泄漏，即不再使用的对象没有被释放。这段代码记录的内存使用情况可以帮助监控这种情况。
* **频繁创建临时对象:**  如果 `allocated_since_last_gc` 的值很高，且 GC 发生频率很高，可能意味着代码中频繁创建和销毁临时对象，导致 GC 压力增大。
* **对象晋升过多:**  如果 `promoted` 的值很高，可能意味着新生代的对象过早地晋升到老年代，增加了老年代 GC 的压力。
* **全局变量或闭包持有大量对象:** 这会导致这些对象难以被回收，增加堆的压力。

**总结（针对第 2 部分）：**

这部分 `gc-tracer.cc` 代码的核心功能是 **作为 V8 引擎中垃圾回收事件的详细性能记录器。** 它能够针对不同类型的 GC 事件，记录其各个阶段的耗时、内存使用情况、对象数量变化以及计算相关的性能指标，并将这些信息格式化输出，为 V8 引擎的性能分析和优化提供关键数据。  虽然是 C++ 代码，但它直接关联到 JavaScript 的内存管理和执行性能。

Prompt: 
```
这是目录为v8/src/heap/gc-tracer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/gc-tracer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
.2f "
          "scavenge.weak_global_handles.process=%.2f "
          "scavenge.parallel=%.2f "
          "scavenge.update_refs=%.2f "
          "scavenge.sweep_array_buffers=%.2f "
          "background.scavenge.parallel=%.2f "
          "incremental.steps_count=%d "
          "incremental.steps_took=%.1f "
          "scavenge_throughput=%.f "
          "total_size_before=%zu "
          "total_size_after=%zu "
          "holes_size_before=%zu "
          "holes_size_after=%zu "
          "allocated=%zu "
          "promoted=%zu "
          "new_space_survived=%zu "
          "nodes_died_in_new=%d "
          "nodes_copied_in_new=%d "
          "nodes_promoted=%d "
          "promotion_ratio=%.1f%% "
          "average_survival_ratio=%.1f%% "
          "promotion_rate=%.1f%% "
          "new_space_survive_rate_=%.1f%% "
          "new_space_allocation_throughput=%.1f "
          "pool_chunks=%zu\n",
          duration.InMillisecondsF(), spent_in_mutator.InMillisecondsF(),
          ToString(current_.type, true), current_.reduce_memory,
          young_gc_while_full_gc_,
          current_.scopes[Scope::TIME_TO_SAFEPOINT].InMillisecondsF(),
          current_scope(Scope::HEAP_PROLOGUE),
          current_scope(Scope::HEAP_EPILOGUE),
          current_scope(Scope::HEAP_EXTERNAL_PROLOGUE),
          current_scope(Scope::HEAP_EXTERNAL_EPILOGUE),
          current_scope(Scope::HEAP_EXTERNAL_WEAK_GLOBAL_HANDLES),
          current_scope(Scope::SCAVENGER_COMPLETE_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::SCAVENGER_SCAVENGE),
          current_scope(Scope::SCAVENGER_FREE_REMEMBERED_SET),
          current_scope(Scope::SCAVENGER_SCAVENGE_ROOTS),
          current_scope(Scope::SCAVENGER_SCAVENGE_WEAK),
          current_scope(Scope::SCAVENGER_SCAVENGE_WEAK_GLOBAL_HANDLES_IDENTIFY),
          current_scope(Scope::SCAVENGER_SCAVENGE_WEAK_GLOBAL_HANDLES_PROCESS),
          current_scope(Scope::SCAVENGER_SCAVENGE_PARALLEL),
          current_scope(Scope::SCAVENGER_SCAVENGE_UPDATE_REFS),
          current_scope(Scope::SCAVENGER_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL),
          incremental_scope(GCTracer::Scope::MC_INCREMENTAL).steps,
          current_scope(Scope::MC_INCREMENTAL),
          YoungGenerationSpeedInBytesPerMillisecond(
              YoungGenerationSpeedMode::kOnlyAtomicPause),
          current_.start_object_size, current_.end_object_size,
          current_.start_holes_size, current_.end_holes_size,
          allocated_since_last_gc, heap_->promoted_objects_size(),
          heap_->new_space_surviving_object_size(),
          heap_->nodes_died_in_new_space_, heap_->nodes_copied_in_new_space_,
          heap_->nodes_promoted_, heap_->promotion_ratio_,
          AverageSurvivalRatio(), heap_->promotion_rate_,
          heap_->new_space_surviving_rate_,
          NewSpaceAllocationThroughputInBytesPerMillisecond(),
          heap_->memory_allocator()->pool()->NumberOfCommittedChunks());
      break;
    case Event::Type::MINOR_MARK_SWEEPER:
    case Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER:
      heap_->isolate()->PrintWithTimestamp(
          "pause=%.1f "
          "mutator=%.1f "
          "gc=%s "
          "reduce_memory=%d "
          "minor_ms=%.2f "
          "time_to_safepoint=%.2f "
          "mark=%.2f "
          "mark.incremental_seed=%.2f "
          "mark.finish_incremental=%.2f "
          "mark.seed=%.2f "
          "mark.traced_handles=%.2f "
          "mark.closure_parallel=%.2f "
          "mark.closure=%.2f "
          "mark.conservative_stack=%.2f "
          "clear=%.2f "
          "clear.string_forwarding_table=%.2f "
          "clear.string_table=%.2f "
          "clear.global_handles=%.2f "
          "complete.sweep_array_buffers=%.2f "
          "complete.sweeping=%.2f "
          "sweep=%.2f "
          "sweep.new=%.2f "
          "sweep.new_lo=%.2f "
          "sweep.update_string_table=%.2f "
          "sweep.start_jobs=%.2f "
          "sweep.array_buffers=%.2f "
          "finish=%.2f "
          "finish.ensure_capacity=%.2f "
          "finish.sweep_array_buffers=%.2f "
          "background.mark=%.2f "
          "background.sweep=%.2f "
          "background.sweep.array_buffers=%.2f "
          "conservative_stack_scanning=%.2f "
          "total_size_before=%zu "
          "total_size_after=%zu "
          "holes_size_before=%zu "
          "holes_size_after=%zu "
          "allocated=%zu "
          "promoted=%zu "
          "new_space_survived=%zu "
          "nodes_died_in_new=%d "
          "nodes_copied_in_new=%d "
          "nodes_promoted=%d "
          "promotion_ratio=%.1f%% "
          "average_survival_ratio=%.1f%% "
          "promotion_rate=%.1f%% "
          "new_space_survive_rate_=%.1f%% "
          "new_space_allocation_throughput=%.1f\n",
          duration.InMillisecondsF(), spent_in_mutator.InMillisecondsF(), "mms",
          current_.reduce_memory, current_scope(Scope::MINOR_MS),
          current_scope(Scope::TIME_TO_SAFEPOINT),
          current_scope(Scope::MINOR_MS_MARK),
          current_scope(Scope::MINOR_MS_MARK_INCREMENTAL_SEED),
          current_scope(Scope::MINOR_MS_MARK_FINISH_INCREMENTAL),
          current_scope(Scope::MINOR_MS_MARK_SEED),
          current_scope(Scope::MINOR_MS_MARK_TRACED_HANDLES),
          current_scope(Scope::MINOR_MS_MARK_CLOSURE_PARALLEL),
          current_scope(Scope::MINOR_MS_MARK_CLOSURE),
          current_scope(Scope::MINOR_MS_MARK_CONSERVATIVE_STACK),
          current_scope(Scope::MINOR_MS_CLEAR),
          current_scope(Scope::MINOR_MS_CLEAR_STRING_FORWARDING_TABLE),
          current_scope(Scope::MINOR_MS_CLEAR_STRING_TABLE),
          current_scope(Scope::MINOR_MS_CLEAR_WEAK_GLOBAL_HANDLES),
          current_scope(Scope::MINOR_MS_COMPLETE_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::MINOR_MS_COMPLETE_SWEEPING),
          current_scope(Scope::MINOR_MS_SWEEP),
          current_scope(Scope::MINOR_MS_SWEEP_NEW),
          current_scope(Scope::MINOR_MS_SWEEP_NEW_LO),
          current_scope(Scope::MINOR_MS_SWEEP_UPDATE_STRING_TABLE),
          current_scope(Scope::MINOR_MS_SWEEP_START_JOBS),
          current_scope(Scope::YOUNG_ARRAY_BUFFER_SWEEP),
          current_scope(Scope::MINOR_MS_FINISH),
          current_scope(Scope::MINOR_MS_FINISH_ENSURE_CAPACITY),
          current_scope(Scope::MINOR_MS_FINISH_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::MINOR_MS_BACKGROUND_MARKING),
          current_scope(Scope::MINOR_MS_BACKGROUND_SWEEPING),
          current_scope(Scope::BACKGROUND_YOUNG_ARRAY_BUFFER_SWEEP),
          current_scope(Scope::CONSERVATIVE_STACK_SCANNING),
          current_.start_object_size, current_.end_object_size,
          current_.start_holes_size, current_.end_holes_size,
          allocated_since_last_gc, heap_->promoted_objects_size(),
          heap_->new_space_surviving_object_size(),
          heap_->nodes_died_in_new_space_, heap_->nodes_copied_in_new_space_,
          heap_->nodes_promoted_, heap_->promotion_ratio_,
          AverageSurvivalRatio(), heap_->promotion_rate_,
          heap_->new_space_surviving_rate_,
          NewSpaceAllocationThroughputInBytesPerMillisecond());
      break;
    case Event::Type::MARK_COMPACTOR:
    case Event::Type::INCREMENTAL_MARK_COMPACTOR:
      heap_->isolate()->PrintWithTimestamp(
          "pause=%.1f "
          "mutator=%.1f "
          "gc=%s "
          "reduce_memory=%d "
          "time_to_safepoint=%.2f "
          "heap.prologue=%.2f "
          "heap.embedder_tracing_epilogue=%.2f "
          "heap.epilogue=%.2f "
          "heap.external.prologue=%.1f "
          "heap.external.epilogue=%.1f "
          "heap.external.weak_global_handles=%.1f "
          "clear=%1.f "
          "clear.external_string_table=%.1f "
          "clear.string_forwarding_table=%.1f "
          "clear.weak_global_handles=%.1f "
          "clear.dependent_code=%.1f "
          "clear.maps=%.1f "
          "clear.slots_buffer=%.1f "
          "clear.weak_collections=%.1f "
          "clear.weak_lists=%.1f "
          "clear.weak_references_trivial=%.1f "
          "clear.weak_references_non_trivial=%.1f "
          "clear.weak_references_filter_non_trivial=%.1f "
          "clear.js_weak_references=%.1f "
          "clear.join_filter_job=%.1f"
          "clear.join_job=%.1f "
          "weakness_handling=%.1f "
          "complete.sweep_array_buffers=%.1f "
          "complete.sweeping=%.1f "
          "epilogue=%.1f "
          "evacuate=%.1f "
          "evacuate.candidates=%.1f "
          "evacuate.clean_up=%.1f "
          "evacuate.copy=%.1f "
          "evacuate.prologue=%.1f "
          "evacuate.epilogue=%.1f "
          "evacuate.rebalance=%.1f "
          "evacuate.update_pointers=%.1f "
          "evacuate.update_pointers.to_new_roots=%.1f "
          "evacuate.update_pointers.slots.main=%.1f "
          "evacuate.update_pointers.weak=%.1f "
          "finish=%.1f "
          "finish.sweep_array_buffers=%.1f "
          "mark=%.1f "
          "mark.finish_incremental=%.1f "
          "mark.roots=%.1f "
          "mark.full_closure_parallel=%.1f "
          "mark.full_closure=%.1f "
          "mark.ephemeron.marking=%.1f "
          "mark.ephemeron.linear=%.1f "
          "mark.embedder_prologue=%.1f "
          "mark.embedder_tracing=%.1f "
          "prologue=%.1f "
          "sweep=%.1f "
          "sweep.code=%.1f "
          "sweep.map=%.1f "
          "sweep.new=%.1f "
          "sweep.new_lo=%.1f "
          "sweep.old=%.1f "
          "sweep.start_jobs=%.1f "
          "incremental=%.1f "
          "incremental.finalize=%.1f "
          "incremental.finalize.external.prologue=%.1f "
          "incremental.finalize.external.epilogue=%.1f "
          "incremental.layout_change=%.1f "
          "incremental.sweep_array_buffers=%.1f "
          "incremental.sweeping=%.1f "
          "incremental.embedder_tracing=%.1f "
          "incremental_wrapper_tracing_longest_step=%.1f "
          "incremental_longest_step=%.1f "
          "incremental_steps_count=%d "
          "incremental_marking_throughput=%.f "
          "incremental_walltime_duration=%.f "
          "background.mark=%.1f "
          "background.sweep=%.1f "
          "background.evacuate.copy=%.1f "
          "background.evacuate.update_pointers=%.1f "
          "conservative_stack_scanning=%.2f "
          "total_size_before=%zu "
          "total_size_after=%zu "
          "holes_size_before=%zu "
          "holes_size_after=%zu "
          "allocated=%zu "
          "promoted=%zu "
          "new_space_survived=%zu "
          "nodes_died_in_new=%d "
          "nodes_copied_in_new=%d "
          "nodes_promoted=%d "
          "promotion_ratio=%.1f%% "
          "average_survival_ratio=%.1f%% "
          "promotion_rate=%.1f%% "
          "new_space_survive_rate=%.1f%% "
          "new_space_allocation_throughput=%.1f "
          "pool_chunks=%zu "
          "compaction_speed=%.f\n",
          duration.InMillisecondsF(), spent_in_mutator.InMillisecondsF(),
          ToString(current_.type, true), current_.reduce_memory,
          current_scope(Scope::TIME_TO_SAFEPOINT),
          current_scope(Scope::HEAP_PROLOGUE),
          current_scope(Scope::HEAP_EMBEDDER_TRACING_EPILOGUE),
          current_scope(Scope::HEAP_EPILOGUE),
          current_scope(Scope::HEAP_EXTERNAL_PROLOGUE),
          current_scope(Scope::HEAP_EXTERNAL_EPILOGUE),
          current_scope(Scope::HEAP_EXTERNAL_WEAK_GLOBAL_HANDLES),
          current_scope(Scope::MC_CLEAR),
          current_scope(Scope::MC_CLEAR_EXTERNAL_STRING_TABLE),
          current_scope(Scope::MC_CLEAR_STRING_FORWARDING_TABLE),
          current_scope(Scope::MC_CLEAR_WEAK_GLOBAL_HANDLES),
          current_scope(Scope::MC_CLEAR_DEPENDENT_CODE),
          current_scope(Scope::MC_CLEAR_MAPS),
          current_scope(Scope::MC_CLEAR_SLOTS_BUFFER),
          current_scope(Scope::MC_CLEAR_WEAK_COLLECTIONS),
          current_scope(Scope::MC_CLEAR_WEAK_LISTS),
          current_scope(Scope::MC_CLEAR_WEAK_REFERENCES_TRIVIAL),
          current_scope(Scope::MC_CLEAR_WEAK_REFERENCES_NON_TRIVIAL),
          current_scope(Scope::MC_CLEAR_WEAK_REFERENCES_FILTER_NON_TRIVIAL),
          current_scope(Scope::MC_CLEAR_JS_WEAK_REFERENCES),
          current_scope(Scope::MC_CLEAR_WEAK_REFERENCES_JOIN_FILTER_JOB),
          current_scope(Scope::MC_CLEAR_JOIN_JOB),
          current_scope(Scope::MC_WEAKNESS_HANDLING),
          current_scope(Scope::MC_COMPLETE_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::MC_COMPLETE_SWEEPING),
          current_scope(Scope::MC_EPILOGUE), current_scope(Scope::MC_EVACUATE),
          current_scope(Scope::MC_EVACUATE_CANDIDATES),
          current_scope(Scope::MC_EVACUATE_CLEAN_UP),
          current_scope(Scope::MC_EVACUATE_COPY),
          current_scope(Scope::MC_EVACUATE_PROLOGUE),
          current_scope(Scope::MC_EVACUATE_EPILOGUE),
          current_scope(Scope::MC_EVACUATE_REBALANCE),
          current_scope(Scope::MC_EVACUATE_UPDATE_POINTERS),
          current_scope(Scope::MC_EVACUATE_UPDATE_POINTERS_TO_NEW_ROOTS),
          current_scope(Scope::MC_EVACUATE_UPDATE_POINTERS_SLOTS_MAIN),
          current_scope(Scope::MC_EVACUATE_UPDATE_POINTERS_WEAK),
          current_scope(Scope::MC_FINISH),
          current_scope(Scope::MC_FINISH_SWEEP_ARRAY_BUFFERS),
          current_scope(Scope::MC_MARK),
          current_scope(Scope::MC_MARK_FINISH_INCREMENTAL),
          current_scope(Scope::MC_MARK_ROOTS),
          current_scope(Scope::MC_MARK_FULL_CLOSURE_PARALLEL),
          current_scope(Scope::MC_MARK_FULL_CLOSURE),
          current_scope(Scope::MC_MARK_WEAK_CLOSURE_EPHEMERON_MARKING),
          current_scope(Scope::MC_MARK_WEAK_CLOSURE_EPHEMERON_LINEAR),
          current_scope(Scope::MC_MARK_EMBEDDER_PROLOGUE),
          current_scope(Scope::MC_MARK_EMBEDDER_TRACING),
          current_scope(Scope::MC_PROLOGUE), current_scope(Scope::MC_SWEEP),
          current_scope(Scope::MC_SWEEP_CODE),
          current_scope(Scope::MC_SWEEP_MAP),
          current_scope(Scope::MC_SWEEP_NEW),
          current_scope(Scope::MC_SWEEP_NEW_LO),
          current_scope(Scope::MC_SWEEP_OLD),
          current_scope(Scope::MC_SWEEP_START_JOBS),
          current_scope(Scope::MC_INCREMENTAL),
          current_scope(Scope::MC_INCREMENTAL_FINALIZE),
          current_scope(Scope::MC_INCREMENTAL_EXTERNAL_PROLOGUE),
          current_scope(Scope::MC_INCREMENTAL_EXTERNAL_EPILOGUE),
          current_scope(Scope::MC_INCREMENTAL_LAYOUT_CHANGE),
          current_scope(Scope::MC_INCREMENTAL_START),
          current_scope(Scope::MC_INCREMENTAL_SWEEPING),
          current_scope(Scope::MC_INCREMENTAL_EMBEDDER_TRACING),
          incremental_scope(Scope::MC_INCREMENTAL_EMBEDDER_TRACING)
              .longest_step.InMillisecondsF(),
          incremental_scope(Scope::MC_INCREMENTAL)
              .longest_step.InMillisecondsF(),
          incremental_scope(Scope::MC_INCREMENTAL).steps,
          IncrementalMarkingSpeedInBytesPerMillisecond(),
          incremental_walltime_duration.InMillisecondsF(),
          current_scope(Scope::MC_BACKGROUND_MARKING),
          current_scope(Scope::MC_BACKGROUND_SWEEPING),
          current_scope(Scope::MC_BACKGROUND_EVACUATE_COPY),
          current_scope(Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS),
          current_scope(Scope::CONSERVATIVE_STACK_SCANNING),
          current_.start_object_size, current_.end_object_size,
          current_.start_holes_size, current_.end_holes_size,
          allocated_since_last_gc, heap_->promoted_objects_size(),
          heap_->new_space_surviving_object_size(),
          heap_->nodes_died_in_new_space_, heap_->nodes_copied_in_new_space_,
          heap_->nodes_promoted_, heap_->promotion_ratio_,
          AverageSurvivalRatio(), heap_->promotion_rate_,
          heap_->new_space_surviving_rate_,
          NewSpaceAllocationThroughputInBytesPerMillisecond(),
          heap_->memory_allocator()->pool()->NumberOfCommittedChunks(),
          CompactionSpeedInBytesPerMillisecond());
      break;
    case Event::Type::START:
      break;
  }
}

void GCTracer::RecordIncrementalMarkingSpeed(size_t bytes,
                                             base::TimeDelta duration) {
  DCHECK(!Event::IsYoungGenerationEvent(current_.type));
  if (duration.IsZero() || bytes == 0) return;
  double current_speed =
      static_cast<double>(bytes) / duration.InMillisecondsF();
  if (recorded_major_incremental_marking_speed_ == 0) {
    recorded_major_incremental_marking_speed_ = current_speed;
  } else {
    recorded_major_incremental_marking_speed_ =
        (recorded_major_incremental_marking_speed_ + current_speed) / 2;
  }
}

void GCTracer::RecordTimeToIncrementalMarkingTask(
    base::TimeDelta time_to_task) {
  if (!average_time_to_incremental_marking_task_.has_value()) {
    average_time_to_incremental_marking_task_.emplace(time_to_task);
  } else {
    average_time_to_incremental_marking_task_ =
        (average_time_to_incremental_marking_task_.value() + time_to_task) / 2;
  }
}

std::optional<base::TimeDelta> GCTracer::AverageTimeToIncrementalMarkingTask()
    const {
  return average_time_to_incremental_marking_task_;
}

void GCTracer::RecordEmbedderMarkingSpeed(size_t bytes,
                                          base::TimeDelta duration) {
  recorded_embedder_marking_.Push(BytesAndDuration(bytes, duration));
}

void GCTracer::RecordMutatorUtilization(base::TimeTicks mark_compact_end_time,
                                        base::TimeDelta mark_compact_duration) {
  total_duration_since_last_mark_compact_ =
      mark_compact_end_time - previous_mark_compact_end_time_;
  DCHECK_GE(total_duration_since_last_mark_compact_, base::TimeDelta());
  const base::TimeDelta mutator_duration =
      total_duration_since_last_mark_compact_ - mark_compact_duration;
  DCHECK_GE(mutator_duration, base::TimeDelta());
  if (average_mark_compact_duration_ == 0 && average_mutator_duration_ == 0) {
    // This is the first event with mutator and mark-compact durations.
    average_mark_compact_duration_ = mark_compact_duration.InMillisecondsF();
    average_mutator_duration_ = mutator_duration.InMillisecondsF();
  } else {
    average_mark_compact_duration_ = (average_mark_compact_duration_ +
                                      mark_compact_duration.InMillisecondsF()) /
                                     2;
    average_mutator_duration_ =
        (average_mutator_duration_ + mutator_duration.InMillisecondsF()) / 2;
  }
  current_mark_compact_mutator_utilization_ =
      !total_duration_since_last_mark_compact_.IsZero()
          ? mutator_duration.InMillisecondsF() /
                total_duration_since_last_mark_compact_.InMillisecondsF()
          : 0;
  previous_mark_compact_end_time_ = mark_compact_end_time;
}

double GCTracer::AverageMarkCompactMutatorUtilization() const {
  double average_total_duration =
      average_mark_compact_duration_ + average_mutator_duration_;
  if (average_total_duration == 0) return 1.0;
  return average_mutator_duration_ / average_total_duration;
}

double GCTracer::CurrentMarkCompactMutatorUtilization() const {
  return current_mark_compact_mutator_utilization_;
}

double GCTracer::IncrementalMarkingSpeedInBytesPerMillisecond() const {
  if (recorded_major_incremental_marking_speed_ != 0) {
    return recorded_major_incremental_marking_speed_;
  }
  if (!current_.incremental_marking_duration.IsZero()) {
    return current_.incremental_marking_bytes /
           current_.incremental_marking_duration.InMillisecondsF();
  }
  return kConservativeSpeedInBytesPerMillisecond;
}

double GCTracer::EmbedderSpeedInBytesPerMillisecond() const {
  return BoundedAverageSpeed(recorded_embedder_marking_);
}

double GCTracer::YoungGenerationSpeedInBytesPerMillisecond(
    YoungGenerationSpeedMode mode) const {
  switch (mode) {
    case YoungGenerationSpeedMode::kUpToAndIncludingAtomicPause:
      return BoundedAverageSpeed(recorded_minor_gc_per_thread_);
    case YoungGenerationSpeedMode::kOnlyAtomicPause:
      return BoundedAverageSpeed(recorded_minor_gc_atomic_pause_);
  }
  UNREACHABLE();
}

double GCTracer::CompactionSpeedInBytesPerMillisecond() const {
  return BoundedAverageSpeed(recorded_compactions_);
}

double GCTracer::MarkCompactSpeedInBytesPerMillisecond() const {
  return BoundedAverageSpeed(recorded_mark_compacts_);
}

double GCTracer::FinalIncrementalMarkCompactSpeedInBytesPerMillisecond() const {
  return BoundedAverageSpeed(recorded_incremental_mark_compacts_);
}

double GCTracer::OldGenerationSpeedInBytesPerMillisecond() {
  if (v8_flags.gc_speed_uses_counters) {
    return BoundedAverageSpeed(recorded_major_totals_);
  }

  const double kMinimumMarkingSpeed = 0.5;
  if (combined_mark_compact_speed_cache_ > 0)
    return combined_mark_compact_speed_cache_;
  // MarkCompact speed is more stable than incremental marking speed, because
  // there might not be many incremental marking steps because of concurrent
  // marking.
  combined_mark_compact_speed_cache_ = MarkCompactSpeedInBytesPerMillisecond();
  if (combined_mark_compact_speed_cache_ > 0)
    return combined_mark_compact_speed_cache_;
  double speed1 = IncrementalMarkingSpeedInBytesPerMillisecond();
  double speed2 = FinalIncrementalMarkCompactSpeedInBytesPerMillisecond();
  if (speed1 < kMinimumMarkingSpeed || speed2 < kMinimumMarkingSpeed) {
    // No data for the incremental marking speed.
    // Return the non-incremental mark-compact speed.
    combined_mark_compact_speed_cache_ =
        MarkCompactSpeedInBytesPerMillisecond();
  } else {
    // Combine the speed of incremental step and the speed of the final step.
    // 1 / (1 / speed1 + 1 / speed2) = speed1 * speed2 / (speed1 + speed2).
    combined_mark_compact_speed_cache_ = speed1 * speed2 / (speed1 + speed2);
  }
  return combined_mark_compact_speed_cache_;
}

double GCTracer::NewSpaceAllocationThroughputInBytesPerMillisecond() const {
  return BoundedThroughput(new_generation_allocations_);
}

double GCTracer::OldGenerationAllocationThroughputInBytesPerMillisecond()
    const {
  return BoundedThroughput(old_generation_allocations_);
}

double GCTracer::EmbedderAllocationThroughputInBytesPerMillisecond() const {
  return BoundedThroughput(embedder_generation_allocations_);
}

double GCTracer::AllocationThroughputInBytesPerMillisecond() const {
  return NewSpaceAllocationThroughputInBytesPerMillisecond() +
         OldGenerationAllocationThroughputInBytesPerMillisecond();
}

double GCTracer::AverageSurvivalRatio() const {
  if (recorded_survival_ratios_.Empty()) return 0.0;
  double sum = recorded_survival_ratios_.Reduce(
      [](double a, double b) { return a + b; }, 0.0);
  return sum / recorded_survival_ratios_.Size();
}

bool GCTracer::SurvivalEventsRecorded() const {
  return !recorded_survival_ratios_.Empty();
}

void GCTracer::ResetSurvivalEvents() { recorded_survival_ratios_.Clear(); }

void GCTracer::NotifyIncrementalMarkingStart() {
  current_.incremental_marking_start_time = base::TimeTicks::Now();
}

void GCTracer::FetchBackgroundCounters() {
  base::MutexGuard guard(&background_scopes_mutex_);
  for (int i = Scope::FIRST_BACKGROUND_SCOPE; i <= Scope::LAST_BACKGROUND_SCOPE;
       i++) {
    current_.scopes[i] += background_scopes_[i];
    background_scopes_[i] = base::TimeDelta();
  }
}

namespace {

V8_INLINE int TruncateToMs(base::TimeDelta delta) {
  return static_cast<int>(delta.InMilliseconds());
}

}  // namespace

void GCTracer::RecordGCPhasesHistograms(RecordGCPhasesInfo::Mode mode) {
  Counters* counters = heap_->isolate()->counters();
  if (mode == RecordGCPhasesInfo::Mode::Finalize) {
    DCHECK_EQ(Scope::FIRST_TOP_MC_SCOPE, Scope::MC_CLEAR);
    counters->gc_finalize_clear()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_CLEAR]));
    counters->gc_finalize_epilogue()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_EPILOGUE]));
    counters->gc_finalize_evacuate()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_EVACUATE]));
    counters->gc_finalize_finish()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_FINISH]));
    counters->gc_finalize_mark()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_MARK]));
    counters->gc_finalize_prologue()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_PROLOGUE]));
    counters->gc_finalize_sweep()->AddSample(
        TruncateToMs(current_.scopes[Scope::MC_SWEEP]));
    if (!current_.incremental_marking_duration.IsZero()) {
      heap_->isolate()->counters()->incremental_marking_sum()->AddSample(
          TruncateToMs(current_.incremental_marking_duration));
    }
    DCHECK_EQ(Scope::LAST_TOP_MC_SCOPE, Scope::MC_SWEEP);
  } else if (mode == RecordGCPhasesInfo::Mode::Scavenger) {
    counters->gc_scavenger_scavenge_main()->AddSample(
        TruncateToMs(current_.scopes[Scope::SCAVENGER_SCAVENGE_PARALLEL]));
    counters->gc_scavenger_scavenge_roots()->AddSample(
        TruncateToMs(current_.scopes[Scope::SCAVENGER_SCAVENGE_ROOTS]));
  }
}

void GCTracer::RecordGCSumCounters() {
  const base::TimeDelta atomic_pause_duration =
      current_.scopes[Scope::MARK_COMPACTOR];
  const base::TimeDelta incremental_marking =
      incremental_scopes_[Scope::MC_INCREMENTAL_LAYOUT_CHANGE].duration +
      incremental_scopes_[Scope::MC_INCREMENTAL_START].duration +
      current_.incremental_marking_duration +
      incremental_scopes_[Scope::MC_INCREMENTAL_FINALIZE].duration;
  const base::TimeDelta incremental_sweeping =
      incremental_scopes_[Scope::MC_INCREMENTAL_SWEEPING].duration;
  const base::TimeDelta overall_duration =
      atomic_pause_duration + incremental_marking + incremental_sweeping;
  const base::TimeDelta atomic_marking_duration =
      current_.scopes[Scope::MC_PROLOGUE] + current_.scopes[Scope::MC_MARK];
  const base::TimeDelta marking_duration =
      atomic_marking_duration + incremental_marking;
  base::TimeDelta background_duration;
  base::TimeDelta marking_background_duration;
  {
    base::MutexGuard guard(&background_scopes_mutex_);
    background_duration =
        background_scopes_[Scope::MC_BACKGROUND_EVACUATE_COPY] +
        background_scopes_[Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS] +
        background_scopes_[Scope::MC_BACKGROUND_MARKING] +
        background_scopes_[Scope::MC_BACKGROUND_SWEEPING];
    marking_background_duration =
        background_scopes_[Scope::MC_BACKGROUND_MARKING];
  }

  recorded_major_totals_.Push(
      BytesAndDuration(current_.end_object_size, overall_duration));

  // Emit trace event counters.
  TRACE_EVENT_INSTANT2(
      TRACE_DISABLED_BY_DEFAULT("v8.gc"), "V8.GCMarkCompactorSummary",
      TRACE_EVENT_SCOPE_THREAD, "duration", overall_duration.InMillisecondsF(),
      "background_duration", background_duration.InMillisecondsF());
  TRACE_EVENT_INSTANT2(
      TRACE_DISABLED_BY_DEFAULT("v8.gc"), "V8.GCMarkCompactorMarkingSummary",
      TRACE_EVENT_SCOPE_THREAD, "duration", marking_duration.InMillisecondsF(),
      "background_duration", marking_background_duration.InMillisecondsF());
}

namespace {

void CopyTimeMetrics(
    ::v8::metrics::GarbageCollectionPhases& metrics,
    const cppgc::internal::MetricRecorder::GCCycle::IncrementalPhases&
        cppgc_metrics) {
  // Allow for uninitialized values (-1), in case incremental marking/sweeping
  // were not used.
  DCHECK_LE(-1, cppgc_metrics.mark_duration_us);
  metrics.mark_wall_clock_duration_in_us = cppgc_metrics.mark_duration_us;
  DCHECK_LE(-1, cppgc_metrics.sweep_duration_us);
  metrics.sweep_wall_clock_duration_in_us = cppgc_metrics.sweep_duration_us;
  // The total duration is initialized, even if both incremental
  // marking and sweeping were not used.
  metrics.total_wall_clock_duration_in_us =
      std::max(INT64_C(0), metrics.mark_wall_clock_duration_in_us) +
      std::max(INT64_C(0), metrics.sweep_wall_clock_duration_in_us);
}

void CopyTimeMetrics(
    ::v8::metrics::GarbageCollectionPhases& metrics,
    const cppgc::internal::MetricRecorder::GCCycle::Phases& cppgc_metrics) {
  DCHECK_NE(-1, cppgc_metrics.compact_duration_us);
  metrics.compact_wall_clock_duration_in_us = cppgc_metrics.compact_duration_us;
  DCHECK_NE(-1, cppgc_metrics.mark_duration_us);
  metrics.mark_wall_clock_duration_in_us = cppgc_metrics.mark_duration_us;
  DCHECK_NE(-1, cppgc_metrics.sweep_duration_us);
  metrics.sweep_wall_clock_duration_in_us = cppgc_metrics.sweep_duration_us;
  DCHECK_NE(-1, cppgc_metrics.weak_duration_us);
  metrics.weak_wall_clock_duration_in_us = cppgc_metrics.weak_duration_us;
  metrics.total_wall_clock_duration_in_us =
      metrics.compact_wall_clock_duration_in_us +
      metrics.mark_wall_clock_duration_in_us +
      metrics.sweep_wall_clock_duration_in_us +
      metrics.weak_wall_clock_duration_in_us;
}

void CopySizeMetrics(
    ::v8::metrics::GarbageCollectionSizes& metrics,
    const cppgc::internal::MetricRecorder::GCCycle::Sizes& cppgc_metrics) {
  DCHECK_NE(-1, cppgc_metrics.after_bytes);
  metrics.bytes_after = cppgc_metrics.after_bytes;
  DCHECK_NE(-1, cppgc_metrics.before_bytes);
  metrics.bytes_before = cppgc_metrics.before_bytes;
  DCHECK_NE(-1, cppgc_metrics.freed_bytes);
  metrics.bytes_freed = cppgc_metrics.freed_bytes;
}

::v8::metrics::Recorder::ContextId GetContextId(
    v8::internal::Isolate* isolate) {
  DCHECK_NOT_NULL(isolate);
  if (isolate->context().is_null())
    return v8::metrics::Recorder::ContextId::Empty();
  HandleScope scope(isolate);
  return isolate->GetOrRegisterRecorderContextId(isolate->native_context());
}

template <typename EventType>
void FlushBatchedEvents(
    v8::metrics::GarbageCollectionBatchedEvents<EventType>& batched_events,
    Isolate* isolate) {
  DCHECK_NOT_NULL(isolate->metrics_recorder());
  DCHECK(!batched_events.events.empty());
  isolate->metrics_recorder()->AddMainThreadEvent(std::move(batched_events),
                                                  GetContextId(isolate));
  batched_events = {};
}

}  // namespace

void GCTracer::ReportFullCycleToRecorder() {
  DCHECK(!Event::IsYoungGenerationEvent(current_.type));
  DCHECK_EQ(Event::State::NOT_RUNNING, current_.state);
  auto* cpp_heap = v8::internal::CppHeap::From(heap_->cpp_heap());
  DCHECK_IMPLIES(cpp_heap,
                 cpp_heap->GetMetricRecorder()->FullGCMetricsReportPending());
  const std::shared_ptr<metrics::Recorder>& recorder =
      heap_->isolate()->metrics_recorder();
  DCHECK_NOT_NULL(recorder);
  if (!recorder->HasEmbedderRecorder()) {
    incremental_mark_batched_events_ = {};
    incremental_sweep_batched_events_ = {};
    if (cpp_heap) {
      cpp_heap->GetMetricRecorder()->ClearCachedEvents();
    }
    return;
  }
  if (!incremental_mark_batched_events_.events.empty()) {
    FlushBatchedEvents(incremental_mark_batched_events_, heap_->isolate());
  }
  if (!incremental_sweep_batched_events_.events.empty()) {
    FlushBatchedEvents(incremental_sweep_batched_events_, heap_->isolate());
  }

  v8::metrics::GarbageCollectionFullCycle event;
  event.reason = static_cast<int>(current_.gc_reason);
  event.priority = current_.priority;

  // Managed C++ heap statistics:
  if (cpp_heap) {
    cpp_heap->GetMetricRecorder()->FlushBatchedIncrementalEvents();
    const std::optional<cppgc::internal::MetricRecorder::GCCycle>
        optional_cppgc_event =
            cpp_heap->GetMetricRecorder()->ExtractLastFullGcEvent();
    DCHECK(optional_cppgc_event.has_value());
    DCHECK(!cpp_heap->GetMetricRecorder()->FullGCMetricsReportPending());
    const cppgc::internal::MetricRecorder::GCCycle& cppgc_event =
        optional_cppgc_event.value();
    DCHECK_EQ(cppgc_event.type,
              cppgc::internal::MetricRecorder::GCCycle::Type::kMajor);
    CopyTimeMetrics(event.total_cpp, cppgc_event.total);
    CopyTimeMetrics(event.main_thread_cpp, cppgc_event.main_thread);
    CopyTimeMetrics(event.main_thread_atomic_cpp,
                    cppgc_event.main_thread_atomic);
    CopyTimeMetrics(event.main_thread_incremental_cpp,
                    cppgc_event.main_thread_incremental);
    CopySizeMetrics(event.objects_cpp, cppgc_event.objects);
    CopySizeMetrics(event.memory_cpp, cppgc_event.memory);
    DCHECK_NE(-1, cppgc_event.collection_rate_in_percent);
    event.collection_rate_cpp_in_percent =
        cppgc_event.collection_rate_in_percent;
    DCHECK_NE(-1, cppgc_event.efficiency_in_bytes_per_us);
    event.efficiency_cpp_in_bytes_per_us =
        cppgc_event.efficiency_in_bytes_per_us;
    DCHECK_NE(-1, cppgc_event.main_thread_efficiency_in_bytes_per_us);
    event.main_thread_efficiency_cpp_in_bytes_per_us =
        cppgc_event.main_thread_efficiency_in_bytes_per
"""


```