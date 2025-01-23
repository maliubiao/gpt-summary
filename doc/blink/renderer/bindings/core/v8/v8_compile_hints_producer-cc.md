Response:
The user wants to understand the functionality of the provided C++ source code file, `v8_compile_hints_producer.cc`. I need to:

1. **Identify the core purpose** of this file based on its name, included headers, and internal logic. The name strongly suggests it's involved in generating hints for the V8 JavaScript engine during compilation.
2. **Explain its relation to JavaScript, HTML, and CSS.**  Since it deals with V8 compilation, the connection to JavaScript is direct. I need to explain how these compilation hints might impact JavaScript execution. HTML and CSS interact with JavaScript, so there's an indirect relationship.
3. **Provide examples with logical reasoning (input/output).**  This will be tricky since the code interacts with V8 internals. I can create hypothetical scenarios of JavaScript code and infer how the hints might be generated.
4. **Point out common user/programming errors.**  Since this is backend code, user errors are less direct. Programming errors would likely involve incorrect usage of the API or assumptions about the data collection process.
5. **Describe the user journey to reach this code.** This involves thinking about how the browser processes web pages, leading to JavaScript execution and the potential need for compilation hints.
6. **Summarize the functionality in one sentence.** This will be the final step after understanding the details.

**Mental Sandbox:**

* **Core Function:** The code seems to collect information about script execution and then uses this information to generate "compile hints" for V8. This is likely an optimization technique.
* **JavaScript Relationship:** When a browser executes JavaScript, V8 compiles it. These hints probably guide V8 to make better compilation decisions, leading to faster execution.
* **HTML/CSS Relationship:** JavaScript often manipulates the DOM (which represents HTML) and applies CSS styles. If JavaScript execution is faster, these interactions will also be faster, leading to a more responsive user experience.
* **Input/Output (Hypothetical):**  *Input:* A JavaScript function is called frequently. *Output:* The `V8CompileHintsProducer` records this and generates a hint suggesting V8 should aggressively optimize this function.
* **User/Programming Errors:** A programmer might try to force the generation of hints in non-production environments, misunderstanding the random sampling logic.
* **User Journey:** User opens a web page -> browser parses HTML -> encounters `<script>` tags or inline JavaScript -> V8 starts compiling and executing the JavaScript -> `V8CompileHintsProducer` (if enabled and selected) observes the compilation process.

**Constraint Checklist & Confidence Score:**

1. List functionality? Yes.
2. Relation to JS/HTML/CSS? Yes.
3. Examples with reasoning? Yes (hypothetical).
4. User/programming errors? Yes.
5. User journey? Yes.
6. Summarize functionality? Yes.

Confidence Score: 4/5 (Slight uncertainty about the precision of the hypothetical examples due to the internal nature of the code).

Strategizing complete. I will now generate the response based on these insights.
这个 C++ 源代码文件 `v8_compile_hints_producer.cc` 的主要功能是**收集关于 JavaScript 代码编译的提示信息，并将这些信息上报用于优化 V8 JavaScript 引擎的未来编译行为。** 更具体地说，它旨在实现一种众包的编译提示机制。

以下是它的功能分解：

1. **决定是否收集数据:**
   - 它通过 feature flags (`features::kProduceCompileHints2`, `features::kForceProduceCompileHints`) 和随机抽样 (基于 `features::kProduceCompileHintsDataProductionLevel`) 来决定当前渲染器进程是否应该收集编译提示数据。
   - 数据收集主要在 Windows 平台上启用。
   - 每个渲染器进程只会收集一次数据。

2. **记录脚本编译信息:**
   - 当一个 JavaScript 脚本被编译时，`RecordScript` 方法会被调用。
   - 它会记录脚本的名称哈希值 (`ScriptNameHash`) 以及 V8 提供的编译提示收集器 (`script->GetCompileHintsCollector()`).
   - 它使用 `BloomFilter` 来存储收集到的函数位置信息，以节省空间和提高效率。

3. **生成并上报数据:**
   - `GenerateData` 方法负责生成最终的编译提示数据。
   - 它从 V8 的 `CompileHintsCollector` 中提取具体的编译提示（例如，哪些函数应该被优化）。
   - 它将脚本名称哈希和函数位置信息组合成哈希值，并添加到 Bloom Filter 中。
   - 为了保护隐私，会对 Bloom Filter 的数据添加噪声 (`AddNoise`).
   - 最终，它将 Bloom Filter 的数据（一系列 64 位的整数）通过 UKM (User Metrics) 系统上报。上报的数据结构是 `ukm::builders::V8CompileHints_Version5`。
   - 上报的前提是收集到的函数数量超过一定的阈值 (`kFunctionCountThreshold`)。

4. **数据清理:**
   - `ClearData` 方法用于停止数据收集并清空已收集的数据。
   - 为了避免内存占用过久，它会安排一个延时任务 (`ScheduleDataDeletionTask`)，在一段时间后自动清理数据。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接关系到 **JavaScript** 的性能优化。它通过收集实际运行的 JavaScript 代码的编译信息，来指导 V8 引擎未来如何更有效地编译 JavaScript 代码。

**举例说明:**

假设一个网站的 JavaScript 代码中有一个名为 `calculateSum` 的函数被频繁调用。

* **假设输入：** 用户访问了该网站，浏览器开始解析 HTML，并执行 `<script>` 标签中的 JavaScript 代码。V8 引擎在编译 `calculateSum` 函数时，`V8CrowdsourcedCompileHintsProducer` 开始记录相关信息。
* **逻辑推理：** `V8CompileHintsProducer` 会记录 `calculateSum` 函数在脚本中的位置，并将其哈希值添加到 Bloom Filter 中。如果足够多的用户访问了这个网站，并且他们的浏览器都上报了包含 `calculateSum` 函数编译信息的提示，那么 V8 引擎的开发者就能了解到这个函数是一个热点函数。
* **输出：**  未来，当 V8 引擎遇到 `calculateSum` 函数时，可能会根据这些众包的提示，采取更激进的优化策略，例如更早地进行即时编译 (JIT) 或者应用特定的优化技术，从而提高该函数的执行速度。

虽然这个文件不直接处理 **HTML** 或 **CSS**，但 JavaScript 经常被用来操作 DOM (HTML 结构) 和应用 CSS 样式。 因此，通过优化 JavaScript 的执行效率，这个文件可以间接地提升与 HTML 和 CSS 相关的操作性能，例如：

* 更快地动态更新页面内容 (操作 DOM)。
* 更流畅地应用 CSS 动画和过渡效果。
* 响应用户交互更快 (例如，按钮点击触发的 JavaScript 动画)。

**用户或编程常见的使用错误：**

由于这是一个底层的浏览器引擎组件，普通用户不太可能直接与之交互并产生使用错误。常见的编程错误可能包括：

* **错误地配置 feature flags：**  例如，在不应该开启数据收集的环境中强制开启，可能会导致不必要的性能开销。
* **误解随机抽样逻辑：**  开发者可能会期望在所有情况下都能收集到数据，但由于随机抽样的存在，并非每次都会收集。
* **假设立即生效：**  收集到的编译提示数据需要经过汇总、分析，并最终应用到 V8 引擎的更新中，这需要一个过程，并非立即生效。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个网页：** 用户在 Chrome 浏览器中输入网址或点击链接。
2. **浏览器请求网页资源：** 浏览器向服务器请求 HTML、CSS、JavaScript 等资源。
3. **渲染引擎解析 HTML：** Blink 渲染引擎开始解析下载的 HTML 代码，构建 DOM 树。
4. **遇到 JavaScript 代码：** 当解析到 `<script>` 标签或内联的 JavaScript 代码时，渲染引擎会通知 V8 引擎。
5. **V8 引擎编译 JavaScript：** V8 引擎开始解析和编译 JavaScript 代码。
6. **创建 V8CrowdsourcedCompileHintsProducer 对象：** 当页面被加载时，`V8CrowdsourcedCompileHintsProducer` 对象可能会被创建（取决于 feature flag 和随机抽样）。
7. **RecordScript 被调用：** 在 JavaScript 脚本编译过程中，V8 会调用 `V8CrowdsourcedCompileHintsProducer` 的 `RecordScript` 方法，将编译信息传递给它。
8. **（可选）GenerateData 被调用：**  在一定条件下（例如，页面卸载前或达到一定的时间间隔），`GenerateData` 方法会被调用，将收集到的编译提示数据上报到 UKM。

**功能归纳 (第1部分)：**

`v8_compile_hints_producer.cc` 的主要功能是作为 Blink 渲染引擎的一部分，选择性地收集当前页面中 JavaScript 代码的编译信息，并通过用户指标系统 (UKM) 上报这些信息，以用于指导和优化 V8 JavaScript 引擎未来的编译行为。它通过 feature flags 和随机抽样来控制数据收集，并使用 Bloom Filter 来高效地存储和上报收集到的编译提示。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/v8_compile_hints_producer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_producer.h"

#if BUILDFLAG(PRODUCE_V8_COMPILE_HINTS)

#include "base/rand_util.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/wtf/bloom_filter.h"

#include <limits>

namespace blink::v8_compile_hints {

std::atomic<bool>
    V8CrowdsourcedCompileHintsProducer::data_generated_for_this_process_ =
        false;

namespace {

bool RandomlySelectedToGenerateData() {
  // Data collection is only enabled on Windows. TODO(chromium:1406506): enable
  // on more platforms.
#if BUILDFLAG(IS_WIN)
  bool compile_hints_enabled =
      base::FeatureList::IsEnabled(features::kProduceCompileHints2);
  if (!compile_hints_enabled) {
    return false;
  }

  // Decide whether we collect the data based on client-side randomization.
  // This is further subject to UKM restrictions: whether the user has enabled
  // the data collection + downsampling. See crbug.com/1483975 .
  double data_production_level =
      features::kProduceCompileHintsDataProductionLevel.Get();
  return base::RandDouble() < data_production_level;
#else   //  BUILDFLAG(IS_WIN)
  return false;
#endif  //  BUILDFLAG(IS_WIN)
}

bool ShouldThisProcessGenerateData() {
  if (base::FeatureList::IsEnabled(features::kForceProduceCompileHints)) {
    return true;
  }
  static bool randomly_selected_to_generate_data =
      RandomlySelectedToGenerateData();
  return randomly_selected_to_generate_data;
}

}  // namespace

V8CrowdsourcedCompileHintsProducer::V8CrowdsourcedCompileHintsProducer(
    Page* page)
    : page_(page) {
  // Decide whether to produce the data once per renderer process.
  bool should_generate_data = ShouldThisProcessGenerateData();
  if (should_generate_data && !data_generated_for_this_process_) {
    state_ = State::kCollectingData;
  }
}

void V8CrowdsourcedCompileHintsProducer::RecordScript(
    Frame* frame,
    ExecutionContext* execution_context,
    const v8::Local<v8::Script> script,
    ScriptState* script_state) {
  if (state_ != State::kCollectingData) {
    // We've already generated data for this V8CrowdsourcedCompileHintsProducer,
    // or data generation is disabled. Don't record any script compilations.
    return;
  }
  if (data_generated_for_this_process_) {
    // We've already generated data for some other
    // V8CrowdsourcedCompileHintsProducer, so stop collecting data.
    ClearData();
    return;
  }

  v8::Isolate* isolate = execution_context->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  uint32_t script_name_hash =
      ScriptNameHash(script->GetResourceName(), context, isolate);

  compile_hints_collectors_.emplace_back(isolate,
                                         script->GetCompileHintsCollector());
  script_name_hashes_.emplace_back(script_name_hash);

  if (compile_hints_collectors_.size() == 1) {
    ScheduleDataDeletionTask(execution_context);
  }
}

void V8CrowdsourcedCompileHintsProducer::GenerateData() {
  // Guard against this function getting called repeatedly.
  if (state_ != State::kCollectingData) {
    return;
  }

  if (!data_generated_for_this_process_) {
    data_generated_for_this_process_ = SendDataToUkm();
  }

  ClearData();
}

void V8CrowdsourcedCompileHintsProducer::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(compile_hints_collectors_);
}

void V8CrowdsourcedCompileHintsProducer::ClearData() {
  // Stop logging script executions for this page.
  state_ = State::kFinishedOrDisabled;
  compile_hints_collectors_.clear();
  script_name_hashes_.clear();
}

namespace {

void ClearDataTask(V8CrowdsourcedCompileHintsProducer* producer) {
  if (producer != nullptr) {
    producer->ClearData();
  }
}

}  // namespace

void V8CrowdsourcedCompileHintsProducer::ScheduleDataDeletionTask(
    ExecutionContext* execution_context) {
  constexpr int kDeletionDelaySeconds = 30;
  auto delay = base::Seconds(kDeletionDelaySeconds);

  execution_context->GetTaskRunner(TaskType::kIdleTask)
      ->PostDelayedTask(FROM_HERE,
                        WTF::BindOnce(&ClearDataTask, WrapWeakPersistent(this)),
                        delay);
}

bool V8CrowdsourcedCompileHintsProducer::MightGenerateData() {
  if (state_ != State::kCollectingData || data_generated_for_this_process_) {
    return false;
  }

  Frame* main_frame = page_->MainFrame();
  // Because of OOPIF, the main frame is not necessarily a LocalFrame. We cannot
  // generate good compile hints, because we cannot retrieve data from other
  // processes.
  if (!main_frame->IsLocalFrame()) {
    ClearData();
    return false;
  }
  return true;
}

bool V8CrowdsourcedCompileHintsProducer::SendDataToUkm() {
  // Re-check the main frame, since it might have changed.
  Frame* main_frame = page_->MainFrame();
  if (!main_frame->IsLocalFrame()) {
    ClearData();
    return false;
  }

  ScriptState* script_state =
      ToScriptStateForMainWorld(DynamicTo<LocalFrame>(main_frame));
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  v8::Isolate* isolate = execution_context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  int total_funcs = 0;

  DCHECK_EQ(compile_hints_collectors_.size(), script_name_hashes_.size());

  // Create a Bloom filter w/ 16 key bits. This results in a Bloom filter
  // containing 2 ^ 16 bits, which equals to 1024 64-bit ints.
  static_assert((1 << kBloomFilterKeySize) / (sizeof(int32_t) * 8) ==
                kBloomFilterInt32Count);
  WTF::BloomFilter<kBloomFilterKeySize> bloom;

  for (wtf_size_t script_ix = 0; script_ix < compile_hints_collectors_.size();
       ++script_ix) {
    v8::Local<v8::CompileHintsCollector> compile_hints_collector =
        compile_hints_collectors_[script_ix].Get(isolate);
    std::vector<int> compile_hints =
        compile_hints_collector->GetCompileHints(isolate);
    for (int function_position : compile_hints) {
      uint32_t hash =
          CombineHash(script_name_hashes_[script_ix], function_position);
      bloom.Add(hash);
      ++total_funcs;
    }
  }

  // Don't clutter the data with elements with less than a threshold amount of
  // functions.
  constexpr int kFunctionCountThreshold = 100;
  if (total_funcs < kFunctionCountThreshold) {
    return false;
  }

  static_assert(sizeof(unsigned) == sizeof(int32_t));
  unsigned* raw_data = (bloom.GetRawData());

  // Add noise to the data.
  for (int i = 0; i < kBloomFilterInt32Count; ++i) {
    AddNoise(&raw_data[i]);
  }

  // Send the data to UKM.
  DCHECK_NE(execution_context->UkmSourceID(), ukm::kInvalidSourceId);
  ukm::UkmRecorder* ukm_recorder = execution_context->UkmRecorder();
  ukm::builders::V8CompileHints_Version5(execution_context->UkmSourceID())
      .SetData0(static_cast<int64_t>(raw_data[1]) << 32 | raw_data[0])
      .SetData1(static_cast<int64_t>(raw_data[3]) << 32 | raw_data[2])
      .SetData2(static_cast<int64_t>(raw_data[5]) << 32 | raw_data[4])
      .SetData3(static_cast<int64_t>(raw_data[7]) << 32 | raw_data[6])
      .SetData4(static_cast<int64_t>(raw_data[9]) << 32 | raw_data[8])
      .SetData5(static_cast<int64_t>(raw_data[11]) << 32 | raw_data[10])
      .SetData6(static_cast<int64_t>(raw_data[13]) << 32 | raw_data[12])
      .SetData7(static_cast<int64_t>(raw_data[15]) << 32 | raw_data[14])
      .SetData8(static_cast<int64_t>(raw_data[17]) << 32 | raw_data[16])
      .SetData9(static_cast<int64_t>(raw_data[19]) << 32 | raw_data[18])
      .SetData10(static_cast<int64_t>(raw_data[21]) << 32 | raw_data[20])
      .SetData11(static_cast<int64_t>(raw_data[23]) << 32 | raw_data[22])
      .SetData12(static_cast<int64_t>(raw_data[25]) << 32 | raw_data[24])
      .SetData13(static_cast<int64_t>(raw_data[27]) << 32 | raw_data[26])
      .SetData14(static_cast<int64_t>(raw_data[29]) << 32 | raw_data[28])
      .SetData15(static_cast<int64_t>(raw_data[31]) << 32 | raw_data[30])
      .SetData16(static_cast<int64_t>(raw_data[33]) << 32 | raw_data[32])
      .SetData17(static_cast<int64_t>(raw_data[35]) << 32 | raw_data[34])
      .SetData18(static_cast<int64_t>(raw_data[37]) << 32 | raw_data[36])
      .SetData19(static_cast<int64_t>(raw_data[39]) << 32 | raw_data[38])
      .SetData20(static_cast<int64_t>(raw_data[41]) << 32 | raw_data[40])
      .SetData21(static_cast<int64_t>(raw_data[43]) << 32 | raw_data[42])
      .SetData22(static_cast<int64_t>(raw_data[45]) << 32 | raw_data[44])
      .SetData23(static_cast<int64_t>(raw_data[47]) << 32 | raw_data[46])
      .SetData24(static_cast<int64_t>(raw_data[49]) << 32 | raw_data[48])
      .SetData25(static_cast<int64_t>(raw_data[51]) << 32 | raw_data[50])
      .SetData26(static_cast<int64_t>(raw_data[53]) << 32 | raw_data[52])
      .SetData27(static_cast<int64_t>(raw_data[55]) << 32 | raw_data[54])
      .SetData28(static_cast<int64_t>(raw_data[57]) << 32 | raw_data[56])
      .SetData29(static_cast<int64_t>(raw_data[59]) << 32 | raw_data[58])
      .SetData30(static_cast<int64_t>(raw_data[61]) << 32 | raw_data[60])
      .SetData31(static_cast<int64_t>(raw_data[63]) << 32 | raw_data[62])
      .SetData32(static_cast<int64_t>(raw_data[65]) << 32 | raw_data[64])
      .SetData33(static_cast<int64_t>(raw_data[67]) << 32 | raw_data[66])
      .SetData34(static_cast<int64_t>(raw_data[69]) << 32 | raw_data[68])
      .SetData35(static_cast<int64_t>(raw_data[71]) << 32 | raw_data[70])
      .SetData36(static_cast<int64_t>(raw_data[73]) << 32 | raw_data[72])
      .SetData37(static_cast<int64_t>(raw_data[75]) << 32 | raw_data[74])
      .SetData38(static_cast<int64_t>(raw_data[77]) << 32 | raw_data[76])
      .SetData39(static_cast<int64_t>(raw_data[79]) << 32 | raw_data[78])
      .SetData40(static_cast<int64_t>(raw_data[81]) << 32 | raw_data[80])
      .SetData41(static_cast<int64_t>(raw_data[83]) << 32 | raw_data[82])
      .SetData42(static_cast<int64_t>(raw_data[85]) << 32 | raw_data[84])
      .SetData43(static_cast<int64_t>(raw_data[87]) << 32 | raw_data[86])
      .SetData44(static_cast<int64_t>(raw_data[89]) << 32 | raw_data[88])
      .SetData45(static_cast<int64_t>(raw_data[91]) << 32 | raw_data[90])
      .SetData46(static_cast<int64_t>(raw_data[93]) << 32 | raw_data[92])
      .SetData47(static_cast<int64_t>(raw_data[95]) << 32 | raw_data[94])
      .SetData48(static_cast<int64_t>(raw_data[97]) << 32 | raw_data[96])
      .SetData49(static_cast<int64_t>(raw_data[99]) << 32 | raw_data[98])
      .SetData50(static_cast<int64_t>(raw_data[101]) << 32 | raw_data[100])
      .SetData51(static_cast<int64_t>(raw_data[103]) << 32 | raw_data[102])
      .SetData52(static_cast<int64_t>(raw_data[105]) << 32 | raw_data[104])
      .SetData53(static_cast<int64_t>(raw_data[107]) << 32 | raw_data[106])
      .SetData54(static_cast<int64_t>(raw_data[109]) << 32 | raw_data[108])
      .SetData55(static_cast<int64_t>(raw_data[111]) << 32 | raw_data[110])
      .SetData56(static_cast<int64_t>(raw_data[113]) << 32 | raw_data[112])
      .SetData57(static_cast<int64_t>(raw_data[115]) << 32 | raw_data[114])
      .SetData58(static_cast<int64_t>(raw_data[117]) << 32 | raw_data[116])
      .SetData59(static_cast<int64_t>(raw_data[119]) << 32 | raw_data[118])
      .SetData60(static_cast<int64_t>(raw_data[121]) << 32 | raw_data[120])
      .SetData61(static_cast<int64_t>(raw_data[123]) << 32 | raw_data[122])
      .SetData62(static_cast<int64_t>(raw_data[125]) << 32 | raw_data[124])
      .SetData63(static_cast<int64_t>(raw_data[127]) << 32 | raw_data[126])
      .SetData64(static_cast<int64_t>(raw_data[129]) << 32 | raw_data[128])
      .SetData65(static_cast<int64_t>(raw_data[131]) << 32 | raw_data[130])
      .SetData66(static_cast<int64_t>(raw_data[133]) << 32 | raw_data[132])
      .SetData67(static_cast<int64_t>(raw_data[135]) << 32 | raw_data[134])
      .SetData68(static_cast<int64_t>(raw_data[137]) << 32 | raw_data[136])
      .SetData69(static_cast<int64_t>(raw_data[139]) << 32 | raw_data[138])
      .SetData70(static_cast<int64_t>(raw_data[141]) << 32 | raw_data[140])
      .SetData71(static_cast<int64_t>(raw_data[143]) << 32 | raw_data[142])
      .SetData72(static_cast<int64_t>(raw_data[145]) << 32 | raw_data[144])
      .SetData73(static_cast<int64_t>(raw_data[147]) << 32 | raw_data[146])
      .SetData74(static_cast<int64_t>(raw_data[149]) << 32 | raw_data[148])
      .SetData75(static_cast<int64_t>(raw_data[151]) << 32 | raw_data[150])
      .SetData76(static_cast<int64_t>(raw_data[153]) << 32 | raw_data[152])
      .SetData77(static_cast<int64_t>(raw_data[155]) << 32 | raw_data[154])
      .SetData78(static_cast<int64_t>(raw_data[157]) << 32 | raw_data[156])
      .SetData79(static_cast<int64_t>(raw_data[159]) << 32 | raw_data[158])
      .SetData80(static_cast<int64_t>(raw_data[161]) << 32 | raw_data[160])
      .SetData81(static_cast<int64_t>(raw_data[163]) << 32 | raw_data[162])
      .SetData82(static_cast<int64_t>(raw_data[165]) << 32 | raw_data[164])
      .SetData83(static_cast<int64_t>(raw_data[167]) << 32 | raw_data[166])
      .SetData84(static_cast<int64_t>(raw_data[169]) << 32 | raw_data[168])
      .SetData85(static_cast<int64_t>(raw_data[171]) << 32 | raw_data[170])
      .SetData86(static_cast<int64_t>(raw_data[173]) << 32 | raw_data[172])
      .SetData87(static_cast<int64_t>(raw_data[175]) << 32 | raw_data[174])
      .SetData88(static_cast<int64_t>(raw_data[177]) << 32 | raw_data[176])
      .SetData89(static_cast<int64_t>(raw_data[179]) << 32 | raw_data[178])
      .SetData90(static_cast<int64_t>(raw_data[181]) << 32 | raw_data[180])
      .SetData91(static_cast<int64_t>(raw_data[183]) << 32 | raw_data[182])
      .SetData92(static_cast<int64_t>(raw_data[185]) << 32 | raw_data[184])
      .SetData93(static_cast<int64_t>(raw_data[187]) << 32 | raw_data[186])
      .SetData94(static_cast<int64_t>(raw_data[189]) << 32 | raw_data[188])
      .SetData95(static_cast<int64_t>(raw_data[191]) << 32 | raw_data[190])
      .SetData96(static_cast<int64_t>(raw_data[193]) << 32 | raw_data[192])
      .SetData97(static_cast<int64_t>(raw_data[195]) << 32 | raw_data[194])
      .SetData98(static_cast<int64_t>(raw_data[197]) << 32 | raw_data[196])
      .SetData99(static_cast<int64_t>(raw_data[199]) << 32 | raw_data[198])
      .SetData100(static_cast<int64_t>(raw_data[201]) << 32 | raw_data[200])
      .SetData101(static_cast<int64_t>(raw_data[203]) << 32 | raw_data[202])
      .SetData102(static_cast<int64_t>(raw_data[205]) << 32 | raw_data[204])
      .SetData103(static_cast<int64_t>(raw_data[207]) << 32 | raw_data[206])
      .SetData104(static_cast<int64_t>(raw_data[209]) << 32 | raw_data[208])
      .SetData105(static_cast<int64_t>(raw_data[211]) << 32 | raw_data[210])
      .SetData106(static_cast<int64_t>(raw_data[213]) << 32 | raw_data[212])
      .SetData107(static_cast<int64_t>(raw_data[215]) << 32 | raw_data[214])
      .SetData108(static_cast<int64_t>(raw_data[217]) << 32 | raw_data[216])
      .SetData109(static_cast<int64_t>(raw_data[219]) << 32 | raw_data[218])
      .SetData110(static_cast<int64_t>(raw_data[221]) << 32 | raw_data[220])
      .SetData111(static_cast<int64_t>(raw_data[223]) << 32 | raw_data[222])
      .SetData112(static_cast<int64_t>(raw_data[225]) << 32 | raw_data[224])
      .SetData113(static_cast<int64_t>(raw_data[227]) << 32 | raw_data[226])
      .SetData114(static_cast<int64_t>(raw_data[229]) << 32 | raw_data[228])
      .SetData115(static_cast<int64_t>(raw_data[231]) << 32 | raw_data[230])
      .SetData116(static_cast<int64_t>(raw_data[233]) << 32 | raw_data[232])
      .SetData117(static_cast<int64_t>(raw_data[235]) << 32 | raw_data[234])
      .SetData118(static_cast<int64_t>(raw_data[237]) << 32 | raw_data[236])
      .SetData119(static_cast<int64_t>(raw_data[239]) << 32 | raw_data[238])
      .SetData120(static_cast<int64_t>(raw_data[241]) << 32 | raw_data[240])
      .SetData121(static_cast<int64_t>(raw_data[243]) << 32 | raw_data[242])
      .SetData122(static_cast<int64_t>(raw_data[245]) << 32 | raw_data[244])
      .SetData123(static_cast<int64_t>(raw_data[247]) << 32 | raw_data[246])
      .SetData124(static_cast<int64_t>(raw_data[249]) << 32 | raw_data[248])
      .SetData125(static_cast<int64_t>(raw_data[251]) << 32 | raw_data[250])
      .SetData126(static_cast<int64_t>(raw_data[253]) << 32 | raw_data[252])
      .SetData127(static_cast<int64_t>(raw_data[255]) << 32 | raw_data[254])
      .SetData128(static_cast<int64_t>(raw_data[257]) << 32 | raw_data[256])
      .SetData129(static_cast<int64_t>(raw_data[259]) << 32 | raw_data[258])
      .SetData130(static_cast<int64_t>(raw_data[261]) << 32 | raw_data[260])
      .SetData131(static_cast<int64_t>(raw_data[263]) << 32 | raw_data[262])
      .SetData132(static_cast<int64_t>(raw_data[265]) << 32 | raw_data[264])
      .SetData133(static_cast<int64_t>(raw_data[267]) << 32 | raw_data[266])
      .SetData134(static_cast<int64_t>(raw_data[269]) << 32 | raw_data[268])
      .SetData135(static_cast<int64_t>(raw_data[271]) << 32 | raw_data[270])
      .SetData136(static_cast<int64_t>(raw_data[273]) << 32 | raw_data[272])
      .SetData137(static_cast<int64_t>(raw_data[275]) << 32 | raw_data[274])
      .SetData138(static_cast<int64_t>(raw_data[277]) << 32 | raw_data[276])
      .SetData139(static_cast<int64_t>(raw_data[279]) << 32 | raw_data[278])
      .SetData140(static_cast<int64_t>(raw_data[281]) << 32 | raw_data[280])
      .SetData141(static_cast<int64_t>(raw_data[283]) << 32 | raw_data[282])
      .SetData142(static_cast<int64_t>(raw_data[285]) << 32 | raw_data[284])
      .SetData143(static_cast<int64_t>(raw_data[287]) << 32 | raw_data[286])
      .SetData144(static_cast<int64_t>(raw_data[289]) << 32 | raw_data[288])
      .SetData145(static_cast<int64_t>(raw_data[291]) << 32 | raw_data[290])
      .SetData146(static_cast<int64_t>(raw_data[293]) << 32 | raw_data[292])
      .SetData147(static_cast<int64_t>(raw_data[295]) << 32 | raw_data[294])
      .SetData148(static_cast<int64_t>(raw_data[297]) << 32 | raw_data[296])
      .SetData149(static_cast<int64_t>(raw_data[299]) << 32 | raw_data[298])
      .SetData150(static_cast<int64_t>(raw_data[301]) << 32 | raw_data[300])
      .SetData151(static_cast<int64_t>(raw_data[303]) << 32 | raw_data[302])
      .SetData152(static_cast<int64_t>(raw_data[305]) << 32 | raw_data[304])
      .SetData153(static_cast<int64_t>(raw_data[307]) << 32 | raw_data[306])
      .SetData154(static_cast<int64_t>(raw_data[309]) << 32 | raw_data[308])
      .SetData155(static_cast<int64_t>(raw_data[311]) << 32 | raw_data[310])
      .SetData156(static_cast<int64_t>(raw_data[313]) << 32 | raw_data[312])
      .SetData157(static_cast<int64_t>(raw_data[315]) << 32 | raw_data[314])
      .SetData158(static_cast<int64_t>(raw_data[317]) << 32 | raw_data[316])
      .SetData159(static_cast<int64_t>(raw_data[319]) << 32 | raw_data[318])
      .SetData160(static_cast<int64_t>(raw_data[321]) << 32 | raw_data[320])
      .SetData161(static_cast<int64_t>(raw_data[323]) << 32 | raw_data[322])
      .SetData162(static_cast<int64_t>(raw_data[325]) << 32 | raw_data[324])
      .SetData163(static_cast<int64_t>(raw_data[327]) << 32 | raw_data[326])
      .SetData164(static_cast<int64_t>(raw_data[329]) << 32 | raw_data[328])
      .SetData165(static_cast<int64_t>(raw_data[331]) << 32 | raw_data[330])
      .SetData166(static_cast<int64_t>(raw_data[333]) << 32 | raw_data[332])
      .SetData167(static_cast<int64_t>(raw_data[335]) << 32 | raw_data[334])
      .SetData168(static_cast<int64_t>(raw_data[337]) << 32 | raw_data[336])
      .SetData169(static_cast<int64_t>(raw_data[339]) << 32 | raw_data[338])
      .SetData170(static_cast<int64_t>(raw_data[341]) << 32 | raw_data[340])
      .SetData171(static_cast<int64_t>(raw_data[343]) << 32 | raw_data[342])
      .SetData172(static_cast<int64_t>(raw_data[345]) << 32 | raw_data[344])
      .SetData173(static_cast<int64_t>(raw_data[347]) << 32 | raw_data[346])
      .SetData174(static_cast<int64_t>(raw_data[349]) << 32 | raw_data[348])
      .SetData175(static_cast<int64_t>(raw_data[351]) << 32 | raw_data[350])
      .SetData176(static_cast<int64_t>(raw_data[353]) << 32 | raw_data[352])
      .SetData177(static_cast<int64_t>(raw_data[355]) << 32 | raw_data[354])
      .SetData178(static_cast<int64_t>(raw_data[357]) << 32 | raw_data[356])
      .SetData179(static_cast<int64_t>(raw_data[359]) << 32 | raw_data[358])
      .SetData180(static_cast<int64_t>(raw_data[361]) << 32 | raw_data[360])
      .SetData181(static_cast<int64_t>(raw_data[363]) << 32 | raw_data[362])
      .SetData182(static_cast<int64_t>(raw_data[365]) << 32 | raw_data[364])
      .SetData183(static_cast<int64_t>(raw_data[367]) << 32 | raw_data[366])
      .SetData184(static_cast<int64_t>(raw_data[369]) << 32 | raw_data[368])
      .SetData185(static_cast<int64_t>(raw_data[371]) << 32 | raw_data[370])
      .SetData186(static_cast<int64_t>(raw_data[373]) << 32 | raw_data[372])
      .SetData187(static_cast<int64_t>(raw_data[375]) << 32 | raw_data[374])
      .SetData188(static_cast<int64_t>(raw_data[377]) << 32 | raw_data[376])
      .SetData189(static_cast<int64_t>(raw_data[379]) << 32 | raw_data[378])
      .SetData190(static_cast<int64_t>(raw_data[381]) << 32 | raw_data[380])
      .SetData191(static_cast<int64_t>(raw_data[383]) << 32 | raw_data[382])
      .SetData192(static_cast<int64_t>(raw_data[385]) << 32 | raw_data[384])
      .SetData193(static_cast<int64_t>(raw_data[387]) << 32 | raw_data[386])
      .SetData194(static_cast<int64_t>(raw_data[389]) << 32 | raw_data[388])
      .SetData195(static_cast<int64_t>(raw_data[391]) << 32 | raw_data[390])
      .SetData196(static_cast<int64_t>(raw_data[393]) << 32 | raw_data[392])
      .SetData197(static_cast<int64_t>(raw_data[395]) << 32 | raw_data[394])
      .SetData198(static_cast<int64_t>(raw_data[397]) << 32 | raw_data[396])
      .SetData199(static_cast<int64_t>(raw_data[399]) << 32 | raw_data[398])
      .SetData200(static_cast<int64_t>(raw_data[401]) << 32 | raw_data[400])
      .SetData201(static_cast<int64_t>(raw_data[403]) << 32 | raw_data[402])
      .SetData202(static_cast<int64_t>(raw_data[405]) << 32 | raw_data[404])
      .SetData203(static_cast<int64_t>(raw_data[407]) << 32 | raw_data[406])
      .SetData204(static_cast<int64_t>(raw_data[409]) << 32 | raw_data[408])
      .SetData205(static_cast<int64_t>(raw_data[411]) << 32 | raw_data[410])
      .SetData206(static_cast<int64_t>(raw_data[413]) << 32 | raw_data[412])
      .SetData207(static_cast<int64_t>(raw_data[415]) << 32 | raw_data[414])
      .SetData208(static_cast<int64_t>(raw_data[417]) << 32 | raw_data[416])
      .SetData209(static_cast<int64_t>(raw_data[419]) << 32 | raw_data[418])
      .SetData210(static_cast<int64_t>(raw_data[421]) << 32 | raw_data[420])
      .SetData211(static_cast<int64_t>(raw_data[423]) << 32 | raw_data[422])
      .SetData212(static_cast<int64_t>(raw_data[425]) << 32 | raw_data[424])
      .SetData213(static_cast<int64_t>(raw_data[427]) << 32 | raw_data[426])
      .SetData214(static_cast<int64_t>(raw_data[429]) << 32 | raw_data[428])
      .SetData215(static_cast<int64_t>(raw_data[431]) << 32 | raw_data[430])
      .SetData216(static_cast<int64_t>(raw_data[433]) << 32 | raw_data[432])
      .SetData217(static_cast<int64_t>(raw_data[435]) << 32 | raw_data[434])
      .SetData218(static_cast<int64_t>(raw_data[437]) << 32 | raw_data[436])
      .SetData219(static_cast<int64_t>(raw_data[439]) << 32 | raw_data[438])
      .SetData220(static_cast<int64_t>(raw_data[441]) << 32 | raw_data[440])
      .SetData221(static_cast<int64_t>(raw_data[443]) << 32 | raw_data[442])
      .SetData222(static_cast<int64_t>(raw_data[445]) << 32 | raw_data[444])
      .SetData223(static_cast<int64_t>(raw_data[447]) << 32 | raw_data[446])
      .SetData224(static_cast<int64_t>(raw_data[449]) << 32 | raw_data[448])
      .SetData225(static_cast<int64_t>(raw_data[451]) << 32 | raw_data[450])
      .SetData226(static_cast<int64_t>(raw_data[453]) << 32 | raw_data[452])
      .SetData227(static_cast<int64_t>(raw_data[455]) << 32 | raw_data[454])
      .SetData228(static_cast<int64_t>(raw_data[457]) << 32 | raw_data[456])
      .SetData229(static_cast<int64_t>(raw_data[459]) << 32 | raw_data[458])
      .SetData230(static_cast<int64_t>(raw_data[461]) << 32 | raw_data[460])
      .SetData231(static_cast<int64_t>(raw_data[463]) << 32 | raw_data[462])
      .SetData232(static_cast<int64_t>(raw_data[465]) << 32 | raw_data[464])
      .SetData233(static_cast<int64_t>(raw_data[467]) << 32 | raw_data[466])
      .SetData234(static_cast<int64_t>(raw_data[469]) << 32 | raw_data[468])
      .SetData235(static_cast<int64_t>(raw_data[471]) << 32 | raw_data[470])
      .SetData236(static_cast<int64_t>(raw_data[473]) << 32 | raw_data[472])
      .SetData237(static_cast<int64_t>(raw_data[475]) << 32 | raw_data[474])
      .SetData238(static_cast<int64_t>(raw_data[477]) << 32 | raw_data[476])
      .SetData239(static_cast<int64_t>(raw_data[479]) << 32 | raw_data[478])
      .SetData240(static_cast<int64_t>(raw_data[481]) << 32 | raw_data[480])
      .SetData241(static_cast<int64_t>(raw_data[483]) << 32 | raw_data[482])
      .SetData242(static_cast<int64_t>(raw_data[485]) << 32 | raw_data[484])
      .SetData243(static_cast<int64_t>(raw_data[487]) << 32 | raw_data[486])
      .SetData244(static_cast<int64_t>(raw_data[489]) << 32 | raw_data[488])
      .SetData245(static_cast<int64_t>(raw_data[491]) << 32 | raw_data[490])
      .SetData246(static_cast<int64_t>(raw_data[493]) << 32 | raw_data[492])
      .SetData247(static_cast<int64_t>(raw_data[495]) << 32 | raw_data[494])
      .SetData248(static_cast<int64_t>(raw_data[497]) << 32 | raw_data[496])
      .SetData249(static_cast<int64_t>(raw_data[499]) << 32 | raw_data[498])
      .SetData250(static_cast<int64_t>(raw_data[501]) << 32 | raw_data[500])
      .SetData251(static_cast<int64_t>(raw_data[503]) << 32 | raw_data[502])
      .SetData252(static_cast<int64_t>(raw_data[505]) << 32 | raw_data[504])
      .SetData253(static_cast<int64_t>(raw_data[507]) << 32 | raw_data[506])
      .SetData254(static_cast<int64_t>(raw_data[509]) << 32 | raw_data[508])
      .SetData255(static_cast<int64_t>(raw_data[511]) << 32 | raw_data[510])
      .SetData256(static_cast<int64_t>(raw_data[513]) << 32 | raw_data[512])
      .SetData257(static_cast<int64_t>(raw_data[515]) << 32 | raw_data[514])
      .SetData258(static_cast<int64_t>(raw_data[517]) << 32 | raw_data[516])
      .SetData259(static_cast<int64_t>(raw_data[519]) << 32 | raw_data[518])
      .SetData260(static_cast<int64_t>(raw_data[521]) << 32 | raw_data[520])
      .SetData261(static_cast<int64_t>(raw_data[523]) << 32 | raw_data[522])
      .SetData262(static_cast<int64_t>(raw_data[525]) << 32 | raw_data[524])
      .SetData263(static_cast<int64_t>(raw_data[527]) << 32 | raw_data[526])
      .SetData264(static_cast<int64_t>(raw_data[529]) << 32 | raw_data[528])
      .SetData265(static_cast<int64_t>(raw_data[531]) << 32 | raw_data[530])
      .SetData266(static_cast<int64_t>(raw_data[533]) << 32 | raw_data[532])
      .SetData267(static_cast<int64_t>(raw_data[535]) << 32 | raw_data[534])
      .SetData268(static_cast<int64_t>(raw_data[537]) << 32 | raw_data[536])
      .SetData269(static_cast<int64_t>(raw_data[539]) << 32 | raw_data[538])
      .SetData270(static_cast<int64_t>(raw_data[541]) << 32 | raw_data[540])
      .SetData271(static_cast<int64_t>(raw_data[543]) << 32 | raw_data[542])
      .SetData272(static_cast<int64_t>(raw_data[545]) << 32 | raw_data[544])
      .SetData273(static_cast<int64_t>(raw_data[547]) << 32 | raw_data[546])
      .SetData274(static_cast<int64_t>(raw_data[549]) << 32 | raw_data[548])
      .SetData275(static_cast<int64_t>(raw_data[551]) << 32 | raw_data[550])
      .SetData276(static_cast<int64_t>(raw_data[553]) << 32 | raw_data[552])
      .SetData277(static_cast<int64_t>(raw_data[555]) << 32 | raw_data[554])
      .SetData278(static_cast<int64_t>(raw_data[557]) << 32 | raw_data[556])
      .SetData279(static_cast<int64_t>(raw_data[559]) << 32 | raw_data[558])
      .SetData280(static_cast<int64_t>(raw_data[561]) << 32 | raw_data[560])
      .SetData281(static_cast<int64_t>(raw_data[563]) << 32 | raw_data[562])
      .SetData282(static_cast<int64_t>(raw_data[565]) << 32 | raw_data[564])
      .SetData283(static_cast<int64_t>(raw_data[567]) << 32 | raw_data[566])
      .SetData284(static_cast<int64_t>(raw_data[569]) << 32 | raw_data[568])
      .SetData285(static_cast<int64_t>(raw_data[571]) << 32 | raw_data[570])
      .SetData286(static_cast<int64_t>(raw_data[573]) << 32 | raw_data[572])
      .SetData287(static_cast<int64_t>(raw_data[575]) << 32 | raw_data[574])
      .SetData288(static_cast<int64_t>(raw_data[577]) << 32 | raw_data[576])
      .SetData289(static_cast<int64_t>(raw_data[579]) << 32 | raw_data[578])
      .SetData290(static_cast<int64_t>(raw_data[581]) << 32 | raw_data[580])
      .SetData291(static_cast<int64_t>(raw_data[583]) << 32 | raw_data[582])
      .SetData292(static_cast<int64_t>(raw_data[585]) << 32 | raw_data[584])
      .SetData293(static_cast<int64_t>(raw_data[587]) << 32 | raw_data[586])
      .SetData294(static_cast<int64_t>(raw_data[589]) << 32 | raw_data[588])
      .SetData295(static_cast<int64_t>(raw_data[591]) << 32 | raw_data[590])
      .SetData296(static_cast<int64_t>(raw_data[593]) << 32 | raw_data[592])
      .SetData297(static_cast<int64_t>(raw_data[595]) << 32 | raw_data[594])
      .SetData298(static_cast<int64_t>(raw_data[597]) << 32 | raw_data[596])
      .SetData299(static_cast<int64_t>(raw_data[599]) << 32 | raw_data[598])
      .SetData300(static_cast<int64_t>(raw_data[601]) << 32 | raw_data[600])
      .SetData301(static_cast<int64_t>(raw_data[603]) << 32 | raw_data[602])
      .SetData302(static_cast<int64_t>(raw_data[605]) << 32 | raw_data[604])
      .SetData303(static_cast<int64_t>(raw_data[607]) << 32 | raw_data[606])
      .SetData304(static_cast<int64_t>(raw_data[609]) << 32 | raw_data[608])
      .SetData305(static_cast<int64_t>(raw_data[611]) << 32 | raw_data[610])
      .SetData306(static_cast<int64_t>(raw_data[613]) << 32 | raw_data[612])
      .SetData307(static_cast<int64_t>(raw_data[615]) << 32 | raw_data[614])
      .SetData308(static_cast<int64_t>(raw_data[617]) << 32 | raw_data[616])
      .SetData309(static_cast<int64_t>(raw_data[619]) << 32 | raw_data[618])
      .SetData310(static_cast<int64_t>(raw_data[621]) << 32 | raw_data[620])
      .SetData311(static_cast<int64_t>(raw_data[623]) << 32 | raw_data[622])
      .SetData312(static_cast<int64_t>(raw_data[625]) << 32 | raw_data[624])
      .SetData313(static_cast<int64_t>(raw_data[627]) << 32 | raw_data[626])
      .SetData314(static_cast<int64_t>(raw_data[629]) << 32 | raw_data[628])
      .SetData315(static_cast<int64_t>(raw_data[631]) << 32 | raw_data[630])
      .SetData316(static_cast<int64_t>(raw_data[633]) << 32 | raw_data[632])
      .SetData317(static_cast<int64_t>(raw_data[635]) << 32 | raw_data[634])
      .SetData318(static_cast<int64_t>(raw_data[637]) << 32 | raw_data[636])
      .SetData319(static_cast<int64_t>(raw_data[639]) << 32 | raw_data[638])
      .SetData320(static_cast<int64_t>(raw_data[641]) << 32 | raw_data[640])
      .SetData321(static_cast<int64_t>(raw_data[643]) << 32 | raw_data[642])
      .SetData322(static_cast<int64_t>(raw_data[645]) << 32 | raw_data[644])
      .SetData323(static_cast<int64_t>(raw_data[647]) << 32 | raw_data[646])
      .SetData324(static_cast<int64_t>(raw_data[649]) << 32 | raw_data[648])
      .SetData325(static_cast<int64_t>(raw_data[651]) << 32 | raw_data[650])
      .SetData326(static_cast<int64_t>(raw_data[653]) << 32 | raw_data[652])
      .SetData327(static_cast<int64_t>(raw_data[655]) << 32 | raw_data[654])
      .SetData328(static_cast<int64_t>(raw_data[657]) << 32 | raw_data[656])
      .SetData329(static_cast<int64_t>(raw_data[659])
```