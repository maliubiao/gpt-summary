Response:
Let's break down the thought process for answering the prompt about `res_stats.c`.

**1. Understanding the Goal:**

The core request is to analyze the functionality of the `res_stats.c` file within the context of Android's Bionic library, particularly focusing on its role in DNS resolution, its relationship to the Android framework, and potential usage/debugging scenarios. The prompt specifically asks for explanations of libc functions, dynamic linking aspects, example usage errors, and how to reach this code from higher levels (Android framework/NDK).

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for key terms and patterns. I'd notice:

* **Includes:** `stdbool.h`, `arpa/nameser.h`, `string.h`, `async_safe/log.h`, `isc/eventlib.h`, `resolv_stats.h`. These reveal dependencies on basic C libraries, DNS-related headers, Android's async logging, and an internal event library. The presence of `resolv_stats.h` indicates this file implements functionality defined in that header.
* **Function Names:** `_res_stats_calculate_rtt`, `_res_stats_set_sample`, `_res_stats_clear_samples`, `android_net_res_stats_aggregate`, `_res_stats_usable_server`, `android_net_res_stats_get_usable_servers`. The naming convention suggests internal helper functions (starting with `_`) and public-facing functions (starting with `android_net_`). These function names clearly relate to collecting and analyzing DNS resolution statistics.
* **Data Structures:** `struct timespec`, `struct __res_sample`, `struct __res_stats`, `struct __res_params`. These are the key data structures the code operates on. The `__res_` prefix suggests they are part of the resolver implementation.
* **Constants/Macros:** `DBG`, `RCODE_TIMEOUT`, `RCODE_INTERNAL_ERROR`. These suggest debugging flags and specific DNS response codes.
* **Logic:**  Loops, conditional statements (especially `switch` on `rcode`), calculations involving time differences, comparisons against thresholds. The logic seems to revolve around tracking success and failure rates for DNS servers.

**3. Deconstructing Function by Function:**

Next, I'd analyze each function in detail:

* **`_res_stats_calculate_rtt`:**  This is straightforward time difference calculation. I'd note the conversion to milliseconds and highlight the use of `timespec`.
* **`_res_stats_set_sample`:**  This function populates a `__res_sample` structure with the response code, current time, and round-trip time. The debug logging is also important to note.
* **`_res_stats_clear_samples`:**  This resets the sample counters, effectively clearing the history for a server.
* **`android_net_res_stats_aggregate`:** This is the core aggregation function. I'd carefully trace the `switch` statement on `rcode` to understand how different response codes are categorized as successes, errors, timeouts, or internal errors. The calculation of `rtt_avg` and the tracking of `last_sample_time` are also key.
* **`_res_stats_usable_server`:**  This function makes the decision of whether a server is considered "usable" based on the aggregated statistics. I'd pay close attention to the conditions for marking a server as unusable (too many errors or timeouts, low success rate, and handling of stale samples). The logic for retrying stale servers vs. ignoring them is important.
* **`android_net_res_stats_get_usable_servers`:** This iterates through a list of servers and uses `_res_stats_usable_server` to determine which ones are usable. The fallback behavior of considering all servers usable if none are initially deemed so is a critical detail.

**4. Identifying Connections to Android Features:**

With an understanding of the functions, I'd start connecting them to Android features:

* **DNS Resolution:** The core functionality clearly relates to DNS resolution, so I'd mention how this code helps Android choose reliable DNS servers.
* **Network Connectivity:**  The statistics collected contribute to Android's overall assessment of network connectivity. A flaky DNS server impacts the user experience.
* **`async_safe_log`:**  This immediately points to Android's logging system. I'd explain that these logs are visible through `adb logcat`.
* **Bionic:** Since this file is part of Bionic, it's a low-level component used by higher-level Android services and applications.

**5. Addressing Specific Prompt Requirements:**

* **Libc Function Explanation:** For `timespec`, I'd explain its role in high-resolution timekeeping. For `string.h` functions (although not explicitly used heavily here, its inclusion suggests potential use elsewhere in the resolver), I'd give a general overview.
* **Dynamic Linker:** This is a trickier part. While this specific file doesn't have explicit dynamic linking calls, the fact that it's part of `libc.so` means it's *linked* dynamically. I'd explain the general concept of shared libraries, the role of the dynamic linker, and provide a sample `libc.so` layout. The linking process would involve the linker resolving symbols at runtime.
* **Assumed Inputs and Outputs:** For `_res_stats_usable_server`, I'd create example scenarios with different success/error/timeout counts and demonstrate how the function would determine usability based on the parameters.
* **Common Usage Errors:**  This requires thinking about how a developer *might* interact with DNS settings or experience DNS-related issues. Incorrect DNS server configuration in Wi-Fi settings or VPN apps comes to mind.
* **Android Framework/NDK Path:**  This involves tracing the layers. A user initiates a network request (e.g., opening a webpage). The Android framework's networking components (like `ConnectivityService` and `NetworkStack`) would eventually call into Bionic's resolver functions, which use this statistics code. For the NDK, a C/C++ app could directly use Bionic's DNS functions.
* **Frida Hook Example:**  I'd create a simple Frida script that hooks one of the key functions (like `android_net_res_stats_aggregate`) to observe its inputs and outputs at runtime.

**6. Structuring the Answer:**

Finally, I'd organize the information logically, using headings and bullet points for clarity. I'd start with a general overview of the file's purpose, then delve into the details of each function, address the Android-specific aspects, and conclude with the usage/debugging information. Using the provided Chinese language was a crucial requirement throughout the entire process.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file directly manages the list of DNS servers. **Correction:**  It seems more focused on *evaluating* the reliability of existing configured servers.
* **Initial thought:** Focus heavily on low-level details of timekeeping. **Correction:** While important, the higher-level purpose of the code (DNS server reliability) is more central to the request.
* **Ensuring clarity:**  Double-checking the explanations for technical terms like "dynamic linker" and "DNS resolution" to make them understandable to a broader audience.

By following these steps, combining code analysis with contextual knowledge of Android, and addressing each aspect of the prompt, a comprehensive and accurate answer can be constructed.
## 对 `bionic/libc/dns/resolv/res_stats.c` 源代码的分析

该文件 `res_stats.c` 位于 Android Bionic C 库的 DNS 解析器 (`resolv`) 目录下，其主要功能是 **收集和分析 DNS 服务器的统计信息，用于评估其可用性和性能。**  Bionic 库是 Android 系统的核心底层库，提供了 C 标准库的实现以及与操作系统交互的功能。

**主要功能：**

1. **计算往返时间 (RTT)：**  `_res_stats_calculate_rtt` 函数计算 DNS 查询的往返时间，这是衡量服务器响应速度的重要指标。
2. **记录样本数据：** `_res_stats_set_sample` 函数记录单个 DNS 查询的结果，包括响应代码 (rcode)、查询时间以及计算出的 RTT。
3. **清除样本数据：** `_res_stats_clear_samples` 函数清除指定服务器的所有已记录的样本数据，用于重新评估服务器状态。
4. **聚合统计信息：** `android_net_res_stats_aggregate` 函数基于存储的样本数据，聚合出 DNS 服务器的成功次数、错误次数、超时次数、内部错误次数、平均 RTT 以及最后一次采样时间。
5. **判断服务器是否可用：** `_res_stats_usable_server` 函数根据聚合的统计信息和预定义的参数，判断一个 DNS 服务器是否被认为是可用的。这涉及到成功率、错误率、超时率以及样本数据的时效性等因素。
6. **获取可用服务器列表：** `android_net_res_stats_get_usable_servers` 函数遍历所有配置的 DNS 服务器，并使用 `_res_stats_usable_server` 函数判断哪些服务器是可用的，最终返回一个布尔数组表示每个服务器的可用状态。

**与 Android 功能的关系及举例说明：**

该文件直接影响 Android 设备的网络连接质量和 DNS 解析的效率。

* **网络连接稳定性：** Android 系统使用这些统计信息来动态选择最佳的 DNS 服务器。如果一个 DNS 服务器频繁返回错误或超时，系统可能会暂时或永久地将其标记为不可用，并切换到其他可用的服务器，从而提高网络连接的稳定性。 例如，当用户访问一个网站时，如果首选 DNS 服务器出现故障，Android 可以快速切换到其他健康的 DNS 服务器，减少用户访问延迟或连接失败的可能性。
* **DNS 解析效率：** 通过跟踪 RTT，Android 可以倾向于选择响应速度更快的 DNS 服务器，从而加快网页加载速度和应用的网络请求速度。例如，如果用户在地理位置上靠近某个 DNS 服务器，其 RTT 会更低，Android 可能会优先选择该服务器。
* **避免故障 DNS 服务器：** 当 DNS 服务器出现严重故障，例如持续返回 SERVFAIL 错误，Android 可以及时将其标记为不可用，避免用户受到影响。例如，某个运营商的 DNS 服务器遭受攻击导致大量解析失败，Android 设备可以自动避开该服务器。

**libc 函数的功能实现：**

* **`struct timespec` (来自 `<time.h>` 或 `<sys/time.h>`):**  用于表示高精度的时间，包含秒 (`tv_sec`) 和纳秒 (`tv_nsec`) 两个成员。在 `_res_stats_calculate_rtt` 中，它被用来记录 DNS 查询开始和结束的时间点，以便计算时间差。
    * **实现原理：** `timespec` 结构体的具体实现取决于操作系统。在 Linux 内核中，它通常直接映射到内核提供的表示时间的数据结构。获取当前时间填充 `timespec` 通常使用 `clock_gettime()` 系统调用，它可以获取不同时钟源的时间。
* **`string.h` 中的函数 (如 `memset`, `memcpy` 等):**  虽然在这个文件中没有直接使用 `string.h` 中的函数，但在实际的 DNS 解析器实现中，这些函数经常被用于操作字符串，例如拷贝域名、构建 DNS 查询报文等。
    * **实现原理：** 这些函数通常是汇编语言编写的，以保证效率。例如，`memcpy` 会根据数据大小选择不同的拷贝策略（例如，使用 CPU 的 SIMD 指令进行批量拷贝）。
* **`async_safe/log.h` 中的 `async_safe_format_log`:**  用于在异步信号处理程序中安全地输出日志信息到 Android 的系统日志 (logcat)。
    * **实现原理：**  传统的 `printf` 等日志函数在信号处理程序中可能不是线程安全的。`async_safe_format_log` 使用原子操作和无锁机制，确保在信号处理程序中调用是安全的。它通常会将日志信息写入一个环形缓冲区，然后由专门的日志守护进程读取并输出。

**涉及 dynamic linker 的功能：**

这个 `res_stats.c` 文件本身并不直接包含与 dynamic linker 交互的代码。然而，作为 `libc.so` 的一部分，它的代码在程序运行时会被 dynamic linker 加载和链接。

**so 布局样本 (简化版):**

```
libc.so:
    .text          # 存放可执行代码
        _res_stats_calculate_rtt
        _res_stats_set_sample
        ...
        android_net_res_stats_aggregate
        ...
    .rodata        # 存放只读数据 (例如字符串常量)
    .data          # 存放已初始化的全局变量和静态变量
    .bss           # 存放未初始化的全局变量和静态变量
    .dynamic       # 存放动态链接信息
        NEEDED      libm.so  # 可能依赖的库
        SONAME      libc.so
        SYMTAB      # 符号表
        STRTAB      # 字符串表
        ...
```

**链接的处理过程：**

1. **加载：** 当一个 Android 应用程序启动时，zygote 进程会 fork 出新的进程。Dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被内核加载到进程的地址空间。
2. **依赖分析：** Dynamic linker 读取应用程序的 ELF 头，识别出它所依赖的共享库，例如 `libc.so`。
3. **查找共享库：** Dynamic linker 会在预定义的路径下（例如 `/system/lib64`, `/vendor/lib64` 等）查找 `libc.so`。
4. **加载共享库：**  Dynamic linker 将 `libc.so` 加载到进程的地址空间中。
5. **符号解析：** Dynamic linker 解析应用程序和 `libc.so` 的符号表，将应用程序中引用的 `libc.so` 中的函数（例如 `_res_stats_calculate_rtt`）的地址链接到应用程序的调用点。这个过程也称为重定位。
6. **执行：**  一旦链接完成，应用程序就可以安全地调用 `libc.so` 中提供的函数了。

**假设输入与输出 (以 `_res_stats_usable_server` 为例):**

**假设输入：**

* `params`: 一个 `struct __res_params` 结构体，包含以下参数：
    * `min_samples = 5` (至少需要 5 个样本才能进行评估)
    * `success_threshold = 60` (成功率需要达到 60% 以上才认为可用)
    * `sample_validity = 300` (样本数据有效期为 300 秒)
* `stats`: 一个 `struct __res_stats` 结构体，包含以下样本数据：
    * `sample_count = 7`
    * `samples`: 包含 7 个 `struct __res_sample`，其中：
        * 5 个样本的 `rcode` 为 `NOERROR`， `rtt` 分别为 50, 60, 70, 80, 90
        * 2 个样本的 `rcode` 为 `SERVFAIL`， `rtt` 分别为 100, 110
    * `sample_next = 0`
    * 假设最后一次成功采样时间为 100 秒前。

**逻辑推理：**

1. `android_net_res_stats_aggregate` 会被调用，计算出：
    * `successes = 5`
    * `errors = 2`
    * `timeouts = 0`
    * `internal_errors = 0`
    * `rtt_avg = (50 + 60 + 70 + 80 + 90) / 5 = 70`
    * `last_sample_time` 为最近一次采样的时间。
2. `total = successes + errors + timeouts = 5 + 2 + 0 = 7`
3. `total >= params->min_samples` (7 >= 5)，满足条件。
4. `errors > 0` (2 > 0)，满足条件。
5. `success_rate = successes * 100 / total = 5 * 100 / 7 = 71%`
6. `success_rate >= params->success_threshold` (71 >= 60)，满足条件。
7. 由于样本数据不是很久远，`now - last_sample_time <= params->sample_validity`，所以不会清除样本。

**假设输出：**

函数 `_res_stats_usable_server` 将返回 `true`，因为该 DNS 服务器的成功率足够高，并且有足够的样本数据支持。

**涉及用户或者编程常见的使用错误：**

* **没有正确初始化 `__res_params` 结构体：** 如果 `min_samples` 或 `success_threshold` 等参数没有被正确设置，可能会导致对服务器可用性的判断不准确。例如，如果 `min_samples` 设置为 0，即使只有一个失败的请求，服务器也可能被立即标记为不可用。
* **误解不同 RCODE 的含义：** 在 `android_net_res_stats_aggregate` 中，对不同的 RCODE 进行了分类。如果开发者错误地理解了某个 RCODE 的含义，可能会导致统计结果的偏差。例如，如果将 `NXDOMAIN`（域名不存在）错误地认为是服务器故障，会导致不必要的服务器切换。
* **在高并发场景下竞争访问 `__res_stats` 结构体：**  如果多个线程同时更新或读取同一个 `__res_stats` 结构体，可能会导致数据竞争和不一致。通常需要使用互斥锁或其他同步机制来保护共享数据。
* **过度依赖统计信息而忽略其他因素：**  虽然统计信息很有用，但在某些情况下，仅凭统计信息来判断服务器可用性可能不够全面。例如，一个服务器可能 RTT 较低且错误率较低，但其地理位置离用户很远，导致网络延迟仍然很高。

**Android framework 或 NDK 如何一步步到达这里：**

**Android Framework 路径示例：**

1. **应用程序发起网络请求：** 例如，用户点击浏览器中的一个链接，或者应用程序需要从服务器下载数据。
2. **Framework 处理请求：** Android Framework 中的 `ConnectivityService` 或 `NetworkStack` 等组件会接收到该网络请求。
3. **DNS 解析请求：** 如果需要解析域名，Framework 会调用 Bionic 库中的 DNS 解析相关函数，例如 `getaddrinfo`。
4. **Bionic DNS 解析器：** `getaddrinfo` 函数内部会使用 `/system/etc/resolv.conf` 中配置的 DNS 服务器地址。
5. **使用 `res_stats.c` 中的函数：** 在尝试连接到某个 DNS 服务器之前或之后，DNS 解析器会调用 `_res_stats_set_sample` 记录查询结果。  `android_net_res_stats_aggregate` 和 `_res_stats_usable_server` 会被周期性地调用，或者在需要选择最佳 DNS 服务器时调用，以评估服务器的健康状况。

**NDK 路径示例：**

1. **NDK 应用调用 DNS 解析函数：** 使用 NDK 开发的 C/C++ 应用可以直接调用 Bionic 库提供的 DNS 解析函数，例如 `getaddrinfo`。
2. **后续步骤与 Framework 类似：**  NDK 应用的 DNS 解析过程与 Framework 应用类似，最终也会调用到 `res_stats.c` 中的函数来管理 DNS 服务器的统计信息。

**Frida Hook 示例调试步骤：**

假设我们想观察 `android_net_res_stats_aggregate` 函数的输入和输出：

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    try:
        device = frida.get_usb_device(timeout=10)
        pid = device.spawn([package_name])
        session = device.attach(pid)
    except frida.TimedOutError:
        print("[-] 设备未连接或应用未安装。")
        return
    except frida.ProcessNotFoundError:
        print(f"[-] 找不到进程名为 {package_name} 的应用。")
        return

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "android_net_res_stats_aggregate"), {
        onEnter: function(args) {
            this.stats = args[0];
            send("[+] android_net_res_stats_aggregate called!");
            send("    stats: " + this.stats);
        },
        onLeave: function(retval) {
            send("    successes: " + Memory.readS32(this.stats.add(Process.pointerSize * 0)));
            send("    errors: " + Memory.readS32(this.stats.add(Process.pointerSize * 1)));
            send("    timeouts: " + Memory.readS32(this.stats.add(Process.pointerSize * 2)));
            send("    internal_errors: " + Memory.readS32(this.stats.add(Process.pointerSize * 3)));
            send("    rtt_avg: " + Memory.readS32(this.stats.add(Process.pointerSize * 4)));
            send("    last_sample_time: " + Memory.readU64(this.stats.add(Process.pointerSize * 5)));
            send("[-] android_net_res_stats_aggregate finished.");
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input() # 等待用户输入退出
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 调试步骤：**

1. **安装 Frida 和 Python 环境。**
2. **找到目标应用的包名 (例如通过 `adb shell pm list packages`)。**
3. **将上面的 Python 代码保存为 `hook_res_stats.py`，并将 `package_name` 替换为目标应用的包名。**
4. **确保你的 Android 设备已连接并通过 USB 调试授权。**
5. **运行 `python hook_res_stats.py`。**
6. **在你的 Android 设备上触发网络请求，例如打开应用或访问网页。**
7. **观察 Frida 的输出。你将看到 `android_net_res_stats_aggregate` 函数被调用时的相关信息，包括 `__res_stats` 结构体的地址以及聚合后的统计数据。**

通过 Frida Hook，你可以动态地观察 Bionic 库中函数的运行情况，这对于理解 Android 底层网络机制和调试相关问题非常有帮助。

Prompt: 
```
这是目录为bionic/libc/dns/resolv/res_stats.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <arpa/nameser.h>
#include <string.h>

#include <async_safe/log.h>

#include "isc/eventlib.h"
#include "resolv_stats.h"

#define DBG 0

/* Calculate the round-trip-time from start time t0 and end time t1. */
int
_res_stats_calculate_rtt(const struct timespec* t1, const struct timespec* t0) {
    // Divide ns by one million to get ms, multiply s by thousand to get ms (obvious)
    long ms0 = t0->tv_sec * 1000 + t0->tv_nsec / 1000000;
    long ms1 = t1->tv_sec * 1000 + t1->tv_nsec / 1000000;
    return (int) (ms1 - ms0);
}

/* Create a sample for calculating server reachability statistics. */
void
_res_stats_set_sample(struct __res_sample* sample, time_t now, int rcode, int rtt)
{
    if (DBG) {
        async_safe_format_log(ANDROID_LOG_INFO, "libc", "rcode = %d, sec = %d", rcode, rtt);
    }
    sample->at = now;
    sample->rcode = rcode;
    sample->rtt = rtt;
}

/* Clears all stored samples for the given server. */
void
_res_stats_clear_samples(struct __res_stats* stats)
{
    stats->sample_count = stats->sample_next = 0;
}

/* Aggregates the reachability statistics for the given server based on on the stored samples. */
void
android_net_res_stats_aggregate(struct __res_stats* stats, int* successes, int* errors,
        int* timeouts, int* internal_errors, int* rtt_avg, time_t* last_sample_time)
{
    int s = 0;   // successes
    int e = 0;   // errors
    int t = 0;   // timouts
    int ie = 0;  // internal errors
    long rtt_sum = 0;
    time_t last = 0;
    int rtt_count = 0;
    for (int i = 0 ; i < stats->sample_count ; ++i) {
        // Treat everything as an error that the code in send_dg() already considers a
        // rejection by the server, i.e. SERVFAIL, NOTIMP and REFUSED. Assume that NXDOMAIN
        // and NOTAUTH can actually occur for user queries. NOERROR with empty answer section
        // is not treated as an error here either. FORMERR seems to sometimes be returned by
        // some versions of BIND in response to DNSSEC or EDNS0. Whether to treat such responses
        // as an indication of a broken server is unclear, though. For now treat such responses,
        // as well as unknown codes as errors.
        switch (stats->samples[i].rcode) {
        case NOERROR:
        case NOTAUTH:
        case NXDOMAIN:
            ++s;
            rtt_sum += stats->samples[i].rtt;
            ++rtt_count;
            break;
        case RCODE_TIMEOUT:
            ++t;
            break;
        case RCODE_INTERNAL_ERROR:
            ++ie;
            break;
        case SERVFAIL:
        case NOTIMP:
        case REFUSED:
        default:
            ++e;
            break;
        }
    }
    *successes = s;
    *errors = e;
    *timeouts = t;
    *internal_errors = ie;
    /* If there was at least one successful sample, calculate average RTT. */
    if (rtt_count) {
        *rtt_avg = rtt_sum / rtt_count;
    } else {
        *rtt_avg = -1;
    }
    /* If we had at least one sample, populate last sample time. */
    if (stats->sample_count > 0) {
        if (stats->sample_next > 0) {
            last = stats->samples[stats->sample_next - 1].at;
        } else {
            last = stats->samples[stats->sample_count - 1].at;
        }
    }
    *last_sample_time = last;
}

bool
_res_stats_usable_server(const struct __res_params* params, struct __res_stats* stats) {
    int successes = -1;
    int errors = -1;
    int timeouts = -1;
    int internal_errors = -1;
    int rtt_avg = -1;
    time_t last_sample_time = 0;
    android_net_res_stats_aggregate(stats, &successes, &errors, &timeouts, &internal_errors,
            &rtt_avg, &last_sample_time);
    if (successes >= 0 && errors >= 0 && timeouts >= 0) {
        int total = successes + errors + timeouts;
        if (DBG) {
            async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "NS stats: S %d + E %d + T %d + I %d "
                 "= %d, rtt = %d, min_samples = %d\n", successes, errors, timeouts, internal_errors,
                 total, rtt_avg, params->min_samples);
        }
        if (total >= params->min_samples && (errors > 0 || timeouts > 0)) {
            int success_rate = successes * 100 / total;
            if (DBG) {
                async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "success rate %d%%\n",
                                      success_rate);
            }
            if (success_rate < params->success_threshold) {
                // evNowTime() is used here instead of time() to stay consistent with the rest of
                // the code base
                time_t now = evNowTime().tv_sec;
                if (now - last_sample_time > params->sample_validity) {
                    // Note: It might be worth considering to expire old servers after their expiry
                    // date has been reached, however the code for returning the ring buffer to its
                    // previous non-circular state would induce additional complexity.
                    if (DBG) {
                        async_safe_format_log(ANDROID_LOG_INFO, "libc",
                            "samples stale, retrying server\n");
                    }
                    _res_stats_clear_samples(stats);
                } else {
                    if (DBG) {
                        async_safe_format_log(ANDROID_LOG_INFO, "libc",
                            "too many resolution errors, ignoring server\n");
                    }
                    return 0;
                }
            }
        }
    }
    return 1;
}

void
android_net_res_stats_get_usable_servers(const struct __res_params* params,
        struct __res_stats stats[], int nscount, bool usable_servers[]) {
    unsigned usable_servers_found = 0;
    for (int ns = 0; ns < nscount; ns++) {
        bool usable = _res_stats_usable_server(params, &stats[ns]);
        if (usable) {
            ++usable_servers_found;
        }
        usable_servers[ns] = usable;
    }
    // If there are no usable servers, consider all of them usable.
    // TODO: Explore other possibilities, such as enabling only the best N servers, etc.
    if (usable_servers_found == 0) {
        for (int ns = 0; ns < nscount; ns++) {
            usable_servers[ns] = true;
        }
    }
}

"""

```