Response:
Thinking Process to Answer the Question:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C header file (`pkt_sched.h`) within the context of Android's bionic library. The request specifically asks about its features, relation to Android, function implementations (though it's a header), dynamic linking aspects, usage errors, and how Android reaches this file.

2. **Initial Analysis of the Header:**  The file is a Linux kernel UAPI header. This means it defines the *user-space interface* to kernel functionality related to packet scheduling (traffic control). It doesn't *implement* functions itself; it defines data structures, constants, and enums that user-space programs (like those in Android) can use to interact with the kernel's traffic control mechanisms.

3. **Identify Key Functional Areas:** Scan the header for major categories. The presence of `struct tc_*`, `TCA_*`, `TCQ_*`, and various constants clearly indicates definitions related to:
    * **Traffic Classes and Priorities:**  `TC_PRIO_*` constants.
    * **Statistics:** `struct tc_stats`.
    * **Estimators:** `struct tc_estimator`.
    * **Handles:** `TC_H_*` macros.
    * **Link Layer Information:** `enum tc_link_layer`.
    * **Rate Specification:** `struct tc_ratespec`.
    * **Size Specification:** `struct tc_sizespec`.
    * **Queueing Disciplines (qdiscs):** Structures and constants for FIFO, PRIO, TBF, SFQ, RED, GRED, CHOKE, HTB, HFSC, NETEM, DRR, MQPRIO, SFB, QFQ, CODEL, FQ_CODEL, FQ, HHF, PIE, FQ_PIE, CBS, ETF, CAKE, TAPRIO, and ETS. These represent different algorithms for managing network traffic.
    * **Attributes:** `TCA_*` constants.
    * **Commands and Flags:** For specific qdiscs like TAPRIO and ETF.

4. **Address the "Functionality" Question:** Based on the identified areas, summarize the header's purpose: defining the interface for configuring and monitoring network traffic shaping and scheduling in Linux. Emphasize that it's about *describing* the interface, not implementing it.

5. **Relate to Android:**  Think about how Android might use traffic control. Examples include:
    * **Prioritizing interactive traffic:** Ensuring UI responsiveness.
    * **Limiting background data usage:**  Preventing apps from consuming too much bandwidth.
    * **Quality of Service (QoS):**  For specific applications or types of traffic.
    * **Network testing/emulation:** Simulating network conditions.

6. **Address "Libc Function Implementation":**  Crucially, clarify that this is a *header file*, not a source file with function *implementations*. The implementations reside in the Linux kernel. Explain the role of header files: declarations and definitions for the compiler.

7. **Address "Dynamic Linker":**  Since this is a kernel header, it's not directly linked by the dynamic linker for user-space programs. Explain that user-space tools (like `ip route`) or Android system services might use system calls that interact with the kernel's traffic control implementation. Give a conceptual example of how a user-space tool might use the `ioctl` system call with structures defined in this header. A true dynamic linking example with `.so` layouts isn't applicable here.

8. **Address "Logical Reasoning/Assumptions":**  Provide a simple scenario. Imagine setting the priority of a certain type of network traffic using tools that leverage this header. Show the conceptual input (e.g., a command to set `TC_PRIO_INTERACTIVE`) and the expected outcome (the kernel prioritizing that traffic).

9. **Address "User/Programming Errors":**  Give examples of common mistakes:
    * Using incorrect constants.
    * Providing invalid parameter values.
    * Not having sufficient privileges.

10. **Address "Android Framework/NDK Path":**  Outline the steps:
    * An app or system service wants to control traffic.
    * It uses Android APIs (Java or NDK).
    * These APIs might translate into system calls (like `ioctl` with `TCGETQDISC`, `TCADDACT`, etc.).
    * The system calls interact with the Linux kernel's traffic control implementation.
    * The kernel implementation uses the definitions in `pkt_sched.h`.

11. **Provide Frida Hook Examples:**  Demonstrate how Frida could be used to intercept calls related to traffic control, even though direct libc functions aren't involved. Focus on hooking system calls or higher-level Android framework functions. This highlights *observing* the interaction rather than directly hooking functions *defined* in the header.

12. **Structure and Language:** Organize the answer clearly using headings for each part of the request. Use clear, concise Chinese. Avoid overly technical jargon where simpler explanations suffice. Emphasize the key distinction between header files and source code.

**Self-Correction/Refinement During Thinking:**

* **Initial thought:** "Need to explain libc functions."  **Correction:** Realized this header *doesn't* contain libc function *implementations*. Shifted focus to the *interface* it defines for interacting with kernel functionality.
* **Initial thought:** "Need a `.so` layout for dynamic linking." **Correction:** Recognized that direct dynamic linking isn't the primary mechanism here. Focused on the interaction via system calls. A conceptual `.so` example related to a user-space traffic control utility could be added if absolutely necessary, but it's not directly tied to this header.
* **Emphasis:**  Made sure to repeatedly stress that this is a *kernel UAPI header*, to prevent confusion about function implementations.
* **Frida examples:** Initially thought about hooking specific libc functions. **Correction:** Shifted to hooking system calls or higher-level Android functions because there are no directly relevant libc functions *defined* in this header. This makes the Frida examples more accurate in this context.

By following these steps and self-correcting along the way, a comprehensive and accurate answer can be generated.

好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/pkt_sched.h` 这个头文件。

**功能概述**

`pkt_sched.h` 是 Linux 内核用户空间 API (UAPI) 的一部分，它定义了用于配置和管理网络数据包调度 (packet scheduling) 的数据结构和常量。简单来说，它描述了用户空间的程序如何与 Linux 内核中的流量控制 (traffic control) 子系统进行交互。

**核心功能点：**

1. **定义流量控制的优先级:**  例如 `TC_PRIO_BESTEFFORT`, `TC_PRIO_CONTROL` 等常量，用于标识不同流量的优先级。
2. **定义统计信息结构:**  `struct tc_stats` 用于报告数据包调度的统计信息，如发送字节数、包数、丢包数等。
3. **定义流量整形 (traffic shaping) 和队列规则 (queueing disciplines，qdiscs) 的配置选项:**  例如，`struct tc_fifo_qopt` 定义了 FIFO 队列的限制， `struct tc_tbf_qopt` 定义了令牌桶过滤器 (Token Bucket Filter, TBF) 的参数。
4. **定义了各种队列规则的特定参数:**  涵盖了 FIFO, 优先级队列, TBF, SFQ, RED, HTB, HFSC, NETEM 等多种不同的流量控制算法。
5. **定义了属性 (attributes) 的枚举:**  例如 `TCA_TBF_PARMS` 用于标识 TBF 队列规则的参数。
6. **定义了与网络链路层相关的选项:**  例如 `enum tc_link_layer` 用于指定链路层类型。
7. **定义了用于多队列 (multi-queue) 的选项:**  例如 `struct tc_multiq_qopt`。

**与 Android 功能的关系及举例说明**

Android 系统底层使用了 Linux 内核，因此 `pkt_sched.h` 中定义的这些结构和常量直接影响着 Android 设备的网络流量管理。

**举例说明:**

* **流量优先级 (Traffic Prioritization):** Android 系统可以使用这些优先级常量来区分不同应用的流量。例如，可以将前台应用的流量设置为更高的优先级 (如 `TC_PRIO_INTERACTIVE`)，确保用户交互的流畅性，而将后台同步等任务的流量设置为较低的优先级 (如 `TC_PRIO_BULK`)，避免占用过多带宽。
* **流量限制 (Traffic Shaping):** Android 可以使用 TBF 或 HTB 等队列规则来限制特定应用的带宽使用，防止个别应用过度消耗网络资源。例如，可以限制后台下载的速率，以免影响前台应用的体验。
* **服务质量 (Quality of Service, QoS):**  一些 Android 应用，特别是涉及到实时通信的应用 (如 VoLTE)，可能需要特定的 QoS 保障。Android 框架可以使用这些底层的流量控制机制来满足这些需求。
* **网络仿真 (Network Emulation):**  Android 开发者或测试人员可以使用 NETEM 队列规则来模拟不同的网络条件，例如延迟、丢包、抖动等，以便在各种网络环境下测试应用的性能。

**libc 函数的功能及其实现**

**重要提示:** `pkt_sched.h` **不是** libc 的源代码文件，而是一个 Linux 内核 UAPI 头文件。它定义的是内核接口，而不是 libc 库中的函数。

libc (bionic) 是 Android 的 C 标准库，它提供了一系列与操作系统交互的函数。虽然 `pkt_sched.h` 本身不包含 libc 函数的实现，但 libc 中可能会有函数，或者更常见的是，Android 的系统库或框架会使用系统调用 (system calls) 来与内核的流量控制子系统交互，而这些系统调用会使用 `pkt_sched.h` 中定义的数据结构。

例如，Android 的 `TrafficStats` 类或者底层的 `ioctl` 系统调用可能会涉及到使用 `pkt_sched.h` 中定义的结构体来配置网络接口的队列规则。

**详细解释 libc 函数的实现 (此处需要理解，并没有直接的 libc 函数定义在这个头文件中):**

由于 `pkt_sched.h` 是内核头文件，我们无法直接解释 "libc 函数的实现"。 我们需要关注的是 **用户空间程序如何通过 libc (或其他库) 与内核的流量控制子系统交互。**

常见的方式是使用 **`ioctl` 系统调用**。 `ioctl` 是一个通用的设备控制操作，它可以用来执行各种设备特定的操作，包括配置网络接口的流量控制。

当用户空间的程序想要配置或查询流量控制规则时，它通常会：

1. **填充 `pkt_sched.h` 中定义的结构体:**  例如，创建一个 `struct tc_attr` 结构体来描述要添加的队列规则，其中包含了 `pkt_sched.h` 中定义的各种 `struct tc_*_qopt` 结构体来指定队列规则的参数。
2. **调用 `ioctl` 系统调用:**  `ioctl` 的第一个参数是网络接口的文件描述符，第二个参数是特定的 `ioctl` 命令 (例如，`TC_ADD_QDISC` 用于添加队列规则)，第三个参数是指向填充好的结构体的指针。
3. **内核处理 `ioctl` 请求:** 内核接收到 `ioctl` 请求后，会解析用户空间传递来的结构体，并根据其中的信息配置相应的流量控制规则。

**涉及 dynamic linker 的功能**

`pkt_sched.h` **不直接涉及** dynamic linker 的功能。 Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载动态链接库 (`.so` 文件) 并解析符号引用。

然而，如果用户空间的应用程序或库需要与内核的流量控制子系统交互，它们可能会链接到提供 `ioctl` 系统调用封装的 libc 库。

**so 布局样本及链接的处理过程 (概念性解释):**

假设我们有一个名为 `libtrafficcontrol.so` 的动态链接库，它封装了一些用于配置流量控制的函数。

```
# libtrafficcontrol.so 的布局 (示例)

.text      # 代码段，包含流量控制相关的函数实现
.data      # 数据段，包含全局变量
.rodata    # 只读数据段，包含常量
.dynsym    # 动态符号表
.dynstr    # 动态字符串表
.rel.dyn   # 动态重定位表
.plt       # 程序链接表 (Procedure Linkage Table)
.got.plt   # 全局偏移量表 (Global Offset Table)
```

**链接处理过程 (概念性):**

1. **编译时链接:**  当应用程序编译时，链接器会记录它对 `libtrafficcontrol.so` 中符号的依赖。
2. **运行时链接:** 当应用程序启动时，dynamic linker 会加载 `libtrafficcontrol.so` 到内存中。
3. **符号解析:** dynamic linker 会解析应用程序中对 `libtrafficcontrol.so` 中函数的调用，并将这些调用地址指向库中实际的函数地址。这通常通过 `.plt` 和 `.got.plt` 完成。
4. **`ioctl` 系统调用:**  `libtrafficcontrol.so` 中的函数最终会调用 libc 提供的 `ioctl` 系统调用，与内核的流量控制子系统进行交互。

**请注意:**  `pkt_sched.h` 定义的是内核接口，用户空间的库 (如 `libtrafficcontrol.so`) 使用它来构造与内核通信的数据结构。 dynamic linker 负责加载和链接这些用户空间的库，但并不直接处理 `pkt_sched.h` 的内容。

**逻辑推理：假设输入与输出**

**假设输入:**  用户空间的程序想要将网络接口 `eth0` 的某个流量类别设置为高优先级。

**处理过程 (概念性):**

1. 程序创建一个 `struct tc_attr` 结构体。
2. 在该结构体中，程序设置队列规则类型和相关参数，例如使用 `TC_PRIO_INTERACTIVE` 作为优先级。
3. 程序调用 `ioctl(sockfd, TC_ADD_QDISC, &tc_attr)`，其中 `sockfd` 是与 `eth0` 关联的 socket 文件描述符。

**预期输出:**

* 如果操作成功，`ioctl` 返回 0。
* 内核会将 `eth0` 上匹配该流量类别的包放入优先级更高的队列中进行处理，从而提高其发送优先级。

**用户或编程常见的使用错误**

1. **使用错误的常量或枚举值:**  例如，使用了不存在的队列规则类型或者错误的优先级常量。
2. **填充结构体时出现错误:**  例如，忘记初始化某些字段，或者将参数值设置在有效范围之外。
3. **权限不足:**  配置网络接口的流量控制通常需要 root 权限。如果程序没有足够的权限，`ioctl` 调用将会失败。
4. **不理解不同队列规则的适用场景:**  错误地选择了不适合当前需求的队列规则。例如，在需要严格带宽保证的场景下使用了 FIFO 队列。
5. **忽略错误处理:**  没有检查 `ioctl` 的返回值，导致程序在操作失败后继续执行，可能会产生不可预测的结果。
6. **在不适当的时间修改流量控制规则:**  例如，在网络接口正在繁忙工作时频繁修改规则，可能会导致性能问题或配置错误。

**Android Framework 或 NDK 如何一步步到达这里**

1. **Android 应用或服务发起网络请求:**  例如，一个应用开始下载文件或进行网络通信。
2. **Android Framework 处理网络请求:** Android 的网络框架 (例如，ConnectivityService, NetworkPolicyManagerService) 可能会根据应用的策略和系统配置，决定是否需要应用特定的流量控制规则。
3. **使用 NDK 或 Java API 调用:**
   * **NDK:** 开发者可以使用 NDK 编写 C/C++ 代码，直接调用 Linux 系统调用 (如 `ioctl`) 来配置流量控制。
   * **Java API:**  Android Framework 提供了 Java API (例如，`TrafficStats`, `NetworkPolicyManager`)，这些 API 底层可能会调用 native 代码或系统服务。
4. **系统服务或 native 代码操作:** 系统服务 (例如 `netd`) 或 Framework 层的 native 代码会构造相应的 `pkt_sched.h` 中定义的结构体，并调用 `ioctl` 系统调用。
5. **`ioctl` 系统调用到达 Linux 内核:**  内核接收到 `ioctl` 调用，解析参数，并根据 `pkt_sched.h` 中定义的结构体信息，配置网络接口的流量控制规则。

**Frida Hook 示例调试这些步骤**

由于 `pkt_sched.h` 定义的是内核接口，我们无法直接 hook 到这个头文件中的 "函数"。 我们需要 hook 的是用户空间与内核交互的关键点，例如 `ioctl` 系统调用，或者 Android Framework 中相关的 Java 方法或 native 函数。

**Frida Hook 示例 (Hook `ioctl` 系统调用):**

```javascript
// Hook ioctl 系统调用
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    console.log("ioctl called");
    console.log("  fd:", fd);
    console.log("  request:", request, "(" + this.context.threadId + ")");

    // 可以根据 request 的值来判断是否是与流量控制相关的 ioctl 命令
    // 例如，TC_ADD_QDISC, TC_GET_QDISC 等

    if (request === 0x8918 || request === 0x8917) { // 0x8918 是 TC_ADD_QDISC, 0x8917 是 TC_GET_QDISC
      console.log("  Potentially a traffic control ioctl");
      // 可以进一步解析 argp 指向的结构体，查看具体的流量控制参数
      // 这需要根据具体的 ioctl 命令和 pkt_sched.h 中的结构体定义进行解析
    }
  },
  onLeave: function (retval) {
    console.log("ioctl returned:", retval);
  },
});
```

**Frida Hook 示例 (Hook Android Framework Java 方法):**

```javascript
// Hook TrafficStats 类的 setThreadStatsTag 方法 (一个可能与流量标记相关的 API)
Java.perform(function () {
  const TrafficStats = Java.use("android.net.TrafficStats");
  TrafficStats.setThreadStatsTag.overload("int").implementation = function (tag) {
    console.log("TrafficStats.setThreadStatsTag called with tag:", tag);
    return this.setThreadStatsTag.overload("int").call(this, tag);
  };
});
```

**Frida Hook 示例 (Hook Android Native 代码):**

这需要找到 Android 系统库中负责调用 `ioctl` 的 native 函数。 这通常需要一些逆向工程分析。

**总结**

`bionic/libc/kernel/uapi/linux/pkt_sched.h` 是理解 Linux 内核流量控制机制的关键。虽然它本身不是 libc 的一部分，但 Android 系统和应用程序通过 libc 提供的系统调用接口，并利用这个头文件中定义的数据结构，与内核的流量控制子系统进行交互，从而实现各种网络流量管理的功能。 使用 Frida 可以帮助我们观察和调试 Android 系统与内核流量控制子系统的交互过程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/pkt_sched.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef __LINUX_PKT_SCHED_H
#define __LINUX_PKT_SCHED_H
#include <linux/const.h>
#include <linux/types.h>
#define TC_PRIO_BESTEFFORT 0
#define TC_PRIO_FILLER 1
#define TC_PRIO_BULK 2
#define TC_PRIO_INTERACTIVE_BULK 4
#define TC_PRIO_INTERACTIVE 6
#define TC_PRIO_CONTROL 7
#define TC_PRIO_MAX 15
struct tc_stats {
  __u64 bytes;
  __u32 packets;
  __u32 drops;
  __u32 overlimits;
  __u32 bps;
  __u32 pps;
  __u32 qlen;
  __u32 backlog;
};
struct tc_estimator {
  signed char interval;
  unsigned char ewma_log;
};
#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h) & TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h) & TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj) & TC_H_MAJ_MASK) | ((min) & TC_H_MIN_MASK))
#define TC_H_UNSPEC (0U)
#define TC_H_ROOT (0xFFFFFFFFU)
#define TC_H_INGRESS (0xFFFFFFF1U)
#define TC_H_CLSACT TC_H_INGRESS
#define TC_H_MIN_PRIORITY 0xFFE0U
#define TC_H_MIN_INGRESS 0xFFF2U
#define TC_H_MIN_EGRESS 0xFFF3U
enum tc_link_layer {
  TC_LINKLAYER_UNAWARE,
  TC_LINKLAYER_ETHERNET,
  TC_LINKLAYER_ATM,
};
#define TC_LINKLAYER_MASK 0x0F
struct tc_ratespec {
  unsigned char cell_log;
  __u8 linklayer;
  unsigned short overhead;
  short cell_align;
  unsigned short mpu;
  __u32 rate;
};
#define TC_RTAB_SIZE 1024
struct tc_sizespec {
  unsigned char cell_log;
  unsigned char size_log;
  short cell_align;
  int overhead;
  unsigned int linklayer;
  unsigned int mpu;
  unsigned int mtu;
  unsigned int tsize;
};
enum {
  TCA_STAB_UNSPEC,
  TCA_STAB_BASE,
  TCA_STAB_DATA,
  __TCA_STAB_MAX
};
#define TCA_STAB_MAX (__TCA_STAB_MAX - 1)
struct tc_fifo_qopt {
  __u32 limit;
};
#define SKBPRIO_MAX_PRIORITY 64
struct tc_skbprio_qopt {
  __u32 limit;
};
#define TCQ_PRIO_BANDS 16
#define TCQ_MIN_PRIO_BANDS 2
struct tc_prio_qopt {
  int bands;
  __u8 priomap[TC_PRIO_MAX + 1];
};
struct tc_multiq_qopt {
  __u16 bands;
  __u16 max_bands;
};
#define TCQ_PLUG_BUFFER 0
#define TCQ_PLUG_RELEASE_ONE 1
#define TCQ_PLUG_RELEASE_INDEFINITE 2
#define TCQ_PLUG_LIMIT 3
struct tc_plug_qopt {
  int action;
  __u32 limit;
};
struct tc_tbf_qopt {
  struct tc_ratespec rate;
  struct tc_ratespec peakrate;
  __u32 limit;
  __u32 buffer;
  __u32 mtu;
};
enum {
  TCA_TBF_UNSPEC,
  TCA_TBF_PARMS,
  TCA_TBF_RTAB,
  TCA_TBF_PTAB,
  TCA_TBF_RATE64,
  TCA_TBF_PRATE64,
  TCA_TBF_BURST,
  TCA_TBF_PBURST,
  TCA_TBF_PAD,
  __TCA_TBF_MAX,
};
#define TCA_TBF_MAX (__TCA_TBF_MAX - 1)
struct tc_sfq_qopt {
  unsigned quantum;
  int perturb_period;
  __u32 limit;
  unsigned divisor;
  unsigned flows;
};
struct tc_sfqred_stats {
  __u32 prob_drop;
  __u32 forced_drop;
  __u32 prob_mark;
  __u32 forced_mark;
  __u32 prob_mark_head;
  __u32 forced_mark_head;
};
struct tc_sfq_qopt_v1 {
  struct tc_sfq_qopt v0;
  unsigned int depth;
  unsigned int headdrop;
  __u32 limit;
  __u32 qth_min;
  __u32 qth_max;
  unsigned char Wlog;
  unsigned char Plog;
  unsigned char Scell_log;
  unsigned char flags;
  __u32 max_P;
  struct tc_sfqred_stats stats;
};
struct tc_sfq_xstats {
  __s32 allot;
};
enum {
  TCA_RED_UNSPEC,
  TCA_RED_PARMS,
  TCA_RED_STAB,
  TCA_RED_MAX_P,
  TCA_RED_FLAGS,
  TCA_RED_EARLY_DROP_BLOCK,
  TCA_RED_MARK_BLOCK,
  __TCA_RED_MAX,
};
#define TCA_RED_MAX (__TCA_RED_MAX - 1)
struct tc_red_qopt {
  __u32 limit;
  __u32 qth_min;
  __u32 qth_max;
  unsigned char Wlog;
  unsigned char Plog;
  unsigned char Scell_log;
  unsigned char flags;
#define TC_RED_ECN 1
#define TC_RED_HARDDROP 2
#define TC_RED_ADAPTATIVE 4
#define TC_RED_NODROP 8
};
#define TC_RED_HISTORIC_FLAGS (TC_RED_ECN | TC_RED_HARDDROP | TC_RED_ADAPTATIVE)
struct tc_red_xstats {
  __u32 early;
  __u32 pdrop;
  __u32 other;
  __u32 marked;
};
#define MAX_DPs 16
enum {
  TCA_GRED_UNSPEC,
  TCA_GRED_PARMS,
  TCA_GRED_STAB,
  TCA_GRED_DPS,
  TCA_GRED_MAX_P,
  TCA_GRED_LIMIT,
  TCA_GRED_VQ_LIST,
  __TCA_GRED_MAX,
};
#define TCA_GRED_MAX (__TCA_GRED_MAX - 1)
enum {
  TCA_GRED_VQ_ENTRY_UNSPEC,
  TCA_GRED_VQ_ENTRY,
  __TCA_GRED_VQ_ENTRY_MAX,
};
#define TCA_GRED_VQ_ENTRY_MAX (__TCA_GRED_VQ_ENTRY_MAX - 1)
enum {
  TCA_GRED_VQ_UNSPEC,
  TCA_GRED_VQ_PAD,
  TCA_GRED_VQ_DP,
  TCA_GRED_VQ_STAT_BYTES,
  TCA_GRED_VQ_STAT_PACKETS,
  TCA_GRED_VQ_STAT_BACKLOG,
  TCA_GRED_VQ_STAT_PROB_DROP,
  TCA_GRED_VQ_STAT_PROB_MARK,
  TCA_GRED_VQ_STAT_FORCED_DROP,
  TCA_GRED_VQ_STAT_FORCED_MARK,
  TCA_GRED_VQ_STAT_PDROP,
  TCA_GRED_VQ_STAT_OTHER,
  TCA_GRED_VQ_FLAGS,
  __TCA_GRED_VQ_MAX
};
#define TCA_GRED_VQ_MAX (__TCA_GRED_VQ_MAX - 1)
struct tc_gred_qopt {
  __u32 limit;
  __u32 qth_min;
  __u32 qth_max;
  __u32 DP;
  __u32 backlog;
  __u32 qave;
  __u32 forced;
  __u32 early;
  __u32 other;
  __u32 pdrop;
  __u8 Wlog;
  __u8 Plog;
  __u8 Scell_log;
  __u8 prio;
  __u32 packets;
  __u32 bytesin;
};
struct tc_gred_sopt {
  __u32 DPs;
  __u32 def_DP;
  __u8 grio;
  __u8 flags;
  __u16 pad1;
};
enum {
  TCA_CHOKE_UNSPEC,
  TCA_CHOKE_PARMS,
  TCA_CHOKE_STAB,
  TCA_CHOKE_MAX_P,
  __TCA_CHOKE_MAX,
};
#define TCA_CHOKE_MAX (__TCA_CHOKE_MAX - 1)
struct tc_choke_qopt {
  __u32 limit;
  __u32 qth_min;
  __u32 qth_max;
  unsigned char Wlog;
  unsigned char Plog;
  unsigned char Scell_log;
  unsigned char flags;
};
struct tc_choke_xstats {
  __u32 early;
  __u32 pdrop;
  __u32 other;
  __u32 marked;
  __u32 matched;
};
#define TC_HTB_NUMPRIO 8
#define TC_HTB_MAXDEPTH 8
#define TC_HTB_PROTOVER 3
struct tc_htb_opt {
  struct tc_ratespec rate;
  struct tc_ratespec ceil;
  __u32 buffer;
  __u32 cbuffer;
  __u32 quantum;
  __u32 level;
  __u32 prio;
};
struct tc_htb_glob {
  __u32 version;
  __u32 rate2quantum;
  __u32 defcls;
  __u32 debug;
  __u32 direct_pkts;
};
enum {
  TCA_HTB_UNSPEC,
  TCA_HTB_PARMS,
  TCA_HTB_INIT,
  TCA_HTB_CTAB,
  TCA_HTB_RTAB,
  TCA_HTB_DIRECT_QLEN,
  TCA_HTB_RATE64,
  TCA_HTB_CEIL64,
  TCA_HTB_PAD,
  TCA_HTB_OFFLOAD,
  __TCA_HTB_MAX,
};
#define TCA_HTB_MAX (__TCA_HTB_MAX - 1)
struct tc_htb_xstats {
  __u32 lends;
  __u32 borrows;
  __u32 giants;
  __s32 tokens;
  __s32 ctokens;
};
struct tc_hfsc_qopt {
  __u16 defcls;
};
struct tc_service_curve {
  __u32 m1;
  __u32 d;
  __u32 m2;
};
struct tc_hfsc_stats {
  __u64 work;
  __u64 rtwork;
  __u32 period;
  __u32 level;
};
enum {
  TCA_HFSC_UNSPEC,
  TCA_HFSC_RSC,
  TCA_HFSC_FSC,
  TCA_HFSC_USC,
  __TCA_HFSC_MAX,
};
#define TCA_HFSC_MAX (__TCA_HFSC_MAX - 1)
enum {
  TCA_NETEM_UNSPEC,
  TCA_NETEM_CORR,
  TCA_NETEM_DELAY_DIST,
  TCA_NETEM_REORDER,
  TCA_NETEM_CORRUPT,
  TCA_NETEM_LOSS,
  TCA_NETEM_RATE,
  TCA_NETEM_ECN,
  TCA_NETEM_RATE64,
  TCA_NETEM_PAD,
  TCA_NETEM_LATENCY64,
  TCA_NETEM_JITTER64,
  TCA_NETEM_SLOT,
  TCA_NETEM_SLOT_DIST,
  TCA_NETEM_PRNG_SEED,
  __TCA_NETEM_MAX,
};
#define TCA_NETEM_MAX (__TCA_NETEM_MAX - 1)
struct tc_netem_qopt {
  __u32 latency;
  __u32 limit;
  __u32 loss;
  __u32 gap;
  __u32 duplicate;
  __u32 jitter;
};
struct tc_netem_corr {
  __u32 delay_corr;
  __u32 loss_corr;
  __u32 dup_corr;
};
struct tc_netem_reorder {
  __u32 probability;
  __u32 correlation;
};
struct tc_netem_corrupt {
  __u32 probability;
  __u32 correlation;
};
struct tc_netem_rate {
  __u32 rate;
  __s32 packet_overhead;
  __u32 cell_size;
  __s32 cell_overhead;
};
struct tc_netem_slot {
  __s64 min_delay;
  __s64 max_delay;
  __s32 max_packets;
  __s32 max_bytes;
  __s64 dist_delay;
  __s64 dist_jitter;
};
enum {
  NETEM_LOSS_UNSPEC,
  NETEM_LOSS_GI,
  NETEM_LOSS_GE,
  __NETEM_LOSS_MAX
};
#define NETEM_LOSS_MAX (__NETEM_LOSS_MAX - 1)
struct tc_netem_gimodel {
  __u32 p13;
  __u32 p31;
  __u32 p32;
  __u32 p14;
  __u32 p23;
};
struct tc_netem_gemodel {
  __u32 p;
  __u32 r;
  __u32 h;
  __u32 k1;
};
#define NETEM_DIST_SCALE 8192
#define NETEM_DIST_MAX 16384
enum {
  TCA_DRR_UNSPEC,
  TCA_DRR_QUANTUM,
  __TCA_DRR_MAX
};
#define TCA_DRR_MAX (__TCA_DRR_MAX - 1)
struct tc_drr_stats {
  __u32 deficit;
};
#define TC_QOPT_BITMASK 15
#define TC_QOPT_MAX_QUEUE 16
enum {
  TC_MQPRIO_HW_OFFLOAD_NONE,
  TC_MQPRIO_HW_OFFLOAD_TCS,
  __TC_MQPRIO_HW_OFFLOAD_MAX
};
#define TC_MQPRIO_HW_OFFLOAD_MAX (__TC_MQPRIO_HW_OFFLOAD_MAX - 1)
enum {
  TC_MQPRIO_MODE_DCB,
  TC_MQPRIO_MODE_CHANNEL,
  __TC_MQPRIO_MODE_MAX
};
#define __TC_MQPRIO_MODE_MAX (__TC_MQPRIO_MODE_MAX - 1)
enum {
  TC_MQPRIO_SHAPER_DCB,
  TC_MQPRIO_SHAPER_BW_RATE,
  __TC_MQPRIO_SHAPER_MAX
};
#define __TC_MQPRIO_SHAPER_MAX (__TC_MQPRIO_SHAPER_MAX - 1)
enum {
  TC_FP_EXPRESS = 1,
  TC_FP_PREEMPTIBLE = 2,
};
struct tc_mqprio_qopt {
  __u8 num_tc;
  __u8 prio_tc_map[TC_QOPT_BITMASK + 1];
  __u8 hw;
  __u16 count[TC_QOPT_MAX_QUEUE];
  __u16 offset[TC_QOPT_MAX_QUEUE];
};
#define TC_MQPRIO_F_MODE 0x1
#define TC_MQPRIO_F_SHAPER 0x2
#define TC_MQPRIO_F_MIN_RATE 0x4
#define TC_MQPRIO_F_MAX_RATE 0x8
enum {
  TCA_MQPRIO_TC_ENTRY_UNSPEC,
  TCA_MQPRIO_TC_ENTRY_INDEX,
  TCA_MQPRIO_TC_ENTRY_FP,
  __TCA_MQPRIO_TC_ENTRY_CNT,
  TCA_MQPRIO_TC_ENTRY_MAX = (__TCA_MQPRIO_TC_ENTRY_CNT - 1)
};
enum {
  TCA_MQPRIO_UNSPEC,
  TCA_MQPRIO_MODE,
  TCA_MQPRIO_SHAPER,
  TCA_MQPRIO_MIN_RATE64,
  TCA_MQPRIO_MAX_RATE64,
  TCA_MQPRIO_TC_ENTRY,
  __TCA_MQPRIO_MAX,
};
#define TCA_MQPRIO_MAX (__TCA_MQPRIO_MAX - 1)
enum {
  TCA_SFB_UNSPEC,
  TCA_SFB_PARMS,
  __TCA_SFB_MAX,
};
#define TCA_SFB_MAX (__TCA_SFB_MAX - 1)
struct tc_sfb_qopt {
  __u32 rehash_interval;
  __u32 warmup_time;
  __u32 max;
  __u32 bin_size;
  __u32 increment;
  __u32 decrement;
  __u32 limit;
  __u32 penalty_rate;
  __u32 penalty_burst;
};
struct tc_sfb_xstats {
  __u32 earlydrop;
  __u32 penaltydrop;
  __u32 bucketdrop;
  __u32 queuedrop;
  __u32 childdrop;
  __u32 marked;
  __u32 maxqlen;
  __u32 maxprob;
  __u32 avgprob;
};
#define SFB_MAX_PROB 0xFFFF
enum {
  TCA_QFQ_UNSPEC,
  TCA_QFQ_WEIGHT,
  TCA_QFQ_LMAX,
  __TCA_QFQ_MAX
};
#define TCA_QFQ_MAX (__TCA_QFQ_MAX - 1)
struct tc_qfq_stats {
  __u32 weight;
  __u32 lmax;
};
enum {
  TCA_CODEL_UNSPEC,
  TCA_CODEL_TARGET,
  TCA_CODEL_LIMIT,
  TCA_CODEL_INTERVAL,
  TCA_CODEL_ECN,
  TCA_CODEL_CE_THRESHOLD,
  __TCA_CODEL_MAX
};
#define TCA_CODEL_MAX (__TCA_CODEL_MAX - 1)
struct tc_codel_xstats {
  __u32 maxpacket;
  __u32 count;
  __u32 lastcount;
  __u32 ldelay;
  __s32 drop_next;
  __u32 drop_overlimit;
  __u32 ecn_mark;
  __u32 dropping;
  __u32 ce_mark;
};
#define FQ_CODEL_QUANTUM_MAX (1 << 20)
enum {
  TCA_FQ_CODEL_UNSPEC,
  TCA_FQ_CODEL_TARGET,
  TCA_FQ_CODEL_LIMIT,
  TCA_FQ_CODEL_INTERVAL,
  TCA_FQ_CODEL_ECN,
  TCA_FQ_CODEL_FLOWS,
  TCA_FQ_CODEL_QUANTUM,
  TCA_FQ_CODEL_CE_THRESHOLD,
  TCA_FQ_CODEL_DROP_BATCH_SIZE,
  TCA_FQ_CODEL_MEMORY_LIMIT,
  TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR,
  TCA_FQ_CODEL_CE_THRESHOLD_MASK,
  __TCA_FQ_CODEL_MAX
};
#define TCA_FQ_CODEL_MAX (__TCA_FQ_CODEL_MAX - 1)
enum {
  TCA_FQ_CODEL_XSTATS_QDISC,
  TCA_FQ_CODEL_XSTATS_CLASS,
};
struct tc_fq_codel_qd_stats {
  __u32 maxpacket;
  __u32 drop_overlimit;
  __u32 ecn_mark;
  __u32 new_flow_count;
  __u32 new_flows_len;
  __u32 old_flows_len;
  __u32 ce_mark;
  __u32 memory_usage;
  __u32 drop_overmemory;
};
struct tc_fq_codel_cl_stats {
  __s32 deficit;
  __u32 ldelay;
  __u32 count;
  __u32 lastcount;
  __u32 dropping;
  __s32 drop_next;
};
struct tc_fq_codel_xstats {
  __u32 type;
  union {
    struct tc_fq_codel_qd_stats qdisc_stats;
    struct tc_fq_codel_cl_stats class_stats;
  };
};
enum {
  TCA_FQ_UNSPEC,
  TCA_FQ_PLIMIT,
  TCA_FQ_FLOW_PLIMIT,
  TCA_FQ_QUANTUM,
  TCA_FQ_INITIAL_QUANTUM,
  TCA_FQ_RATE_ENABLE,
  TCA_FQ_FLOW_DEFAULT_RATE,
  TCA_FQ_FLOW_MAX_RATE,
  TCA_FQ_BUCKETS_LOG,
  TCA_FQ_FLOW_REFILL_DELAY,
  TCA_FQ_ORPHAN_MASK,
  TCA_FQ_LOW_RATE_THRESHOLD,
  TCA_FQ_CE_THRESHOLD,
  TCA_FQ_TIMER_SLACK,
  TCA_FQ_HORIZON,
  TCA_FQ_HORIZON_DROP,
  TCA_FQ_PRIOMAP,
  TCA_FQ_WEIGHTS,
  __TCA_FQ_MAX
};
#define TCA_FQ_MAX (__TCA_FQ_MAX - 1)
#define FQ_BANDS 3
#define FQ_MIN_WEIGHT 16384
struct tc_fq_qd_stats {
  __u64 gc_flows;
  __u64 highprio_packets;
  __u64 tcp_retrans;
  __u64 throttled;
  __u64 flows_plimit;
  __u64 pkts_too_long;
  __u64 allocation_errors;
  __s64 time_next_delayed_flow;
  __u32 flows;
  __u32 inactive_flows;
  __u32 throttled_flows;
  __u32 unthrottle_latency_ns;
  __u64 ce_mark;
  __u64 horizon_drops;
  __u64 horizon_caps;
  __u64 fastpath_packets;
  __u64 band_drops[FQ_BANDS];
  __u32 band_pkt_count[FQ_BANDS];
  __u32 pad;
};
enum {
  TCA_HHF_UNSPEC,
  TCA_HHF_BACKLOG_LIMIT,
  TCA_HHF_QUANTUM,
  TCA_HHF_HH_FLOWS_LIMIT,
  TCA_HHF_RESET_TIMEOUT,
  TCA_HHF_ADMIT_BYTES,
  TCA_HHF_EVICT_TIMEOUT,
  TCA_HHF_NON_HH_WEIGHT,
  __TCA_HHF_MAX
};
#define TCA_HHF_MAX (__TCA_HHF_MAX - 1)
struct tc_hhf_xstats {
  __u32 drop_overlimit;
  __u32 hh_overlimit;
  __u32 hh_tot_count;
  __u32 hh_cur_count;
};
enum {
  TCA_PIE_UNSPEC,
  TCA_PIE_TARGET,
  TCA_PIE_LIMIT,
  TCA_PIE_TUPDATE,
  TCA_PIE_ALPHA,
  TCA_PIE_BETA,
  TCA_PIE_ECN,
  TCA_PIE_BYTEMODE,
  TCA_PIE_DQ_RATE_ESTIMATOR,
  __TCA_PIE_MAX
};
#define TCA_PIE_MAX (__TCA_PIE_MAX - 1)
struct tc_pie_xstats {
  __u64 prob;
  __u32 delay;
  __u32 avg_dq_rate;
  __u32 dq_rate_estimating;
  __u32 packets_in;
  __u32 dropped;
  __u32 overlimit;
  __u32 maxq;
  __u32 ecn_mark;
};
enum {
  TCA_FQ_PIE_UNSPEC,
  TCA_FQ_PIE_LIMIT,
  TCA_FQ_PIE_FLOWS,
  TCA_FQ_PIE_TARGET,
  TCA_FQ_PIE_TUPDATE,
  TCA_FQ_PIE_ALPHA,
  TCA_FQ_PIE_BETA,
  TCA_FQ_PIE_QUANTUM,
  TCA_FQ_PIE_MEMORY_LIMIT,
  TCA_FQ_PIE_ECN_PROB,
  TCA_FQ_PIE_ECN,
  TCA_FQ_PIE_BYTEMODE,
  TCA_FQ_PIE_DQ_RATE_ESTIMATOR,
  __TCA_FQ_PIE_MAX
};
#define TCA_FQ_PIE_MAX (__TCA_FQ_PIE_MAX - 1)
struct tc_fq_pie_xstats {
  __u32 packets_in;
  __u32 dropped;
  __u32 overlimit;
  __u32 overmemory;
  __u32 ecn_mark;
  __u32 new_flow_count;
  __u32 new_flows_len;
  __u32 old_flows_len;
  __u32 memory_usage;
};
struct tc_cbs_qopt {
  __u8 offload;
  __u8 _pad[3];
  __s32 hicredit;
  __s32 locredit;
  __s32 idleslope;
  __s32 sendslope;
};
enum {
  TCA_CBS_UNSPEC,
  TCA_CBS_PARMS,
  __TCA_CBS_MAX,
};
#define TCA_CBS_MAX (__TCA_CBS_MAX - 1)
struct tc_etf_qopt {
  __s32 delta;
  __s32 clockid;
  __u32 flags;
#define TC_ETF_DEADLINE_MODE_ON _BITUL(0)
#define TC_ETF_OFFLOAD_ON _BITUL(1)
#define TC_ETF_SKIP_SOCK_CHECK _BITUL(2)
};
enum {
  TCA_ETF_UNSPEC,
  TCA_ETF_PARMS,
  __TCA_ETF_MAX,
};
#define TCA_ETF_MAX (__TCA_ETF_MAX - 1)
enum {
  TCA_CAKE_UNSPEC,
  TCA_CAKE_PAD,
  TCA_CAKE_BASE_RATE64,
  TCA_CAKE_DIFFSERV_MODE,
  TCA_CAKE_ATM,
  TCA_CAKE_FLOW_MODE,
  TCA_CAKE_OVERHEAD,
  TCA_CAKE_RTT,
  TCA_CAKE_TARGET,
  TCA_CAKE_AUTORATE,
  TCA_CAKE_MEMORY,
  TCA_CAKE_NAT,
  TCA_CAKE_RAW,
  TCA_CAKE_WASH,
  TCA_CAKE_MPU,
  TCA_CAKE_INGRESS,
  TCA_CAKE_ACK_FILTER,
  TCA_CAKE_SPLIT_GSO,
  TCA_CAKE_FWMARK,
  __TCA_CAKE_MAX
};
#define TCA_CAKE_MAX (__TCA_CAKE_MAX - 1)
enum {
  __TCA_CAKE_STATS_INVALID,
  TCA_CAKE_STATS_PAD,
  TCA_CAKE_STATS_CAPACITY_ESTIMATE64,
  TCA_CAKE_STATS_MEMORY_LIMIT,
  TCA_CAKE_STATS_MEMORY_USED,
  TCA_CAKE_STATS_AVG_NETOFF,
  TCA_CAKE_STATS_MIN_NETLEN,
  TCA_CAKE_STATS_MAX_NETLEN,
  TCA_CAKE_STATS_MIN_ADJLEN,
  TCA_CAKE_STATS_MAX_ADJLEN,
  TCA_CAKE_STATS_TIN_STATS,
  TCA_CAKE_STATS_DEFICIT,
  TCA_CAKE_STATS_COBALT_COUNT,
  TCA_CAKE_STATS_DROPPING,
  TCA_CAKE_STATS_DROP_NEXT_US,
  TCA_CAKE_STATS_P_DROP,
  TCA_CAKE_STATS_BLUE_TIMER_US,
  __TCA_CAKE_STATS_MAX
};
#define TCA_CAKE_STATS_MAX (__TCA_CAKE_STATS_MAX - 1)
enum {
  __TCA_CAKE_TIN_STATS_INVALID,
  TCA_CAKE_TIN_STATS_PAD,
  TCA_CAKE_TIN_STATS_SENT_PACKETS,
  TCA_CAKE_TIN_STATS_SENT_BYTES64,
  TCA_CAKE_TIN_STATS_DROPPED_PACKETS,
  TCA_CAKE_TIN_STATS_DROPPED_BYTES64,
  TCA_CAKE_TIN_STATS_ACKS_DROPPED_PACKETS,
  TCA_CAKE_TIN_STATS_ACKS_DROPPED_BYTES64,
  TCA_CAKE_TIN_STATS_ECN_MARKED_PACKETS,
  TCA_CAKE_TIN_STATS_ECN_MARKED_BYTES64,
  TCA_CAKE_TIN_STATS_BACKLOG_PACKETS,
  TCA_CAKE_TIN_STATS_BACKLOG_BYTES,
  TCA_CAKE_TIN_STATS_THRESHOLD_RATE64,
  TCA_CAKE_TIN_STATS_TARGET_US,
  TCA_CAKE_TIN_STATS_INTERVAL_US,
  TCA_CAKE_TIN_STATS_WAY_INDIRECT_HITS,
  TCA_CAKE_TIN_STATS_WAY_MISSES,
  TCA_CAKE_TIN_STATS_WAY_COLLISIONS,
  TCA_CAKE_TIN_STATS_PEAK_DELAY_US,
  TCA_CAKE_TIN_STATS_AVG_DELAY_US,
  TCA_CAKE_TIN_STATS_BASE_DELAY_US,
  TCA_CAKE_TIN_STATS_SPARSE_FLOWS,
  TCA_CAKE_TIN_STATS_BULK_FLOWS,
  TCA_CAKE_TIN_STATS_UNRESPONSIVE_FLOWS,
  TCA_CAKE_TIN_STATS_MAX_SKBLEN,
  TCA_CAKE_TIN_STATS_FLOW_QUANTUM,
  __TCA_CAKE_TIN_STATS_MAX
};
#define TCA_CAKE_TIN_STATS_MAX (__TCA_CAKE_TIN_STATS_MAX - 1)
#define TC_CAKE_MAX_TINS (8)
enum {
  CAKE_FLOW_NONE = 0,
  CAKE_FLOW_SRC_IP,
  CAKE_FLOW_DST_IP,
  CAKE_FLOW_HOSTS,
  CAKE_FLOW_FLOWS,
  CAKE_FLOW_DUAL_SRC,
  CAKE_FLOW_DUAL_DST,
  CAKE_FLOW_TRIPLE,
  CAKE_FLOW_MAX,
};
enum {
  CAKE_DIFFSERV_DIFFSERV3 = 0,
  CAKE_DIFFSERV_DIFFSERV4,
  CAKE_DIFFSERV_DIFFSERV8,
  CAKE_DIFFSERV_BESTEFFORT,
  CAKE_DIFFSERV_PRECEDENCE,
  CAKE_DIFFSERV_MAX
};
enum {
  CAKE_ACK_NONE = 0,
  CAKE_ACK_FILTER,
  CAKE_ACK_AGGRESSIVE,
  CAKE_ACK_MAX
};
enum {
  CAKE_ATM_NONE = 0,
  CAKE_ATM_ATM,
  CAKE_ATM_PTM,
  CAKE_ATM_MAX
};
enum {
  TC_TAPRIO_CMD_SET_GATES = 0x00,
  TC_TAPRIO_CMD_SET_AND_HOLD = 0x01,
  TC_TAPRIO_CMD_SET_AND_RELEASE = 0x02,
};
enum {
  TCA_TAPRIO_SCHED_ENTRY_UNSPEC,
  TCA_TAPRIO_SCHED_ENTRY_INDEX,
  TCA_TAPRIO_SCHED_ENTRY_CMD,
  TCA_TAPRIO_SCHED_ENTRY_GATE_MASK,
  TCA_TAPRIO_SCHED_ENTRY_INTERVAL,
  __TCA_TAPRIO_SCHED_ENTRY_MAX,
};
#define TCA_TAPRIO_SCHED_ENTRY_MAX (__TCA_TAPRIO_SCHED_ENTRY_MAX - 1)
enum {
  TCA_TAPRIO_SCHED_UNSPEC,
  TCA_TAPRIO_SCHED_ENTRY,
  __TCA_TAPRIO_SCHED_MAX,
};
#define TCA_TAPRIO_SCHED_MAX (__TCA_TAPRIO_SCHED_MAX - 1)
#define TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST _BITUL(0)
#define TCA_TAPRIO_ATTR_FLAG_FULL_OFFLOAD _BITUL(1)
enum {
  TCA_TAPRIO_TC_ENTRY_UNSPEC,
  TCA_TAPRIO_TC_ENTRY_INDEX,
  TCA_TAPRIO_TC_ENTRY_MAX_SDU,
  TCA_TAPRIO_TC_ENTRY_FP,
  __TCA_TAPRIO_TC_ENTRY_CNT,
  TCA_TAPRIO_TC_ENTRY_MAX = (__TCA_TAPRIO_TC_ENTRY_CNT - 1)
};
enum {
  TCA_TAPRIO_OFFLOAD_STATS_PAD = 1,
  TCA_TAPRIO_OFFLOAD_STATS_WINDOW_DROPS,
  TCA_TAPRIO_OFFLOAD_STATS_TX_OVERRUNS,
  __TCA_TAPRIO_OFFLOAD_STATS_CNT,
  TCA_TAPRIO_OFFLOAD_STATS_MAX = (__TCA_TAPRIO_OFFLOAD_STATS_CNT - 1)
};
enum {
  TCA_TAPRIO_ATTR_UNSPEC,
  TCA_TAPRIO_ATTR_PRIOMAP,
  TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST,
  TCA_TAPRIO_ATTR_SCHED_BASE_TIME,
  TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY,
  TCA_TAPRIO_ATTR_SCHED_CLOCKID,
  TCA_TAPRIO_PAD,
  TCA_TAPRIO_ATTR_ADMIN_SCHED,
  TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME,
  TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION,
  TCA_TAPRIO_ATTR_FLAGS,
  TCA_TAPRIO_ATTR_TXTIME_DELAY,
  TCA_TAPRIO_ATTR_TC_ENTRY,
  __TCA_TAPRIO_ATTR_MAX,
};
#define TCA_TAPRIO_ATTR_MAX (__TCA_TAPRIO_ATTR_MAX - 1)
#define TCQ_ETS_MAX_BANDS 16
enum {
  TCA_ETS_UNSPEC,
  TCA_ETS_NBANDS,
  TCA_ETS_NSTRICT,
  TCA_ETS_QUANTA,
  TCA_ETS_QUANTA_BAND,
  TCA_ETS_PRIOMAP,
  TCA_ETS_PRIOMAP_BAND,
  __TCA_ETS_MAX,
};
#define TCA_ETS_MAX (__TCA_ETS_MAX - 1)
#endif

"""

```