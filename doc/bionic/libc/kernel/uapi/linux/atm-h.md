Response:
Let's break down the thought process for analyzing this header file and generating the detailed response.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `atm.h` header file, including its purpose, relationship to Android, function implementation details (even though it's a header), dynamic linker involvement, usage errors, and how Android reaches this code.

**2. Initial Assessment of the File:**

* **Header File Nature:** The first and most crucial observation is that this is a header file (`.h`). Header files primarily define data structures, constants, and function prototypes. They *declare* things, not *implement* them. This immediately tells us we won't find actual function implementations here.
* **`#ifndef _UAPI_LINUX_ATM_H`:** This is a standard header guard to prevent multiple inclusions, a basic C/C++ practice.
* **Includes:** The file includes other kernel headers (`linux/compiler.h`, `linux/atmapi.h`, etc.). This strongly indicates that this header is part of the Linux kernel API related to Asynchronous Transfer Mode (ATM) networking. The `uapi` in the path confirms this, signifying "User API."
* **Definitions and Structures:** The majority of the file consists of `#define` macros (constants) and `struct` definitions. These define the vocabulary and data organization for interacting with the ATM subsystem.

**3. Deconstructing the Content:**

Now, let's go through the file section by section, thinking about the purpose of each element:

* **Constants (`#define`):**  These define specific values used within the ATM protocol. Examples: `ATM_CELL_SIZE`, `ATM_MAX_VCI`, `ATM_AAL5`. These are fundamental to understanding how ATM works.
* **Socket Options (`__SO_ENCODE`, `SO_SETCLP`, etc.):**  The `SO_` prefixed definitions suggest socket options related to ATM. The `__SO_ENCODE` macro is a bitmasking function to pack level, number, and size information into a single integer. This hints at how ATM-specific socket options are managed.
* **Header Bitmasks (`ATM_HDR_GFC_MASK`, etc.):** These macros define bit masks and shifts for accessing fields within an ATM cell header. This is crucial for anyone working with raw ATM packets.
* **Traffic Parameters and QoS (`struct atm_trafprm`, `struct atm_qos`):** These structures define how to describe the characteristics of an ATM connection (traffic class, bandwidth, etc.) and the overall Quality of Service requirements.
* **Addressing Structures (`struct sockaddr_atmpvc`, `struct sockaddr_atmsvc`):** These define structures for representing ATM addresses, analogous to IP addresses in TCP/IP. `sockaddr_atmpvc` likely represents a Permanent Virtual Circuit (PVC), and `sockaddr_atmsvc` a Switched Virtual Circuit (SVC).
* **Interface Structure (`struct atmif_sioc`):** This structure seems related to ioctl calls for configuring ATM interfaces.
* **Typedef (`typedef unsigned short atm_backend_t;`):** This creates an alias for an unsigned short, likely used to represent an ATM backend identifier.

**4. Connecting to Android and Libc:**

* **`uapi` Importance:** Recognizing that this is a `uapi` header is key. It means this defines the *interface* between user-space programs and the Linux kernel's ATM implementation.
* **Libc's Role:**  Android's `bionic` libc provides the standard C library functions. For networking, this includes the socket API (`socket()`, `bind()`, `connect()`, `setsockopt()`, etc.). While this header *doesn't* implement those functions, it defines the *data structures and constants* that those functions would use when interacting with the ATM kernel module.
* **No Direct Libc Functions *Implemented* Here:**  It's crucial to emphasize that this header file itself doesn't contain the implementation of any libc functions. It provides the definitions needed by those functions.

**5. Dynamic Linker (Limited Scope):**

The dynamic linker (`linker`) is responsible for loading shared libraries (`.so` files). While this header defines structures, it doesn't directly involve the dynamic linker's operation in the typical sense. However, if an Android application or a system service were to interact with the ATM subsystem (which is highly unlikely in modern Android), then any libraries involved in that interaction would be subject to the dynamic linker's loading and linking process.

**6. Potential Usage Errors:**

Think about common programming mistakes when working with networking and data structures:

* **Incorrect Size Calculations:**  Using the wrong size for structures when passing them to system calls.
* **Endianness Issues:** Although less likely here given it's primarily kernel-space interaction, endianness can be a problem in network programming.
* **Misinterpreting Constants:** Using the wrong constant value for a specific configuration option.
* **Incorrect Structure Initialization:**  Not properly initializing the fields of the structures before passing them to system calls.

**7. Android Framework and NDK Path (Highly Speculative):**

Reaching this code from the Android Framework or NDK is extremely rare in modern Android. ATM is an older technology. The path would be something like:

* **NDK:** An NDK application would need to use the raw socket API (`socket()`, `setsockopt()`, etc.) and specifically target the ATM protocol family (if even exposed).
* **Framework:**  It's unlikely the high-level Android Framework has direct ATM support. It would probably involve low-level system services or HAL (Hardware Abstraction Layer) components, which are very device-specific and uncommon for ATM.

**8. Frida Hooking (Conceptual):**

Since we don't have concrete libc function implementations here, Frida hooking would target system calls related to sockets and ATM. You'd be looking for system calls like `socket`, `setsockopt`, and potentially ioctls related to ATM interfaces.

**9. Structuring the Response:**

Organize the information logically:

* Start with a clear statement of the file's nature and purpose.
* List its key functionalities based on the content.
* Explain the relationship to Android and libc (emphasizing it's definitions, not implementations).
* Discuss the limited involvement of the dynamic linker.
* Provide examples of usage errors.
* Speculate on the Android/NDK path and give a conceptual Frida example.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file defines some internal libc functions related to networking.
* **Correction:**  Realizing it's a `uapi` header clarifies that it's an interface to the kernel, not libc implementation.
* **Initial thought:** Focus on specific function implementations.
* **Correction:** Shift focus to the data structures and constants defined, as that's the core content of a header file.
* **Realization:**  ATM is very niche in modern Android. Emphasize the low probability of this code being directly used by most Android applications.

By following this structured thinking and iteratively refining the understanding, we can arrive at a comprehensive and accurate analysis of the provided header file.
这是一个定义了Linux内核中与ATM（Asynchronous Transfer Mode，异步传输模式）网络协议相关的用户空间API的头文件。由于它位于 `bionic/libc/kernel/uapi` 路径下，可以确定它是Android Bionic C库中用于与Linux内核交互的一部分。

**功能列举:**

这个头文件主要定义了以下内容，从而为用户空间的程序提供了与ATM协议交互的基础：

1. **常量定义 (`#define`)**:
   - ATM信元大小 (`ATM_CELL_SIZE`, `ATM_CELL_PAYLOAD`)
   - 不同AAL（ATM Adaptation Layer，ATM适配层）的SDU（Service Data Unit，服务数据单元）和PDU（Protocol Data Unit，协议数据单元）的最大尺寸 (`ATM_AAL0_SDU`, `ATM_MAX_AAL34_PDU`, `ATM_MAX_AAL5_PDU`)
   - 其他与ATM相关的数值限制，例如最大CDV（Cell Delay Variation，信元延迟抖动），保留的VCI（Virtual Channel Identifier，虚拟通道标识符），最大VPI（Virtual Path Identifier，虚拟路径标识符）等。
   - 定义了不同的AAL类型 (`ATM_NO_AAL`, `ATM_AAL0`, `ATM_AAL1`, `ATM_AAL2`, `ATM_AAL34`, `ATM_AAL5`)。
   - 定义了socket选项相关的宏，用于设置和获取ATM相关的socket选项 (`SO_SETCLP`, `SO_CIRANGE`, `SO_ATMQOS`, `SO_ATMSAP`, `SO_ATMPVC`, `SO_MULTIPOINT`)。这些宏使用了 `__SO_ENCODE` 宏进行编码。
   - 定义了ATM头部字段的掩码和位移 (`ATM_HDR_GFC_MASK`, `ATM_HDR_VPI_MASK`, `ATM_HDR_VCI_MASK` 等)，用于解析ATM信元头部。
   - 定义了PTI（Payload Type Identifier，负载类型标识符）的取值 (`ATM_PTI_US0`, `ATM_PTI_US1` 等)。
   - 定义了不同的业务类别 (`ATM_NONE`, `ATM_UBR`, `ATM_CBR`, `ATM_VBR`, `ATM_ABR`, `ATM_ANYCLASS`)。

2. **结构体定义 (`struct`)**:
   - `atm_trafprm`: 定义了ATM连接的流量参数，如业务类别、峰值信元速率（PCR）、最大信元延迟抖动（CDV）、最大SDU大小等。
   - `atm_qos`: 定义了ATM连接的QoS（Quality of Service，服务质量）参数，包含发送和接收的流量参数以及AAL类型。
   - `sockaddr_atmpvc`: 定义了ATM PVC（Permanent Virtual Circuit，永久虚电路）的套接字地址结构，包含接口号、VPI和VCI。
   - `sockaddr_atmsvc`: 定义了ATM SVC（Switched Virtual Circuit，交换虚电路）的套接字地址结构，包含私有地址、公共地址、链路完整性指示类型和ID。
   - `atmif_sioc`:  可能用于ATM接口相关的ioctl操作，包含接口号、数据长度和数据指针。

3. **类型定义 (`typedef`)**:
   - `atm_backend_t`: 定义了ATM后端类型的别名。

**与Android功能的关联和举例:**

虽然ATM技术在现代移动设备中并不常见，但在早期的Android设备或某些特定的工业应用中可能会涉及到。这个头文件提供了用户空间程序（包括Android的Native代码）与Linux内核中ATM驱动程序交互的接口。

**举例说明:**

假设一个早期的Android设备或一个基于Android的工业设备连接到了一个ATM网络。一个Native应用可能需要创建ATM socket，设置QoS参数，或者监听特定的VPI/VCI连接。

```c
#include <sys/socket.h>
#include <linux/atm.h>
#include <linux/atmpvc.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int sock_fd = socket(AF_ATM, SOCK_DGRAM, 0); // 创建一个ATM socket
    if (sock_fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_atmpvc addr;
    addr.sap_family = AF_ATM;
    addr.sap_addr.itf = 0; // 假设接口号为0
    addr.sap_addr.vpi = 0;
    addr.sap_addr.vci = 32; // 连接到VCI 32

    if (bind(sock_fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock_fd);
        return 1;
    }

    printf("ATM socket绑定成功，监听 VPI: %d, VCI: %d\n", addr.sap_addr.vpi, addr.sap_addr.vci);

    // 可以继续进行发送和接收ATM信元的操作...

    close(sock_fd);
    return 0;
}
```

在这个例子中，`socket(AF_ATM, SOCK_DGRAM, 0)` 使用了 `AF_ATM` 常量，这个常量可能在 `linux/atm.h` 或者其他相关的头文件中定义。`sockaddr_atmpvc` 结构体被用来指定ATM地址，其定义就来自于当前的 `atm.h` 文件。

**libc函数的功能实现:**

这个头文件本身 **不包含任何libc函数的实现**。它只是定义了数据结构和常量，供libc中的网络相关函数（如 `socket`, `bind`, `setsockopt` 等）使用。

例如，当你在用户空间调用 `socket(AF_ATM, ...)` 时，libc中的 `socket` 函数实现会根据 `AF_ATM` 参数来决定使用哪个协议族的操作。`AF_ATM` 的定义可能就在这个 `atm.h` 文件中。

当调用 `bind` 函数绑定ATM地址时，`sockaddr_atmpvc` 结构体的信息会被传递给内核，内核中的ATM驱动程序会根据这些信息来配置网络连接。

**dynamic linker的功能:**

这个头文件主要定义了数据结构和常量，与动态链接器没有直接的功能关联。动态链接器 (`linker` 或 `ld-android.so`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号引用。

**so布局样本和链接处理过程:**

由于 `atm.h` 是一个头文件，它不会被编译成 `.so` 文件。然而，如果用户空间的程序需要使用这里定义的数据结构和常量，它需要链接到提供网络功能的libc库 (`libc.so`)。

**假设的so布局样本 (libc.so的一部分):**

```
libc.so:
    ...
    .symtab:
        ...
        socket: function address
        bind: function address
        setsockopt: function address
        AF_ATM: constant value
        SOL_ATM: constant value
        ...
    .rel.dyn:
        ...
        # 如果用户代码使用了AF_ATM，这里会有相关的重定位信息
        ...
```

**链接处理过程:**

1. 编译器在编译用户代码时，如果遇到 `socket(AF_ATM, ...)`，会生成一个对 `socket` 函数和 `AF_ATM` 常量的符号引用。
2. 链接器在链接用户代码和 `libc.so` 时，会查找 `libc.so` 的符号表，找到 `socket` 函数的地址和 `AF_ATM` 常量的值。
3. 链接器会将用户代码中对 `socket` 的调用指令修改为跳转到 `libc.so` 中 `socket` 函数的实际地址。
4. 链接器会将用户代码中使用的 `AF_ATM` 替换为 `libc.so` 中定义的 `AF_ATM` 的实际值。

**逻辑推理，假设输入与输出:**

假设有一个程序需要设置ATM socket的CLP (Cell Loss Priority，信元丢失优先级) 选项。

**假设输入:**

- socket描述符 `sock_fd`
- CLP的值 `clp_value` (例如，0或1)

**代码片段:**

```c
#include <sys/socket.h>
#include <linux/atm.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    int sock_fd = socket(AF_ATM, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        perror("socket");
        return 1;
    }

    int clp_value = 1; // 设置CLP为1

    if (setsockopt(sock_fd, SOL_ATM, SO_SETCLP, &clp_value, sizeof(clp_value)) == -1) {
        perror("setsockopt");
        close(sock_fd);
        return 1;
    }

    printf("成功设置ATM socket的CLP选项为 %d\n", clp_value);

    close(sock_fd);
    return 0;
}
```

**输出:**

如果 `setsockopt` 调用成功，程序会输出 "成功设置ATM socket的CLP选项为 1"。如果失败，会输出 "setsockopt: 错误信息"。

在这个例子中，`SOL_ATM` 和 `SO_SETCLP` 的定义就来自于 `atm.h`。 `setsockopt` 是libc提供的函数，它会根据这些参数来调用底层的内核接口。

**用户或编程常见的使用错误:**

1. **头文件包含错误:** 没有包含正确的头文件 (`linux/atm.h`)，导致无法识别 `AF_ATM`, `SOL_ATM`, `SO_SETCLP` 等常量和结构体。
2. **socket域错误:**  创建socket时使用了错误的域，例如使用了 `AF_INET` 而不是 `AF_ATM`。
3. **socket选项值错误:**  传递给 `setsockopt` 的选项值类型或大小不正确，例如，期望传入 `struct atm_cirange` 却传入了 `int`。
4. **地址结构体初始化错误:**  没有正确初始化 `sockaddr_atmpvc` 或 `sockaddr_atmsvc` 结构体的字段，例如，VPI或VCI的值不合法。
5. **权限问题:**  执行需要特定权限的ATM操作，但用户没有相应的权限。

**Android Framework或NDK如何一步步到达这里:**

1. **NDK 应用:**
   - NDK开发者可以使用C/C++编写Native代码。
   - 如果NDK应用需要进行底层的ATM网络编程（这种情况非常罕见，因为现代Android设备通常不直接使用ATM），开发者需要在Native代码中包含 `<linux/atm.h>` 头文件。
   - 使用标准的socket API (如 `socket`, `bind`, `connect`, `setsockopt`)，并使用 `AF_ATM` 常量来创建ATM socket。
   - 当这些libc函数被调用时，它们会最终通过系统调用与Linux内核进行交互。

2. **Android Framework (可能性极低):**
   - Android Framework通常使用更高层次的网络抽象 (如Java的 `java.net` 包)。
   - 直接使用ATM的可能性极低。即使需要，也可能通过底层的Native库进行封装，然后通过JNI (Java Native Interface) 供Framework调用。
   - Framework层面不太可能直接包含或使用这个头文件中定义的结构体和常量。

**Frida Hook示例调试这些步骤:**

由于直接使用ATM的情况非常罕见，以下提供一个 **假设性的** Frida Hook 示例，用于监控 `setsockopt` 函数在 `SOL_ATM` 层级的调用：

```javascript
if (Process.platform === 'linux') {
  const setsockoptPtr = Module.findExportByName('libc.so', 'setsockopt');

  if (setsockoptPtr) {
    Interceptor.attach(setsockoptPtr, {
      onEnter: function (args) {
        const sockfd = args[0].toInt32();
        const level = args[1].toInt32();
        const optname = args[2].toInt32();

        if (level === 16 /* SOL_ATM 的值，需要根据实际系统确定 */) {
          console.log(`setsockopt(sockfd=${sockfd}, level=SOL_ATM, optname=${optname})`);

          // 可以进一步解析 optname 和 optval
          if (optname === /* SO_SETCLP 的值 */) {
            const optvalPtr = ptr(args[3]);
            const optlen = args[4].toInt32();
            if (optlen === 4) {
              const clpValue = optvalPtr.readInt();
              console.log(`  -> SO_SETCLP, value=${clpValue}`);
            }
          }
          // ... 可以添加更多对其他 ATM socket 选项的解析
        }
      },
      onLeave: function (retval) {
        // console.log('setsockopt returned:', retval);
      }
    });
    console.log('Frida hook 已安装到 setsockopt');
  } else {
    console.log('未找到 setsockopt 函数');
  }
} else {
  console.log('此示例仅适用于 Linux 平台');
}
```

**说明:**

1. **查找 `setsockopt`:**  首先找到 `libc.so` 中 `setsockopt` 函数的地址。
2. **拦截 `setsockopt`:**  使用 `Interceptor.attach` 拦截 `setsockopt` 函数的调用。
3. **检查 `level`:** 在 `onEnter` 中，检查 `level` 参数是否等于 `SOL_ATM` 的值（需要根据实际系统确定）。
4. **解析 `optname` 和 `optval`:** 如果 `level` 是 `SOL_ATM`，可以进一步检查 `optname` 来确定具体的ATM socket选项（例如 `SO_SETCLP`）。然后可以读取 `optval` 的值并打印出来。

请注意，由于ATM在现代Android设备中非常罕见，实际运行此Hook可能不会捕获到任何相关的调用。这个示例主要是为了说明如何使用Frida来监控与特定socket层级相关的系统调用。

总结来说，`bionic/libc/kernel/uapi/linux/atm.h` 是Android Bionic中定义Linux内核ATM用户空间API的头文件，它为用户空间的程序提供了与ATM网络协议交互所需的数据结构和常量。虽然ATM在现代Android设备中不常见，但理解这类文件有助于理解Android与Linux内核的交互方式，以及底层网络编程的基本概念。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/atm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_ATM_H
#define _UAPI_LINUX_ATM_H
#include <linux/compiler.h>
#include <linux/atmapi.h>
#include <linux/atmsap.h>
#include <linux/atmioc.h>
#include <linux/types.h>
#define ATM_CELL_SIZE 53
#define ATM_CELL_PAYLOAD 48
#define ATM_AAL0_SDU 52
#define ATM_MAX_AAL34_PDU 65535
#define ATM_AAL5_TRAILER 8
#define ATM_MAX_AAL5_PDU 65535
#define ATM_MAX_CDV 9999
#define ATM_NOT_RSV_VCI 32
#define ATM_MAX_VPI 255
#define ATM_MAX_VPI_NNI 4096
#define ATM_MAX_VCI 65535
#define ATM_NO_AAL 0
#define ATM_AAL0 13
#define ATM_AAL1 1
#define ATM_AAL2 2
#define ATM_AAL34 3
#define ATM_AAL5 5
#define __SO_ENCODE(l,n,t) ((((l) & 0x1FF) << 22) | ((n) << 16) | sizeof(t))
#define __SO_LEVEL_MATCH(c,m) (((c) >> 22) == ((m) & 0x1FF))
#define __SO_NUMBER(c) (((c) >> 16) & 0x3f)
#define __SO_SIZE(c) ((c) & 0x3fff)
#define SO_SETCLP __SO_ENCODE(SOL_ATM, 0, int)
#define SO_CIRANGE __SO_ENCODE(SOL_ATM, 1, struct atm_cirange)
#define SO_ATMQOS __SO_ENCODE(SOL_ATM, 2, struct atm_qos)
#define SO_ATMSAP __SO_ENCODE(SOL_ATM, 3, struct atm_sap)
#define SO_ATMPVC __SO_ENCODE(SOL_ATM, 4, struct sockaddr_atmpvc)
#define SO_MULTIPOINT __SO_ENCODE(SOL_ATM, 5, int)
#define ATM_HDR_GFC_MASK 0xf0000000
#define ATM_HDR_GFC_SHIFT 28
#define ATM_HDR_VPI_MASK 0x0ff00000
#define ATM_HDR_VPI_SHIFT 20
#define ATM_HDR_VCI_MASK 0x000ffff0
#define ATM_HDR_VCI_SHIFT 4
#define ATM_HDR_PTI_MASK 0x0000000e
#define ATM_HDR_PTI_SHIFT 1
#define ATM_HDR_CLP 0x00000001
#define ATM_PTI_US0 0
#define ATM_PTI_US1 1
#define ATM_PTI_UCES0 2
#define ATM_PTI_UCES1 3
#define ATM_PTI_SEGF5 4
#define ATM_PTI_E2EF5 5
#define ATM_PTI_RSV_RM 6
#define ATM_PTI_RSV 7
#define ATM_NONE 0
#define ATM_UBR 1
#define ATM_CBR 2
#define ATM_VBR 3
#define ATM_ABR 4
#define ATM_ANYCLASS 5
#define ATM_MAX_PCR - 1
struct atm_trafprm {
  unsigned char traffic_class;
  int max_pcr;
  int pcr;
  int min_pcr;
  int max_cdv;
  int max_sdu;
  unsigned int icr;
  unsigned int tbe;
  unsigned int frtt : 24;
  unsigned int rif : 4;
  unsigned int rdf : 4;
  unsigned int nrm_pres : 1;
  unsigned int trm_pres : 1;
  unsigned int adtf_pres : 1;
  unsigned int cdf_pres : 1;
  unsigned int nrm : 3;
  unsigned int trm : 3;
  unsigned int adtf : 10;
  unsigned int cdf : 3;
  unsigned int spare : 9;
};
struct atm_qos {
  struct atm_trafprm txtp;
  struct atm_trafprm rxtp __ATM_API_ALIGN;
  unsigned char aal __ATM_API_ALIGN;
};
#define ATM_ITF_ANY - 1
#define ATM_VPI_ANY - 1
#define ATM_VCI_ANY - 1
#define ATM_VPI_UNSPEC - 2
#define ATM_VCI_UNSPEC - 2
struct sockaddr_atmpvc {
  unsigned short sap_family;
  struct {
    short itf;
    short vpi;
    int vci;
  } sap_addr __ATM_API_ALIGN;
};
#define ATM_ESA_LEN 20
#define ATM_E164_LEN 12
#define ATM_AFI_DCC 0x39
#define ATM_AFI_ICD 0x47
#define ATM_AFI_E164 0x45
#define ATM_AFI_LOCAL 0x49
#define ATM_AFI_DCC_GROUP 0xBD
#define ATM_AFI_ICD_GROUP 0xC5
#define ATM_AFI_E164_GROUP 0xC3
#define ATM_AFI_LOCAL_GROUP 0xC7
#define ATM_LIJ_NONE 0
#define ATM_LIJ 1
#define ATM_LIJ_RPJ 2
#define ATM_LIJ_NJ 3
struct sockaddr_atmsvc {
  unsigned short sas_family;
  struct {
    unsigned char prv[ATM_ESA_LEN];
    char pub[ATM_E164_LEN + 1];
    char lij_type;
    __u32 lij_id;
  } sas_addr __ATM_API_ALIGN;
};
struct atmif_sioc {
  int number;
  int length;
  void  * arg;
};
typedef unsigned short atm_backend_t;
#endif

"""

```