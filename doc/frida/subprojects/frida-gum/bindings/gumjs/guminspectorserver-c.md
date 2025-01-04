Response:
Let's break down the thought process for analyzing the `guminspectorserver.c` file and generating the detailed response.

**1. Initial Understanding & Core Functionality:**

* **File Path:**  The path `frida/subprojects/frida-gum/bindings/gumjs/guminspectorserver.c` immediately suggests this component is part of Frida's core (`frida-gum`), specifically related to JavaScript bindings (`gumjs`). The "inspector server" part hints at a debugging or introspection interface.
* **Copyright & Includes:**  The copyright notice and `#include` directives (especially `<libsoup/soup.h>`) strongly indicate a web server component. The inclusion of `<json-glib/json-glib.h>` confirms it deals with JSON data. `<gum/gumprocess.h>` links it to Frida's process interaction capabilities.
* **High-Level Goal:** Based on the name and includes, the primary goal seems to be providing a remote debugging interface (like Chrome DevTools) for Frida's JavaScript environment.

**2. Deconstructing the Code - Function by Function (or Logical Grouping):**

* **Data Structures:**  The `GumInspectorServer` and `GumInspectorPeer` structs define the core data being managed. The server holds the port, ID, title, a `SoupServer`, and a list of connected peers. Each peer represents a websocket connection.
* **Object Lifecycle:** The `G_DEFINE_TYPE` macro and the `_class_init`, `_init`, `_dispose`, and `_finalize` functions are standard GObject patterns for creating and managing objects. This tells us this server is implemented using the GLib object system.
* **Properties:**  The `PROP_PORT` property and associated `get/set_property` functions indicate that the listening port is a configurable parameter.
* **Signal Handling:** The `MESSAGE` signal suggests a way for the server to communicate events to other parts of Frida.
* **Server Setup (`gum_inspector_server_init`):** This is crucial. It shows how the `SoupServer` is created, handlers are added for `/json`, `/json/list`, `/json/version`, and a websocket handler for a dynamically generated path based on the server's ID. This immediately highlights the HTTP and WebSocket aspects.
* **Server Lifecycle (`gum_inspector_server_start`, `gum_inspector_server_stop`):**  Standard functions for starting and stopping the underlying `SoupServer`. The `_start` function shows it listens on a local port.
* **Message Handling (`gum_inspector_server_post_message`):** This function handles messages *sent to* the server *from Frida*. The "DISPATCH" prefix suggests a way for Frida to relay messages to specific connected DevTools clients. This is a key point for understanding how Frida interacts with the debugger.
* **HTTP Endpoints (`gum_inspector_server_on_list`, `gum_inspector_server_on_version`):** These functions handle the HTTP requests.
    * `_on_list`:  Responds with a JSON array containing information about the debuggable target (process name, URLs for DevTools). This is how a DevTools client discovers the target.
    * `_on_version`: Provides version information, including the Frida version and the debugging protocol version.
* **WebSocket Handling (`gum_inspector_server_on_websocket_opened`, `_on_websocket_closed`, `_on_websocket_stanza`):** This is the core communication channel for the debugging protocol.
    * `_on_websocket_opened`: Creates a `GumInspectorPeer` for a new connection and associates it with the server.
    * `_on_websocket_closed`: Cleans up when a connection closes.
    * `_on_websocket_stanza`:  Handles incoming messages from the websocket (from the DevTools client) and emits the `MESSAGE` signal.
* **Utilities:**
    * `gum_inspector_server_check_method`, `_add_json_headers`, `_append_json_body`: Helper functions for handling HTTP requests and responses.
    * `gum_inspector_peer_new`, `_free`, `_post_stanza`, `_on_closed`, `_on_message`: Functions for managing individual websocket connections.
    * `gum_store_process_title`:  A utility to get the process name.

**3. Connecting to Reverse Engineering:**

* **Mental Model:** Think about how a debugger connects to a target process. This server acts as the "middleman," facilitating communication between the debugger UI (Chrome DevTools) and the Frida agent running inside the target process.
* **Key Interactions:** The `/json/list` endpoint is crucial for the debugger to find the target. The websocket is the bidirectional communication channel for sending commands and receiving responses/events.

**4. Identifying Binary/Kernel/Framework Aspects:**

* **Frida Itself:** The very existence of this code within Frida's codebase implies interaction with the target process at a low level. Frida instruments the process, and this server allows external control and observation.
* **Process Information:**  The use of `gum_process_enumerate_modules` and `gum_process_get_id` points to accessing information about the target process.
* **No Direct Kernel Interaction *Here*:**  While Frida *as a whole* interacts with the kernel, this specific file primarily deals with networking and the debugging protocol. The underlying Frida agent (not shown in this file) handles the direct kernel interactions.

**5. Logical Reasoning & Examples:**

* **Input/Output:** Focus on the HTTP endpoints and the websocket. What does the server *expect* to receive, and what does it *send back*? This leads to examples for `/json/list` and `/json/version`.
* **Assumptions:** Think about the pre-requisites. The server needs to be started, and a DevTools client needs to connect.

**6. Common User Errors:**

* **Port Conflicts:**  The most obvious error is trying to run the server on a port already in use.
* **Firewall Issues:** Firewalls could block connections to the server.
* **Incorrect DevTools URL:** Typing the wrong URL into Chrome DevTools will prevent connection.

**7. Tracing User Actions:**

* **Step-by-Step:** Imagine the user starting Frida with the inspector enabled. Then, they would open Chrome and navigate to a specific URL. This step-by-step helps explain how the user's actions lead to the execution of this server's code.

**8. Structuring the Response:**

* **Categorization:**  Organize the findings into clear categories like "Functionality," "Relationship to Reversing," etc. This makes the information easier to digest.
* **Code Snippets:**  Include relevant code snippets to illustrate the points.
* **Clear Examples:**  Provide concrete examples for input/output and user errors.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this file directly handles process instrumentation.
* **Correction:**  Realized the focus is on the *communication* aspect of the debugger, not the instrumentation itself. The underlying Frida agent handles that.
* **Clarification:**  Distinguished between Frida's overall kernel interactions and this specific file's focus on networking.

By following this structured thought process, combining code analysis with conceptual understanding of debugging and network protocols, the detailed and accurate response can be generated.
这个 `guminspectorserver.c` 文件是 Frida 工具中用于实现 Inspector 协议服务器的源代码。Inspector 协议通常用于调试 JavaScript 环境，例如 Node.js 和 Chrome。在 Frida 的上下文中，这个服务器允许外部调试器（如 Chrome DevTools）连接到被 Frida 注入的进程，并检查和调试其 JavaScript 代码。

以下是它的功能列表：

**核心功能:**

1. **启动 HTTP 和 WebSocket 服务器:**  使用 `libsoup` 库创建一个 HTTP 服务器，监听指定的端口（默认为 9229）。同时，它也支持 WebSocket 连接，用于与调试客户端进行双向通信。
2. **提供调试目标列表 (`/json`, `/json/list`):**  当调试器通过 HTTP GET 请求访问 `/json` 或 `/json/list` 时，服务器会返回一个 JSON 数组，其中包含了当前可调试的目标信息。每个目标的信息包括一个唯一的 ID、标题（通常是被注入进程的名称）、描述、以及连接到调试器的 URL。
3. **提供协议版本信息 (`/json/version`):** 当调试器通过 HTTP GET 请求访问 `/json/version` 时，服务器会返回一个 JSON 对象，包含了协议的版本信息，例如 "Browser"（Frida 版本）和 "Protocol-Version"（通常是 "1.1"）。
4. **处理 WebSocket 连接:** 当调试器通过 WebSocket 连接到服务器的指定路径（例如 `/生成的ID`）时，服务器会创建一个 `GumInspectorPeer` 对象来管理这个连接。
5. **转发调试消息:** 通过 WebSocket 连接，调试器可以发送调试命令到 Frida 注入的 JavaScript 环境，而 `GumInspectorServer` 负责接收这些消息并将其转发到 Frida 的核心逻辑。同样，Frida 核心产生的调试事件和响应也会通过这个 WebSocket 连接发送回调试器。
6. **管理连接的客户端:**  服务器维护一个连接的 `GumInspectorPeer` 对象的哈希表，以便跟踪和管理当前的调试会话。
7. **生成唯一 ID:**  为每个 Inspector 服务器实例生成一个唯一的 UUID，用于标识调试目标和生成唯一的 WebSocket 路径。
8. **获取进程标题:**  尝试获取被注入进程的名称作为调试目标的标题。

**与逆向方法的关系及举例说明:**

`guminspectorserver.c` 是 Frida 作为动态 Instrumentation 工具进行逆向分析的关键组成部分。它允许逆向工程师在运行时检查和操纵目标进程的 JavaScript 代码。

* **动态代码分析:** 逆向工程师可以使用 Chrome DevTools 连接到目标进程，查看 JavaScript 代码的执行流程、变量的值、调用栈等信息，而无需事先知道代码的结构。
    * **举例:**  假设你想了解某个 Android 应用中 WebView 加载特定网页时的 JavaScript 行为。你可以使用 Frida 注入应用，启动 Inspector 服务器，然后在 Chrome 中输入 `devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=localhost:9229/你的UUID` 连接到目标进程。之后，你可以在 Sources 面板中设置断点，在 Console 中执行 JavaScript 代码，实时观察应用的 JavaScript 运行状态。
* **运行时修改代码:**  通过 DevTools，逆向工程师可以动态修改 JavaScript 代码，例如修改函数实现、改变变量值，来观察这些修改对应用行为的影响。
    * **举例:**  在一个使用 JavaScript 进行加密的应用中，你可以通过 DevTools 修改加密函数的实现，使其直接返回明文，从而绕过加密逻辑。
* **Hooking 和追踪:**  虽然 `guminspectorserver.c` 本身不直接实现 Hooking 功能，但它提供的调试接口可以方便地与 Frida 的 Hooking 功能结合使用。你可以在 Frida 脚本中设置 Hook，当 Hook 被触发时，通过 Inspector 协议发送事件到 DevTools，方便你观察 Hook 的执行情况和相关数据。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **Frida 的核心功能:**  `guminspectorserver.c` 依赖于 Frida 的核心功能，而 Frida 的核心功能涉及与目标进程的内存交互、代码注入、函数 Hooking 等底层操作，这些都需要深入理解目标平台的 ABI、指令集、内存管理等知识。
* **`libsoup` 库:**  该文件使用了 `libsoup` 库来实现 HTTP 和 WebSocket 服务器。`libsoup` 是一个 GLib 库，它本身会利用底层的网络 socket API，这些 API 在 Linux 和 Android 上有不同的实现。
* **进程间通信 (IPC):**  虽然这里没有直接的 IPC 代码，但 Inspector 服务器作为 Frida 的一部分，涉及到 Frida agent 和目标进程之间的通信，这通常通过共享内存、管道等 IPC 机制实现。
* **Android 框架:**  在 Android 平台上，Frida 经常被用于分析 Android 应用。理解 Android 的 Dalvik/ART 虚拟机、应用框架（如 Activity 生命周期、Service 管理）对于有效地使用 Frida 进行逆向至关重要。Inspector 可以帮助你调试运行在 WebView 中的 JavaScript 代码，这需要你了解 WebView 的工作原理以及它与 Android 应用的交互方式。

**逻辑推理及假设输入与输出:**

假设 Frida 已经成功注入到一个目标进程，并且 `GumInspectorServer` 实例已经创建并启动，监听在端口 9229，其生成的 ID 为 `abcdefg`。

* **假设输入 (HTTP GET 请求):**  用户在浏览器中访问 `http://localhost:9229/json/list`
* **预期输出 (HTTP 响应):**
```json
[
  {
    "description": "Frida Agent",
    "devtoolsFrontendUrl": "devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=localhost:9229/abcdefg",
    "devtoolsFrontendUrlCompat": "devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=localhost:9229/abcdefg",
    "faviconUrl": "https://frida.re/favicon.ico",
    "id": "abcdefg",
    "title": "目标进程名称[进程ID]",
    "type": "node",
    "url": "file://",
    "webSocketDebuggerUrl": "ws://localhost:9229/abcdefg"
  }
]
```

* **假设输入 (WebSocket 连接):**  Chrome DevTools 尝试建立一个 WebSocket 连接到 `ws://localhost:9229/abcdefg`
* **预期输出 (服务器行为):**  `gum_inspector_server_on_websocket_opened` 函数会被调用，创建一个新的 `GumInspectorPeer` 对象，并发出一个 "CONNECT" 信号，例如 "CONNECT 1"（假设这是第一个连接）。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **端口冲突:**  如果用户尝试启动 Inspector 服务器时，指定的端口已经被其他程序占用，`gum_inspector_server_start` 函数会失败并返回错误。
    * **举例:**  如果用户尝试在端口 9229 上启动服务器，但该端口已经被另一个 Frida 实例或者其他服务占用，Frida 会报错，提示端口无法绑定。
2. **防火墙阻止连接:**  如果用户的防火墙阻止了调试器与 Inspector 服务器之间的连接，那么调试器将无法连接到目标进程。
    * **举例:**  用户启动了 Inspector 服务器，但在 Chrome DevTools 中无法连接，可能是因为防火墙阻止了从 Chrome 到 `localhost:9229` 的连接。
3. **错误的 WebSocket URL:**  用户在 Chrome DevTools 中输入的 WebSocket URL 不正确，例如端口号错误或者路径错误，会导致连接失败。
    * **举例:**  如果 Inspector 服务器的 ID 是 `abcdefg`，但用户在 DevTools 中输入的是 `ws://localhost:9229/12345`，连接将无法建立。
4. **Frida 未成功注入:**  如果 Frida 没有成功注入到目标进程，Inspector 服务器可能无法正确获取进程信息或者无法与 JavaScript 环境通信，导致调试功能异常。
    * **举例:**  用户尝试连接到一个没有被 Frida 注入的进程，即使 Inspector 服务器启动了，DevTools 也可能无法显示 JavaScript 上下文或无法执行调试命令。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 并启用 Inspector:**  用户在运行 Frida 脚本时，通常会配置 Frida 启动 Inspector 服务器。这可能通过 Frida 的 API 或命令行选项完成，例如在 Python 脚本中使用 `frida.get_usb_device().attach('目标进程').enable_debugger()` 或在命令行中使用 `--pause` 参数。
2. **Frida 初始化 `GumInspectorServer`:**  当 Frida 需要提供调试功能时，会创建一个 `GumInspectorServer` 的实例。在 `gum_inspector_server_new` 或 `gum_inspector_server_new_with_port` 函数中完成对象的创建和初始化，包括生成 ID、获取进程标题等。
3. **Frida 启动 HTTP/WebSocket 服务器:**  调用 `gum_inspector_server_start` 函数，`libsoup` 库开始监听指定的端口。
4. **用户在浏览器中打开 DevTools:**  用户获取到 Inspector 服务器提供的 URL（通常在 Frida 的输出中可以找到），然后在 Chrome 浏览器中输入该 URL，例如 `devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=localhost:9229/abcdefg`。
5. **DevTools 发送 HTTP 请求:**  浏览器首先会向 Inspector 服务器发送 HTTP GET 请求到 `/json/list` 或 `/json/version` 以获取目标信息和协议版本。`gum_inspector_server_on_list` 和 `gum_inspector_server_on_version` 函数会处理这些请求并返回 JSON 响应。
6. **DevTools 尝试建立 WebSocket 连接:**  根据 `/json/list` 返回的信息，DevTools 会尝试与 `webSocketDebuggerUrl` 建立 WebSocket 连接。`gum_inspector_server_on_websocket_opened` 函数会被调用来处理新的连接。
7. **WebSocket 连接建立，开始通信:**  一旦 WebSocket 连接建立，DevTools 和 Frida 之间就可以通过 WebSocket 发送和接收调试消息。`gum_inspector_peer_on_message` 处理来自 DevTools 的消息，`gum_inspector_server_emit_message` 或 `gum_inspector_peer_post_stanza` 将消息发送回 DevTools。

作为调试线索，如果用户在使用 Frida 的 Inspector 功能时遇到问题，例如无法连接、连接后功能异常等，可以按照这个步骤反向排查：

* **检查 Frida 是否成功启动了 Inspector 服务器，并监听了正确的端口。**
* **确认防火墙是否阻止了连接。**
* **核对在 DevTools 中输入的 URL 是否与 Frida 提供的 URL 完全一致。**
* **检查 Frida 是否成功注入到目标进程。**
* **查看 Frida 的日志输出，是否有任何关于 Inspector 服务器启动或连接的错误信息。**

理解 `guminspectorserver.c` 的功能和工作流程，可以帮助逆向工程师更好地利用 Frida 的调试能力，并有效地排查在使用过程中遇到的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/guminspectorserver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2018-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminspectorserver.h"

#include <gum/gumprocess.h>
#include <json-glib/json-glib.h>
#include <libsoup/soup.h>
#include <string.h>

#define GUM_INSPECTOR_DEFAULT_PORT 9229

typedef struct _GumInspectorPeer GumInspectorPeer;

struct _GumInspectorServer
{
  GObject parent;

  guint port;

  gchar * id;
  gchar * title;
  SoupServer * server;
  GHashTable * peers;
  guint next_peer_id;
};

struct _GumInspectorPeer
{
  guint id;
  SoupWebsocketConnection * connection;

  gulong closed_handler;
  gulong message_handler;

  GumInspectorServer * server;
};

enum
{
  MESSAGE,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_PORT
};

static void gum_inspector_server_dispose (GObject * object);
static void gum_inspector_server_finalize (GObject * object);
static void gum_inspector_server_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_inspector_server_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static void gum_inspector_server_on_list (SoupServer * server,
    SoupServerMessage * msg, const char * path, GHashTable * query,
    gpointer user_data);
static void gum_inspector_server_on_version (SoupServer * server,
    SoupServerMessage * msg, const char * path, GHashTable * query,
    gpointer user_data);
static void gum_inspector_server_on_websocket_opened (SoupServer * server,
    SoupServerMessage * msg, const char * path,
    SoupWebsocketConnection * connection, gpointer user_data);
static void gum_inspector_server_emit_message (GumInspectorServer * self,
    const gchar * format, ...);

static gboolean gum_inspector_server_check_method (SoupServerMessage * msg,
    const gchar * expected_method);
static void gum_inspector_server_add_json_headers (
    SoupMessageHeaders * headers);
static void gum_inspector_server_append_json_body (SoupMessageBody * body,
    JsonBuilder * builder);

static GumInspectorPeer * gum_inspector_peer_new (GumInspectorServer * server,
    SoupWebsocketConnection * connection);
static void gum_inspector_peer_free (GumInspectorPeer * peer);
static void gum_inspector_peer_post_stanza (GumInspectorPeer * self,
    const gchar * stanza);
static void gum_inspector_peer_on_closed (GumInspectorPeer * self);
static void gum_inspector_peer_on_message (GumInspectorPeer * self, gint type,
    GBytes * message);

static gboolean gum_store_process_title (const GumModuleDetails * details,
    gpointer user_data);

G_DEFINE_TYPE (GumInspectorServer, gum_inspector_server, G_TYPE_OBJECT)

static guint gum_inspector_server_signals[LAST_SIGNAL] = { 0, };

static void
gum_inspector_server_class_init (GumInspectorServerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_inspector_server_dispose;
  object_class->finalize = gum_inspector_server_finalize;
  object_class->get_property = gum_inspector_server_get_property;
  object_class->set_property = gum_inspector_server_set_property;

  g_object_class_install_property (object_class, PROP_PORT,
      g_param_spec_uint ("port", "Port", "Port to listen on", 1, G_MAXUINT16,
      GUM_INSPECTOR_DEFAULT_PORT,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  gum_inspector_server_signals[MESSAGE] = g_signal_new ("message",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__STRING, G_TYPE_NONE, 1, G_TYPE_STRING);
}

static void
gum_inspector_server_init (GumInspectorServer * self)
{
  SoupServer * server;
  gchar * ws_path;

  self->id = g_uuid_string_random ();
  gum_process_enumerate_modules (gum_store_process_title, &self->title);

  server = g_object_new (SOUP_TYPE_SERVER, NULL);

  soup_server_add_handler (server, "/json",
      gum_inspector_server_on_list, self, NULL);
  soup_server_add_handler (server, "/json/list",
      gum_inspector_server_on_list, self, NULL);
  soup_server_add_handler (server, "/json/version",
      gum_inspector_server_on_version, self, NULL);

  ws_path = g_strconcat ("/", self->id, NULL);
  soup_server_add_websocket_handler (server, ws_path, NULL, NULL,
      gum_inspector_server_on_websocket_opened, self, NULL);
  g_free (ws_path);

  self->server = server;

  self->peers = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_inspector_peer_free);
  self->next_peer_id = 1;
}

static void
gum_inspector_server_dispose (GObject * object)
{
  GumInspectorServer * self = GUM_INSPECTOR_SERVER (object);

  g_clear_pointer (&self->peers, g_hash_table_unref);

  if (self->server != NULL)
    soup_server_disconnect (self->server);

  g_clear_object (&self->server);

  G_OBJECT_CLASS (gum_inspector_server_parent_class)->dispose (object);
}

static void
gum_inspector_server_finalize (GObject * object)
{
  GumInspectorServer * self = GUM_INSPECTOR_SERVER (object);

  g_free (self->id);
  g_free (self->title);

  G_OBJECT_CLASS (gum_inspector_server_parent_class)->finalize (object);
}

static void
gum_inspector_server_get_property (GObject * object,
                                   guint property_id,
                                   GValue * value,
                                   GParamSpec * pspec)
{
  GumInspectorServer * self = GUM_INSPECTOR_SERVER (object);

  switch (property_id)
  {
    case PROP_PORT:
      g_value_set_uint (value, self->port);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_inspector_server_set_property (GObject * object,
                                   guint property_id,
                                   const GValue * value,
                                   GParamSpec * pspec)
{
  GumInspectorServer * self = GUM_INSPECTOR_SERVER (object);

  switch (property_id)
  {
    case PROP_PORT:
      self->port = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumInspectorServer *
gum_inspector_server_new (void)
{
  return g_object_new (GUM_TYPE_INSPECTOR_SERVER, NULL);
}

GumInspectorServer *
gum_inspector_server_new_with_port (guint port)
{
  return g_object_new (GUM_TYPE_INSPECTOR_SERVER,
      "port", port,
      NULL);
}

gboolean
gum_inspector_server_start (GumInspectorServer * self,
                            GError ** error)
{
  GError * listen_error = NULL;

  if (!soup_server_listen_local (self->server, self->port, 0, &listen_error))
    goto listen_failed;

  return TRUE;

listen_failed:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "%s",
        listen_error->message);

    g_error_free (listen_error);

    return FALSE;
  }
}

void
gum_inspector_server_stop (GumInspectorServer * self)
{
  soup_server_disconnect (self->server);
}

void
gum_inspector_server_post_message (GumInspectorServer * self,
                                   const gchar * message)
{
  const gchar * id_start, * id_end;
  guint id;
  GumInspectorPeer * peer;

  id_start = strchr (message, ' ');
  if (id_start == NULL)
    return;
  id_start++;

  id = (guint) g_ascii_strtoull (id_start, (gchar **) &id_end, 10);
  if (id_end == id_start)
    return;

  peer = g_hash_table_lookup (self->peers, GUINT_TO_POINTER (id));
  if (peer == NULL)
    return;

  if (g_str_has_prefix (message, "DISPATCH "))
  {
    const gchar * stanza;

    if (*id_end != ' ')
      return;
    stanza = id_end + 1;

    gum_inspector_peer_post_stanza (peer, stanza);
  }
}

static void
gum_inspector_server_on_list (SoupServer * server,
                              SoupServerMessage * msg,
                              const char * path,
                              GHashTable * query,
                              gpointer user_data)
{
  GumInspectorServer * self = user_data;
  JsonBuilder * builder;
  gchar * host_port;
  GSList * uris, * cur;
  gchar * url;

  if (!gum_inspector_server_check_method (msg, "GET"))
    return;

  soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

  gum_inspector_server_add_json_headers (
      soup_server_message_get_response_headers (msg));

  builder = json_builder_new ();

  json_builder_begin_array (builder);

  json_builder_begin_object (builder);

  json_builder_set_member_name (builder, "id");
  json_builder_add_string_value (builder, self->id);

  json_builder_set_member_name (builder, "title");
  json_builder_add_string_value (builder, self->title);

  json_builder_set_member_name (builder, "description");
  json_builder_add_string_value (builder, "Frida Agent");

  json_builder_set_member_name (builder, "url");
  json_builder_add_string_value (builder, "file://");

  json_builder_set_member_name (builder, "faviconUrl");
  json_builder_add_string_value (builder, "https://frida.re/favicon.ico");

  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, "node");

  host_port = NULL;
  uris = soup_server_get_uris (self->server);
  for (cur = uris; cur != NULL; cur = cur->next)
  {
    GUri * uri = cur->data;

    host_port = g_strdup_printf ("%s:%d",
        g_uri_get_host (uri),
        g_uri_get_port (uri));
    break;
  }
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  json_builder_set_member_name (builder, "devtoolsFrontendUrl");
  url = g_strdup_printf ("devtools://devtools/bundled/js_app.html"
      "?experiments=true&v8only=true&ws=%s/%s", host_port, self->id);
  json_builder_add_string_value (builder, url);
  g_free (url);

  json_builder_set_member_name (builder, "devtoolsFrontendUrlCompat");
  url = g_strdup_printf ("devtools://devtools/bundled/inspector.html"
      "?experiments=true&v8only=true&ws=%s/%s", host_port, self->id);
  json_builder_add_string_value (builder, url);
  g_free (url);

  json_builder_set_member_name (builder, "webSocketDebuggerUrl");
  url = g_strdup_printf ("ws://%s/%s", host_port, self->id);
  json_builder_add_string_value (builder, url);
  g_free (url);

  g_free (host_port);

  json_builder_end_object (builder);

  json_builder_end_array (builder);

  gum_inspector_server_append_json_body (
      soup_server_message_get_response_body (msg), builder);
}

static void
gum_inspector_server_on_version (SoupServer * server,
                                 SoupServerMessage * msg,
                                 const char * path,
                                 GHashTable * query,
                                 gpointer user_data)
{
  JsonBuilder * builder;

  if (!gum_inspector_server_check_method (msg, "GET"))
    return;

  soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

  gum_inspector_server_add_json_headers (
      soup_server_message_get_response_headers (msg));

  builder = json_builder_new ();

  json_builder_begin_object (builder);

  json_builder_set_member_name (builder, "Browser");
  json_builder_add_string_value (builder, "Frida/v" FRIDA_VERSION);

  json_builder_set_member_name (builder, "Protocol-Version");
  json_builder_add_string_value (builder, "1.1");

  json_builder_end_object (builder);

  gum_inspector_server_append_json_body (
      soup_server_message_get_response_body (msg), builder);
}

static void
gum_inspector_server_on_websocket_opened (SoupServer * server,
                                          SoupServerMessage * msg,
                                          const char * path,
                                          SoupWebsocketConnection * connection,
                                          gpointer user_data)
{
  GumInspectorServer * self = user_data;
  GumInspectorPeer * peer;

  peer = gum_inspector_peer_new (self, connection);
  g_hash_table_insert (self->peers, GUINT_TO_POINTER (peer->id), peer);

  gum_inspector_server_emit_message (self, "CONNECT %u", peer->id);
}

static void
gum_inspector_server_on_websocket_closed (GumInspectorServer * self,
                                          GumInspectorPeer * peer)
{
  gum_inspector_server_emit_message (self, "DISCONNECT %u", peer->id);

  g_hash_table_remove (self->peers, GUINT_TO_POINTER (peer->id));
}

static void
gum_inspector_server_on_websocket_stanza (GumInspectorServer * self,
                                          GumInspectorPeer * peer,
                                          const gchar * stanza)
{
  gum_inspector_server_emit_message (self, "DISPATCH %u %s", peer->id, stanza);
}

static void
gum_inspector_server_emit_message (GumInspectorServer * self,
                                   const gchar * format,
                                   ...)
{
  va_list args;
  gchar * message;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  g_signal_emit (self, gum_inspector_server_signals[MESSAGE], 0, message);

  g_free (message);
}

static gboolean
gum_inspector_server_check_method (SoupServerMessage * msg,
                                   const gchar * expected_method)
{
  if (strcmp (soup_server_message_get_method (msg), expected_method) != 0)
  {
    soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
    return FALSE;
  }

  return TRUE;
}

static void
gum_inspector_server_add_json_headers (SoupMessageHeaders * headers)
{
  GHashTable * content_params;

  content_params = g_hash_table_new (g_str_hash, g_str_equal);
  g_hash_table_insert (content_params, "charset", "UTF-8");
  soup_message_headers_set_content_type (headers,
      "application/json", content_params);
  g_hash_table_unref (content_params);

  soup_message_headers_replace (headers, "Cache-Control", "no-cache");
}

static void
gum_inspector_server_append_json_body (SoupMessageBody * body,
                                       JsonBuilder * builder)
{
  JsonNode * root;
  gchar * json;

  root = json_builder_get_root (builder);
  json = json_to_string (root, FALSE);
  soup_message_body_append_take (body, (guchar *) json, strlen (json));
  json_node_unref (root);

  g_object_unref (builder);
}

static GumInspectorPeer *
gum_inspector_peer_new (GumInspectorServer * server,
                        SoupWebsocketConnection * connection)
{
  GumInspectorPeer * peer;

  peer = g_slice_new (GumInspectorPeer);
  peer->id = server->next_peer_id++;
  peer->connection = g_object_ref (connection);

  peer->closed_handler = g_signal_connect_swapped (connection, "closed",
      G_CALLBACK (gum_inspector_peer_on_closed), peer);
  peer->message_handler = g_signal_connect_swapped (connection, "message",
      G_CALLBACK (gum_inspector_peer_on_message), peer);

  peer->server = server;

  return peer;
}

static void
gum_inspector_peer_free (GumInspectorPeer * peer)
{
  SoupWebsocketConnection * connection = peer->connection;

  g_signal_handler_disconnect (connection, peer->closed_handler);
  g_signal_handler_disconnect (connection, peer->message_handler);
  g_object_unref (connection);

  g_slice_free (GumInspectorPeer, peer);
}

static void
gum_inspector_peer_post_stanza (GumInspectorPeer * self,
                                const gchar * stanza)
{
  soup_websocket_connection_send_text (self->connection, stanza);
}

static void
gum_inspector_peer_on_closed (GumInspectorPeer * self)
{
  gum_inspector_server_on_websocket_closed (self->server, self);
}

static void
gum_inspector_peer_on_message (GumInspectorPeer * self,
                               gint type,
                               GBytes * message)
{
  if (type == SOUP_WEBSOCKET_DATA_TEXT)
  {
    gum_inspector_server_on_websocket_stanza (self->server, self,
        g_bytes_get_data (message, NULL));
  }
}

static gboolean
gum_store_process_title (const GumModuleDetails * details,
                         gpointer user_data)
{
  gchar ** title = user_data;

  *title = g_strdup_printf ("%s[%u]", details->name, gum_process_get_id ());

  return FALSE;
}

"""

```