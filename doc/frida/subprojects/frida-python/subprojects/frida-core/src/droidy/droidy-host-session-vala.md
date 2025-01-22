Response:
### 功能归纳

`droidy-host-session.vala` 是 Frida 工具中用于与 Android 设备进行交互的核心模块之一。它主要负责管理与 Android 设备的连接、会话管理、进程注入、调试等功能。以下是该文件的主要功能归纳：

1. **设备管理**：
   - 通过 `DroidyHostSessionBackend` 类，管理 Android 设备的连接与断开。
   - 使用 `Droidy.DeviceTracker` 跟踪设备的连接状态，并在设备连接或断开时触发相应的事件。

2. **会话管理**：
   - `DroidyHostSessionProvider` 类负责提供与 Android 设备的会话连接。
   - 支持通过 USB 或 TCP 与设备建立连接，并提供会话的创建、销毁、链接等功能。

3. **进程管理**：
   - 支持枚举当前运行的应用程序和进程。
   - 提供获取前台应用程序信息的功能。
   - 支持通过 `spawn` 方法启动新的进程，并通过 `attach` 方法附加到现有进程。

4. **注入与调试**：
   - 支持将 Frida Gadget（一个动态库）注入到目标进程中，以便进行动态调试。
   - 提供 `inject_library_file` 和 `inject_library_blob` 方法，用于将库文件或二进制数据注入到目标进程中。

5. **远程服务器管理**：
   - 通过 `RemoteServer` 类管理与远程 Frida 服务器的连接。
   - 支持通过 TCP 连接到远程服务器，并进行会话管理、进程注入等操作。

6. **事件处理**：
   - 处理设备连接、断开、进程启动、进程崩溃等事件。
   - 通过回调函数处理远程服务器的连接状态变化、进程输出、会话断开等事件。

7. **调试功能**：
   - 提供对目标进程的调试功能，包括暂停、恢复、终止进程等操作。
   - 支持通过 `input` 方法向目标进程发送输入数据。

### 二进制底层与 Linux 内核相关

- **进程注入**：Frida 通过注入 `frida-gadget.so` 到目标进程中，实现对目标进程的动态调试。注入过程涉及到 Linux 的 `ptrace` 系统调用，用于控制目标进程的执行流。
- **进程管理**：通过 Android 的 `getprop` 命令获取系统属性，如 Android 版本、CPU 架构等。这些信息用于确定目标进程的运行环境。
- **调试功能**：Frida 通过 JDWP（Java Debug Wire Protocol）与 Android 设备上的 Java 进程进行通信，实现对 Java 进程的调试。

### LLDB 调试示例

假设我们想要调试 `DroidyHostSession` 类的 `attach` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 设置断点在 DroidyHostSession.attach 方法
b Frida::DroidyHostSession::attach

# 继续执行程序
c

# 当断点命中时，打印相关变量
p pid
p options
```

#### LLDB Python 脚本示例

```python
import lldb

def attach_to_process(pid):
    # 创建调试器实例
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    
    # 附加到目标进程
    target = debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)
    
    # 设置断点
    breakpoint = target.BreakpointCreateByName("Frida::DroidyHostSession::attach", target.GetExecutable().GetFilename())
    
    # 继续执行
    process.Continue()
    
    # 当断点命中时，打印相关信息
    for thread in process:
        if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
            frame = thread.GetFrameAtIndex(0)
            pid_value = frame.FindVariable("pid")
            options_value = frame.FindVariable("options")
            print(f"PID: {pid_value.GetValue()}, Options: {options_value.GetValue()}")

# 使用示例
attach_to_process(1234)
```

### 假设输入与输出

假设我们调用 `attach` 方法附加到进程 `1234`，并传递一些选项：

- **输入**：
  - `pid = 1234`
  - `options = {"debug": True, "timeout": 5000}`

- **输出**：
  - 返回一个 `AgentSessionId`，表示成功附加到目标进程。

### 常见使用错误

1. **设备未连接**：
   - 错误示例：尝试附加到设备时，设备未连接或 USB 调试未开启。
   - 解决方法：确保设备已连接并开启 USB 调试模式。

2. **权限不足**：
   - 错误示例：尝试注入进程时，权限不足导致失败。
   - 解决方法：确保 Frida 以 root 权限运行，或目标进程允许调试。

3. **目标进程不存在**：
   - 错误示例：尝试附加到不存在的进程 ID。
   - 解决方法：确保目标进程正在运行，并且进程 ID 正确。

### 用户操作路径

1. **启动 Frida**：用户启动 Frida 并连接到 Android 设备。
2. **枚举进程**：用户通过 Frida 枚举当前运行的进程。
3. **选择目标进程**：用户选择目标进程并调用 `attach` 方法。
4. **注入调试**：Frida 注入 `frida-gadget.so` 并附加到目标进程。
5. **调试操作**：用户通过 Frida 进行调试操作，如读取内存、调用函数等。

### 调试线索

1. **设备连接**：用户通过 USB 或 TCP 连接到 Android 设备。
2. **会话创建**：Frida 创建会话并与设备进行通信。
3. **进程注入**：Frida 注入 `frida-gadget.so` 到目标进程。
4. **调试操作**：用户通过 Frida 进行调试操作，Frida 处理相关事件并返回结果。

这是第 1 部分的归纳，后续部分将继续深入分析其他功能模块。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/droidy/droidy-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共5部分，请归纳一下它的功能

"""
namespace Frida {
	public class DroidyHostSessionBackend : Object, HostSessionBackend {
		private Droidy.DeviceTracker tracker;

		private Gee.HashMap<string, DroidyHostSessionProvider> providers = new Gee.HashMap<string, DroidyHostSessionProvider> ();

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

		public async void start (Cancellable? cancellable) throws IOError {
			start_request = new Promise<bool> ();
			start_cancellable = new Cancellable ();
			on_start_completed = start.callback;

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (500);
			timeout_source.set_callback (start.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (start.callback);
			cancel_source.attach (main_context);

			do_start.begin ();

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			on_start_completed = null;
		}

		private async void do_start () {
			bool success = true;

			tracker = new Droidy.DeviceTracker ();
			tracker.device_attached.connect (details => {
				var provider = new DroidyHostSessionProvider (details);
				providers[details.serial] = provider;
				provider_available (provider);
			});
			tracker.device_detached.connect (serial => {
				DroidyHostSessionProvider provider;
				providers.unset (serial, out provider);
				provider_unavailable (provider);
				provider.close.begin (io_cancellable);
			});

			try {
				yield tracker.open (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (tracker != null) {
				yield tracker.close (cancellable);
				tracker = null;
			}

			io_cancellable.cancel ();

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}
	}

	public class DroidyHostSessionProvider : Object, HostSessionProvider, HostChannelProvider {
		public string id {
			get { return device_details.serial; }
		}

		public string name {
			get { return device_details.name; }
		}

		public Variant? icon {
			get { return _icon; }
		}
		private Variant _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public Droidy.DeviceDetails device_details {
			get;
			construct;
		}

		private DroidyHostSession? host_session;

		private const double MAX_CLIENT_AGE = 30.0;

		public DroidyHostSessionProvider (Droidy.DeviceDetails details) {
			Object (device_details: details);
		}

		construct {
			var builder = new VariantBuilder (VariantType.VARDICT);
			builder.add ("{sv}", "format", new Variant.string ("rgba"));
			builder.add ("{sv}", "width", new Variant.int64 (16));
			builder.add ("{sv}", "height", new Variant.int64 (16));
			var image = new Bytes (Base64.decode ("AAAAAAAAAAAAAAAAAAAAAP///0DS4pz/////MP///0D///9A////MNflqP////9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///8QzN6Q/7vTa/+vy1L/r8tS/7vTa//O4JXv////EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1eSkz6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/9XkpM8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8vfjcKrIRf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+qyEX/8PXeYAAAAAAAAAAAAAAAAAAAAAAAAAAA////QNLinL+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/97qt6////9AAAAAAAAAAAAAAAAA2eatv7vTa//G2oP/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/M3pD/u9Nr/9nmrb8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADS4pz/pMQ5/7vTa/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/7vTa/+kxDn/0uKc/wAAAAAAAAAA0uKc/6TEOf+702v/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+702v/pMQ5/9LinP8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADO4JXvpMQ5/8DWd/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/8DWd/+kxDn/zuCV7wAAAAAAAAAA7fPXUNLinIDl7sbfpMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/l7sbf0uKcgO3z11AAAAAAAAAAAAAAAAAAAAAA8PXeYMDWd/+qyEX/pMQ5/6/LUv+vy1L/pMQ5/6rIRf/A1nf/7fPXUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu9Nr/6TEOf/C2Hu/wth7v6TEOf+702v/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALvTa/+kxDn/wth7v8LYe7+kxDn/u9Nr/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADc6LPPu9Nr/+HrvY/h672Pu9Nr/9nmrb8AAAAAAAAAAAAAAAAAAAAAAAAAAA=="));
			builder.add ("{sv}", "image", Variant.new_from_data (new VariantType ("ay"), image.get_data (), true, image));
			_icon = builder.end ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Already created");

			host_session = new DroidyHostSession (device_details, this);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			if (address.contains (":")) {
				Droidy.Client client = null;
				try {
					client = yield Droidy.Client.open (cancellable);
					yield client.request ("host:transport:" + device_details.serial, cancellable);
					yield client.request_protocol_change (address, cancellable);
					return client.stream;
				} catch (GLib.Error e) {
					if (client != null)
						client.close.begin ();

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}
	}

	public class DroidyHostSession : Object, HostSession {
		public Droidy.DeviceDetails device_details {
			get;
			construct;
		}

		public weak HostChannelProvider channel_provider {
			get;
			construct;
		}

		private Promise<HelperClient>? helper_client_request;
		private Droidy.ShellSession? helper_shell;

		private Gee.HashMap<uint, Droidy.Injector.GadgetDetails> gadgets =
			new Gee.HashMap<uint, Droidy.Injector.GadgetDetails> ();
		private Gee.HashMap<AgentSessionId?, GadgetEntry> gadget_entries =
			new Gee.HashMap<AgentSessionId?, GadgetEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Promise<RemoteServer>? remote_server_request;
		private RemoteServer? current_remote_server;
		private Timer? last_server_check_timer;
		private Error? last_server_check_error;
		private Gee.HashMap<AgentSessionId?, AgentSessionId?> remote_agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.HashMap<AgentSessionId?, AgentSessionEntry> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Cancellable io_cancellable = new Cancellable ();

		private const double MIN_SERVER_CHECK_INTERVAL = 5.0;
		private const string GADGET_APP_ID = "re.frida.Gadget";

		public DroidyHostSession (Droidy.DeviceDetails device_details, HostChannelProvider channel_provider) {
			Object (
				device_details: device_details,
				channel_provider: channel_provider
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (remote_server_request != null) {
				var server = yield try_get_remote_server (cancellable);
				if (server != null) {
					try {
						yield server.connection.close (cancellable);
					} catch (GLib.Error e) {
					}
				}
			}

			while (!gadget_entries.is_empty) {
				var iterator = gadget_entries.values.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				yield entry.close (cancellable);
			}

			if (helper_client_request != null) {
				HelperClient? helper = yield try_get_helper_client (cancellable);
				if (helper != null) {
					on_helper_client_closed (helper);
					yield helper.close (cancellable);
				}
			}

			if (helper_shell != null) {
				yield helper_shell.close (cancellable);
				helper_shell = null;
			}

			io_cancellable.cancel ();
		}

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.query_system_parameters (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var parameters = new HashTable<string, Variant> (str_hash, str_equal);

			var os = new HashTable<string, Variant> (str_hash, str_equal);
			os["id"] = "android";
			os["name"] = "Android";

			string properties = yield Droidy.ShellCommand.run ("getprop", device_details.serial, cancellable);
			var property_pattern = /\[(.+?)\]: \[(.*?)\]/s;
			try {
				MatchInfo info;
				for (property_pattern.match (properties, 0, out info); info.matches (); info.next ()) {
					string key = info.fetch (1);
					string val = info.fetch (2);
					switch (key) {
						case "ro.build.version.release":
							os["version"] = val;
							break;
						case "ro.build.version.sdk":
							parameters["api-level"] = int64.parse (val);
							break;
						case "ro.product.cpu.abi":
							parameters["arch"] = infer_arch_from_abi (val);
							break;
						default:
							break;
					}
				}
			} catch (RegexError e) {
			}

			parameters["os"] = os;

			parameters["platform"] = "linux";

			parameters["access"] = "jailed";

			return parameters;
		}

		private static string infer_arch_from_abi (string abi) throws Error {
			switch (abi) {
				case "x86":
					return "ia32";
				case "x86_64":
					return "x64";
				case "armeabi":
				case "armeabi-v7a":
					return "arm";
				case "arm64-v8a":
					return "arm64";
				case "mips":
				case "mips64":
					return "mips";
				default:
					throw new Error.NOT_SUPPORTED ("Unsupported ABI: “%s”; please file a bug", abi);
			}
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.get_frontmost_application (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var helper = yield try_get_helper_client (cancellable);
			if (helper == null) {
				if (server == null)
					server = yield get_remote_server (cancellable);
				try {
					return yield server.session.get_frontmost_application (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = FrontmostQueryOptions._deserialize (options);

			var request = new Json.Builder ();
			request
				.begin_array ()
				.add_string_value ("get-frontmost-application")
				.add_string_value (opts.scope.to_nick ())
				.end_array ();

			Json.Node response = yield helper.request (request.get_root (), cancellable);

			if (response.is_null ())
				return HostApplicationInfo.empty ();

			Json.Reader reader = new Json.Reader (response);

			string? identifier = null;
			string? name = null;
			uint pid = 0;
			HashTable<string, Variant> parameters = make_parameters_dict ();

			if (reader.read_element (0)) {
				identifier = reader.get_string_value ();
				reader.end_element ();
			}

			if (reader.read_element (1)) {
				name = reader.get_string_value ();
				reader.end_element ();
			}

			if (reader.read_element (2)) {
				pid = (uint) reader.get_int_value ();
				reader.end_element ();
			}

			if (reader.read_element (3)) {
				if (reader.is_object ())
					add_parameters_from_json (parameters, reader);
				reader.end_element ();
			}

			GLib.Error? error = reader.get_error ();
			if (error != null)
				throw new Error.PROTOCOL ("%s", error.message);

			return HostApplicationInfo (identifier, name, pid, (owned) parameters);
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_applications (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var helper = yield try_get_helper_client (cancellable);
			if (helper == null) {
				if (server == null)
					server = yield get_remote_server (cancellable);
				try {
					return yield server.session.enumerate_applications (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ApplicationQueryOptions._deserialize (options);

			var request = new Json.Builder ();
			request
				.begin_array ()
				.add_string_value ("enumerate-applications");

			request.begin_array ();
			opts.enumerate_selected_identifiers (identifier => request.add_string_value (identifier));
			request.end_array ();

			request
				.add_string_value (opts.scope.to_nick ())
				.end_array ();

			Json.Node response = yield helper.request (request.get_root (), cancellable);

			Json.Reader reader = new Json.Reader (response);

			int num_apps = reader.count_elements ();
			if (num_apps == -1)
				throw new Error.PROTOCOL ("Invalid response from helper service");

			var result = new HostApplicationInfo[0];

			for (int i = 0; i != num_apps; i++) {
				reader.read_element (i);

				string? identifier = null;
				string? name = null;
				uint pid = 0;
				HashTable<string, Variant> parameters = make_parameters_dict ();

				if (reader.read_element (0)) {
					identifier = reader.get_string_value ();
					reader.end_element ();
				}

				if (reader.read_element (1)) {
					name = reader.get_string_value ();
					reader.end_element ();
				}

				if (reader.read_element (2)) {
					pid = (uint) reader.get_int_value ();
					reader.end_element ();
				}

				if (reader.read_element (3)) {
					if (reader.is_object ())
						add_parameters_from_json (parameters, reader);
					reader.end_element ();
				}

				GLib.Error? error = reader.get_error ();
				if (error != null)
					throw new Error.PROTOCOL ("%s", error.message);

				result += HostApplicationInfo (identifier, name, pid, (owned) parameters);

				reader.end_element ();
			}

			if (server != null && server.flavor == GADGET) {
				bool gadget_is_selected = true;
				if (opts.has_selected_identifiers ()) {
					gadget_is_selected = false;
					opts.enumerate_selected_identifiers (identifier => {
						if (identifier == "re.frida.Gadget")
							gadget_is_selected = true;
					});
				}

				if (gadget_is_selected) {
					try {
						foreach (var app in yield server.session.enumerate_applications (options, cancellable))
							result += app;
					} catch (GLib.Error e) {
					}
				}
			}

			return result;
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_processes (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var helper = yield try_get_helper_client (cancellable);
			if (helper == null) {
				if (server == null)
					server = yield get_remote_server (cancellable);
				try {
					return yield server.session.enumerate_processes (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ProcessQueryOptions._deserialize (options);

			var request = new Json.Builder ();
			request
				.begin_array ()
				.add_string_value ("enumerate-processes");

			request.begin_array ();
			opts.enumerate_selected_pids (pid => request.add_int_value (pid));
			request.end_array ();

			request
				.add_string_value (opts.scope.to_nick ())
				.end_array ();

			Json.Node response = yield helper.request (request.get_root (), cancellable);

			Json.Reader reader = new Json.Reader (response);

			int num_processes = reader.count_elements ();
			if (num_processes == -1)
				throw new Error.PROTOCOL ("Invalid response from helper service");

			var result = new HostProcessInfo[0];

			for (int i = 0; i != num_processes; i++) {
				reader.read_element (i);

				uint pid = 0;
				string? name = null;
				HashTable<string, Variant> parameters = make_parameters_dict ();

				if (reader.read_element (0)) {
					pid = (uint) reader.get_int_value ();
					reader.end_element ();
				}

				if (reader.read_element (1)) {
					name = reader.get_string_value ();
					reader.end_element ();
				}

				if (reader.read_element (2)) {
					if (reader.is_object ())
						add_parameters_from_json (parameters, reader);
					reader.end_element ();
				}

				GLib.Error? error = reader.get_error ();
				if (error != null)
					throw new Error.PROTOCOL ("%s", error.message);

				result += HostProcessInfo (pid, name, (owned) parameters);

				reader.end_element ();
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var process in yield server.session.enumerate_processes (options, cancellable)) {
						bool gadget_is_selected = true;
						if (opts.has_selected_pids ()) {
							gadget_is_selected = false;
							uint gadget_pid = process.pid;
							opts.enumerate_selected_pids (pid => {
								if (pid == gadget_pid)
									gadget_is_selected = true;
							});
						}

						if (gadget_is_selected)
							result += process;
					}
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && (server.flavor != GADGET || program == GADGET_APP_ID)) {
				try {
					return yield server.session.spawn (program, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			if (program[0] == '/')
				throw new Error.NOT_SUPPORTED ("Only able to spawn apps");

			unowned string package = program;

			HashTable<string, Variant> aux = options.aux;

			string? user_gadget_path = null;
			Variant? user_gadget_value = aux["gadget"];
			if (user_gadget_value != null) {
				if (!user_gadget_value.is_of_type (VariantType.STRING)) {
					throw new Error.INVALID_ARGUMENT ("The 'gadget' option must be a string pointing at the " +
						"frida-gadget.so to use");
				}
				user_gadget_path = user_gadget_value.get_string ();
			}

			string gadget_path;
			if (user_gadget_path != null) {
				gadget_path = user_gadget_path;
			} else {
				gadget_path = Path.build_filename (Environment.get_user_cache_dir (), "frida", "gadget-android-arm64.so");
			}

			InputStream gadget;
			try {
				var gadget_file = File.new_for_path (gadget_path);
				gadget = yield gadget_file.read_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.NOT_FOUND && user_gadget_path == null) {
					throw new Error.NOT_SUPPORTED (
						"Need Gadget to attach on jailed Android; its default location is: %s", gadget_path);
				} else {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			var details = yield Droidy.Injector.inject (gadget, package, device_details.serial, cancellable);
			gadgets[details.pid] = details;

			return details.pid;
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var gadget = gadgets[pid];
			if (gadget != null) {
				yield gadget.jdwp.resume (cancellable);
				return;
			}

			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.kill (pid, cancellable);
				return;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var gadget = gadgets[pid];
			if (gadget != null)
				return yield attach_via_gadget (pid, options, gadget, cancellable);

			var server = yield get_remote_server (cancellable);
			try {
				return yield attach_via_remote (pid, options, server, cancellable);
			} catch (Error e) {
				throw_dbus_error (e);
			}
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		private async AgentSessionId attach_via_gadget (uint pid, HashTable<string, Variant> options,
				Droidy.Injector.GadgetDetails gadget, Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield channel_provider.open_channel ("localabstract:" + gadget.unix_socket_path, cancellable);

				WebServiceTransport transport = PLAIN;
				string? origin = null;

				stream = yield negotiate_connection (stream, transport, "lolcathost", origin, cancellable);

				var connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION,
					DO_NOT_LOAD_PROPERTIES, cancellable);

				AgentSessionId remote_session_id;
				try {
					remote_session_id = yield host_session.attach (pid, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var local_session_id = AgentSessionId.generate ();
				var gadget_entry = new GadgetEntry (local_session_id, host_session, connection);
				gadget_entry.detached.connect (on_gadget_entry_detached);
				gadget_entries[local_session_id] = gadget_entry;
				agent_sessions[local_session_id] = new AgentSessionEntry (remote_session_id, connection);

				return local_session_id;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async AgentSessionId attach_via_remote (uint pid, HashTable<string, Variant> options, RemoteServer server,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId remote_session_id;
			try {
				remote_session_id = yield server.session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
			var local_session_id = AgentSessionId.generate ();

			var entry = new AgentSessionEntry (remote_session_id, server.connection);

			remote_agent_sessions[remote_session_id] = local_session_id;
			agent_sessions[local_session_id] = entry;

			var transport_broker = server.transport_broker;
			if (transport_broker != null) {
				try {
					entry.connection = yield establish_direct_connection (transport_broker, remote_session_id,
						channel_provider, cancellable);
				} catch (Error e) {
					if (e is Error.NOT_SUPPORTED)
						server.transport_broker = null;
				}
			}

			return local_session_id;
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry entry = agent_sessions[id];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");

			DBusConnection connection = entry.connection;
			AgentSessionId remote_id = entry.remote_session_id;

			AgentSession session = yield connection.get_proxy (null, ObjectPath.for_agent_session (remote_id),
				DO_NOT_LOAD_PROPERTIES, cancellable);

			entry.sink_registration_id = connection.register_object (ObjectPath.for_agent_message_sink (remote_id), sink);

			return session;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_file (pid, path, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void on_gadget_entry_detached (GadgetEntry entry, SessionDetachReason reason) {
			AgentSessionId id = entry.local_session_id;
			var no_crash = CrashInfo.empty ();

			gadget_entries.unset (id);
			agent_sessions.unset (id);

			entry.detached.disconnect (on_gadget_entry_detached);

			agent_session_detached (id, reason, no_crash);

			entry.close.begin (io_cancellable);
		}

		private async RemoteServer? try_get_remote_server (Cancellable? cancellable) throws IOError {
			try {
				return yield get_remote_server (cancellable);
			} catch (Error e) {
				return null;
			}
		}

		private async RemoteServer get_remote_server (Cancellable? cancellable) throws Error, IOError {
			if (current_remote_server != null)
				return current_remote_server;

			while (remote_server_request != null) {
				try {
					return yield remote_server_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			if (last_server_check_timer != null && last_server_check_timer.elapsed () < MIN_SERVER_CHECK_INTERVAL)
				throw last_server_check_error;
			last_server_check_timer = new Timer ();

			remote_server_request = new Promise<RemoteServer> ();

			DBusConnection? connection = null;
			try {
				var stream = yield channel_provider.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (DEFAULT_CONTROL_PORT),
					cancellable);

				WebServiceTransport transport = PLAIN;
				string? origin = null;

				stream = yield negotiate_connection (stream, transport, "lolcathost", origin, cancellable);

				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DO_NOT_LOAD_PROPERTIES,
					cancellable);

				RemoteServer.Flavor flavor = REGULAR;
				try {
					var app = yield session.get_frontmost_application (make_parameters_dict (), cancellable);
					if (app.identifier == GADGET_APP_ID)
						flavor = GADGET;
				} catch (GLib.Error e) {
				}

				TransportBroker? transport_broker = null;
				if (flavor == REGULAR) {
					transport_broker = yield connection.get_proxy (null, ObjectPath.TRANSPORT_BROKER,
						DO_NOT_LOAD_PROPERTIES, cancellable);
				}

				if (connection.closed)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");

				var server = new RemoteServer (session, connection, flavor, transport_broker);
				attach_remote_server (server);
				current_remote_server = server;
				last_server_check_timer = null;
				last_server_check_error = null;

				remote_server_request.resolve (server);

				return server;
			} catch (GLib.Error e) {
				GLib.Error api_error;

				if (e is IOError.CANCELLED) {
					api_error = new IOError.CANCELLED ("%s", e.message);

					last_server_check_timer = null;
					last_server_check_error = null;
				} else {
					if (e is Error.SERVER_NOT_RUNNING) {
						api_error = new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
					} else if (connection != null) {
						api_error = new Error.PROTOCOL ("Incompatible frida-server version");
					} else {
						api_error = new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: %s",
							e.message);
					}

					last_server_check_error = (Error) api_error;
				}

				remote_server_request.reject (api_error);
				remote_server_request = null;

				throw_api_error (api_error);
			}
		}

		private void attach_remote_server (RemoteServer server) {
			server.connection.on_closed.connect (on_remote_connection_closed);

			var session = server.session;
			session.spawn_added.connect (on_remote_spawn_added);
			session.spawn_removed.connect (on_remote_spawn_removed);
			session.child_added.connect (on_remote_child_added);
			session.child_removed.connect (on_remote_child_removed);
			session.process_crashed.connect (on_remote_process_crashed);
			session.output.connect (on_remote_output);
			session.agent_session_detached.connect (on_remote_agent_session_detached);
			session.uninjected.connect (on_remote_uninjected);
		}

		private void detach_remote_server (RemoteServer server) {
			server.connection.on_closed.disconnect (on_remote_connection_closed);

			var session = server.session;
			session.spawn_added.disconnect (on_remote_spawn_added);
			session.spawn_removed.disconnect (on_remote_spawn_removed);
			session.child_added.disconnect (on_remote_child_added);
			session.child_removed.disconnect (on_remote_child_removed);
			session.process_crashed.disconnect (on_remote_process_crashed);
			session.output.disconnect (on_remote_output);
			session.agent_session_detached.disconnect (on_remote_agent_session_detached);
			session.uninjected.disconnect (on_remote_uninjected);
		}

		private void on_remote_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			detach_remote_server (current_remote_server);
			current_remote_server = null;
			remote_server_request = null;

			var no_crash = CrashInfo.empty ();
			foreach (var remote_id in remote_agent_sessions.keys.to_array ())
				on_remote_agent_session_detached (remote_id, CONNECTION_TERMINATED, no_crash);
		}

		private void on_remote_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_remote_spawn_removed (
"""


```