Response:
### 功能归纳

`gadget.vala` 是 Frida 动态插桩工具的核心模块之一，主要负责实现 Frida Gadget 的功能。Frida Gadget 是一个嵌入到目标进程中的库，用于在目标进程中执行动态插桩操作。以下是该文件的主要功能归纳：

1. **脚本加载与执行**：
   - 该模块负责加载和执行 Frida 脚本。脚本可以是 JavaScript 或 QuickJS 字节码格式。
   - 通过 `ScriptEngine` 创建脚本实例，并调用 `init` 函数初始化脚本。
   - 支持脚本的热重载功能，当脚本文件发生变化时，自动重新加载并执行。

2. **RPC 通信**：
   - 提供了与外部控制端（如 Frida CLI 或 Frida Server）的 RPC 通信机制。
   - 通过 `rpc_client` 处理来自控制端的 RPC 请求，并将结果返回给控制端。
   - 支持日志消息的处理，将脚本中的日志信息输出到标准输出或标准错误。

3. **控制服务器**：
   - 实现了 `ControlServer` 类，用于管理控制端的连接和会话。
   - 支持通过 WebSocket 或 Unix Domain Socket 与控制端进行通信。
   - 提供了会话管理功能，包括会话的创建、销毁、重新连接等。

4. **进程管理**：
   - 提供了对目标进程的管理功能，包括进程的挂起、恢复、终止等操作。
   - 支持通过 `spawn` 方法启动新的进程，并通过 `attach` 方法附加到现有进程。

5. **认证与授权**：
   - 提供了基于令牌的认证机制，确保只有授权的控制端可以连接到 Gadget。
   - 支持静态令牌认证和动态令牌认证。

6. **资源管理**：
   - 负责加载和管理 Gadget 所需的资源文件，如脚本文件、证书文件等。
   - 支持从 APK 文件中加载资源（在 Android 平台上）。

7. **日志与调试**：
   - 提供了日志输出功能，支持不同级别的日志（如 info、warning、error）。
   - 通过 `log_info` 和 `log_warning` 函数输出日志信息。

8. **垃圾回收**：
   - 实现了线程垃圾回收机制，确保在脚本执行过程中及时释放不再使用的资源。

### 二进制底层与 Linux 内核相关

- **进程管理**：`gadget.vala` 中的 `spawn`、`resume`、`kill` 等方法涉及到对目标进程的操作，这些操作通常依赖于底层的系统调用（如 `fork`、`exec`、`ptrace` 等）。
- **动态插桩**：Frida Gadget 通过动态插桩技术（如 `ptrace`、`LD_PRELOAD` 等）在目标进程中注入代码，实现对目标进程的监控和控制。
- **线程管理**：`gadget.vala` 中涉及到线程的创建、销毁和垃圾回收，这些操作依赖于底层的线程管理机制（如 `pthread`）。

### LLDB 调试示例

假设我们想要调试 `gadget.vala` 中的 `call_init` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```bash
# 启动目标进程并附加 LLDB
lldb target_process

# 设置断点
b gadget.vala:call_init

# 运行进程
run

# 当断点命中时，查看变量值
frame variable

# 继续执行
continue
```

#### LLDB Python 脚本

```python
import lldb

def breakpoint_handler(frame, bp_loc, dict):
    print("Breakpoint hit in call_init")
    print("Frame:", frame)
    print("Variables:", frame.GetVariables(True, True, True, True))
    return True

# 初始化 LLDB
debugger = lldb.SBDebugger.Create()
target = debugger.CreateTarget("target_process")

# 设置断点
breakpoint = target.BreakpointCreateByLocation("gadget.vala", 123)  # 假设 call_init 在 123 行
breakpoint.SetScriptCallbackFunction("breakpoint_handler")

# 启动进程
process = target.LaunchSimple(None, None, os.getcwd())

# 等待进程结束
process.GetState()
```

### 假设输入与输出

假设我们有一个 Frida 脚本 `example.js`，内容如下：

```javascript
console.log("Hello, Frida!");
```

#### 输入

- 脚本路径：`/path/to/example.js`
- 控制端连接：`localhost:27042`

#### 输出

- 控制端连接到 Gadget 后，Gadget 会加载并执行 `example.js`，输出日志信息到控制端：

```
Hello, Frida!
```

### 用户常见使用错误

1. **脚本路径错误**：
   - 用户提供的脚本路径不正确，导致 Gadget 无法加载脚本。
   - 解决方法：确保脚本路径正确，并且脚本文件存在。

2. **认证失败**：
   - 用户提供的认证令牌不正确，导致控制端无法连接到 Gadget。
   - 解决方法：检查认证令牌是否正确，并确保控制端和 Gadget 使用相同的令牌。

3. **脚本语法错误**：
   - 脚本中存在语法错误，导致 Gadget 无法正确解析和执行脚本。
   - 解决方法：检查脚本语法，确保脚本正确无误。

### 调试线索

1. **用户操作步骤**：
   - 用户启动目标进程，并将 Frida Gadget 注入到目标进程中。
   - 用户通过 Frida CLI 或 Frida Server 连接到 Gadget。
   - 用户发送 RPC 请求，加载并执行 Frida 脚本。

2. **调试线索**：
   - 如果脚本未正确加载，可以检查 `load_asset_bytes` 方法，查看是否成功加载了脚本文件。
   - 如果 RPC 通信失败，可以检查 `rpc_client` 的日志输出，查看是否有错误信息。
   - 如果脚本执行失败，可以检查 `ScriptEngine` 的日志输出，查看是否有语法错误或运行时错误。

### 总结

`gadget.vala` 是 Frida Gadget 的核心模块，负责脚本加载、RPC 通信、进程管理、认证授权等功能。通过 LLDB 调试工具，可以深入分析 Gadget 的运行机制，排查用户常见的使用错误。
### 提示词
```
这是目录为frida/subprojects/frida-core/lib/gadget/gadget.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
gress = true;

			try {
				var path = this.path;

				Bytes contents;
				try {
					load_asset_bytes (path, out contents);
				} catch (FileError e) {
					throw new Error.INVALID_ARGUMENT ("%s", e.message);
				}

				var options = new ScriptOptions ();
				options.name = Path.get_basename (path).split (".", 2)[0];

				ScriptEngine.ScriptInstance instance;
				if (contents.length > 0 && contents[0] == QUICKJS_BYTECODE_MAGIC)
					instance = yield engine.create_script (null, contents, options);
				else
					instance = yield engine.create_script ((string) contents.get_data (), null, options);

				if (id.handle != 0)
					yield engine.destroy_script (id);
				id = instance.script_id;

				yield engine.load_script (id);
				yield call_init ();
			} finally {
				load_in_progress = false;
			}
		}

		private async void call_init () {
			var stage = new Json.Node.alloc ().init_string ((peek_state () == State.CREATED) ? "early" : "late");

			try {
				yield rpc_client.call ("init", new Json.Node[] { stage, parameters }, null, null);
			} catch (GLib.Error e) {
			}
		}

		private void on_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (load_in_progress)
					return true;
				try_reload.begin ();
				return false;
			});
			source.attach (Environment.get_worker_context ());

			if (unchanged_timeout != null)
				unchanged_timeout.destroy ();
			unchanged_timeout = source;
		}

		private void on_message (AgentScriptId script_id, string json, Bytes? data) {
			if (script_id != id)
				return;

			bool handled = rpc_client.try_handle_message (json);
			if (handled)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (json);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();

			var type = message.get_string_member ("type");
			if (type == "log")
				handled = try_handle_log_message (message);

			if (!handled) {
				stdout.puts (json);
				stdout.putc ('\n');
			}
		}

		private bool try_handle_log_message (Json.Object message) {
			var level = message.get_string_member ("level");
			var payload = message.get_string_member ("payload");
			switch (level) {
				case "info":
					print ("%s\n", payload);
					break;

				case "warning":
					printerr ("\033[0;33m%s\033[0m\n", payload);
					break;

				case "error":
					printerr ("\033[0;31m%s\033[0m\n", payload);
					break;
			}
			return true;
		}

		private async void post_rpc_message (string json, Bytes? data, Cancellable? cancellable) throws Error, IOError {
			engine.post_to_script (id, json, data);
		}
	}

	private class ControlServer : BaseController {
		public EndpointParameters endpoint_params {
			get;
			construct;
		}

		public SocketAddress? listen_address {
			get {
				return (service != null) ? service.listen_address : null;
			}
		}

		private WebService? service;
		private AuthenticationService? auth_service;
		private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

		private Gee.Map<AgentSessionId?, LiveAgentSession> sessions =
			new Gee.HashMap<AgentSessionId?, LiveAgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.ArrayList<Gum.Script> eternalized_scripts = new Gee.ArrayList<Gum.Script> ();

		private Cancellable io_cancellable = new Cancellable ();

		public ControlServer (Config config, Location location) throws Error {
			Object (config: config, location: location);
		}

		construct {
		}

		protected override async void on_start () throws Error, IOError {
			var interaction = (ListenInteraction) config.interaction;

			string? token = interaction.token;
			auth_service = (token != null) ? new StaticAuthenticationService (token) : null;

			File? asset_root = null;
			string? asset_root_path = interaction.asset_root;
			if (asset_root_path != null)
				asset_root = File.new_for_path (location.resolve_asset_path (asset_root_path));

			var endpoint_params = new EndpointParameters (interaction.address, interaction.port,
				parse_certificate (interaction.certificate, location), interaction.origin, auth_service, asset_root);

			service = new WebService (endpoint_params, WebServiceFlavor.CONTROL, interaction.on_port_conflict,
				new TunnelInterfaceObserver ());
			service.incoming.connect (on_incoming_connection);
			yield service.start (io_cancellable);
		}

		protected override async void on_terminate (TerminationReason reason) {
			foreach (LiveAgentSession session in sessions.values.to_array ())
				yield session.prepare_for_termination (reason);

			foreach (var connection in peers.keys.to_array ()) {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}
			}
		}

		protected override async void on_stop () {
			service.stop ();

			io_cancellable.cancel ();

			while (!peers.is_empty) {
				var iterator = peers.keys.iterator ();
				iterator.next ();
				var connection = iterator.get ();

				Peer peer;
				peers.unset (connection, out peer);
				try {
					yield peer.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}
			}
		}

		private void on_incoming_connection (IOStream connection, SocketAddress remote_address) {
			handle_incoming_connection.begin (connection);
		}

		private async void handle_incoming_connection (IOStream raw_connection) throws GLib.Error {
			var connection = yield new DBusConnection (raw_connection, null, DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			Peer peer;
			if (auth_service != null)
				peer = new AuthenticationChannel (this, connection);
			else
				peer = setup_control_channel (connection);
			peers[connection] = peer;

			connection.start_message_processing ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Peer peer;
			if (peers.unset (connection, out peer))
				peer.close.begin (io_cancellable);
		}

		private async void promote_authentication_channel (AuthenticationChannel channel) throws GLib.Error {
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			yield channel.close (io_cancellable);

			peers[connection] = setup_control_channel (connection);
		}

		private void kick_authentication_channel (AuthenticationChannel channel) {
			Idle.add (() => {
				channel.connection.close.begin (io_cancellable);
				return false;
			});
		}

		private ControlChannel setup_control_channel (DBusConnection connection) throws IOError {
			return new ControlChannel (this, connection);
		}

		private void teardown_control_channel (ControlChannel channel) {
			foreach (AgentSessionId id in channel.sessions) {
				LiveAgentSession session = sessions[id];

				unregister_session (session);

				if (session.persist_timeout == 0) {
					sessions.unset (id);
					session.close.begin (io_cancellable);
				} else {
					session.controller = null;
					session.message_sink = null;
					session.interrupt.begin (io_cancellable);
				}
			}
		}

		private async AgentSessionId attach (HashTable<string, Variant> options, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			var opts = SessionOptions._deserialize (options);
			if (opts.realm != NATIVE)
				throw new Error.NOT_SUPPORTED ("Only native realm is supported when embedded");

			var id = AgentSessionId.generate ();

			DBusConnection controller_connection = requester.connection;

			AgentMessageSink sink;
			try {
				sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
					DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			MainContext dbus_context = yield get_dbus_context ();

			var session = new LiveAgentSession (this, id, opts.persist_timeout, sink, dbus_context);
			sessions[id] = session;
			session.closed.connect (on_session_closed);
			session.script_eternalized.connect (on_script_eternalized);

			try {
				session.registration_id = controller_connection.register_object (ObjectPath.for_agent_session (id),
					(AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			session.controller = requester;

			requester.sessions.add (id);

			return id;
		}

		private async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable) throws Error, IOError {
			LiveAgentSession? session = sessions[id];
			if (session == null || session.controller != null)
				throw new Error.INVALID_OPERATION ("Invalid session ID");

			DBusConnection controller_connection = requester.connection;

			try {
				session.message_sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
					DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			assert (session.registration_id == 0);
			try {
				session.registration_id = controller_connection.register_object (ObjectPath.for_agent_session (id),
					(AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			session.controller = requester;

			requester.sessions.add (id);
		}

		private void on_session_closed (BaseAgentSession base_session) {
			LiveAgentSession session = (LiveAgentSession) base_session;
			AgentSessionId id = session.id;

			session.script_eternalized.disconnect (on_script_eternalized);
			session.closed.disconnect (on_session_closed);
			sessions.unset (id);

			ControlChannel? controller = session.controller;
			if (controller != null) {
				unregister_session (session);
				controller.sessions.remove (id);
				controller.agent_session_detached (id, APPLICATION_REQUESTED, CrashInfo.empty ());
			}
		}

		private void unregister_session (LiveAgentSession session) {
			var id = session.registration_id;
			if (id != 0) {
				session.controller.connection.unregister_object (id);
				session.registration_id = 0;
			}
		}

		private void on_script_eternalized (Gum.Script script) {
			eternalized_scripts.add (script);
			_is_eternal = true;
		}

		private interface Peer : Object {
			public abstract async void close (Cancellable? cancellable = null) throws IOError;
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak ControlServer parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();

			public AuthenticationChannel (ControlServer parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					AuthenticationService auth_service = this;
					registrations.add (connection.register_object (ObjectPath.AUTHENTICATION_SERVICE, auth_service));

					HostSession host_session = new UnauthorizedHostSession ();
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, host_session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public async void close (Cancellable? cancellable) throws IOError {
				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async string authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				try {
					string session_info = yield parent.auth_service.authenticate (token, cancellable);
					yield parent.promote_authentication_channel (this);
					return session_info;
				} catch (GLib.Error e) {
					if (e is Error.INVALID_ARGUMENT)
						parent.kick_authentication_channel (this);
					throw e;
				}
			}
		}

		private class ControlChannel : Object, Peer, HostSession {
			public weak ControlServer parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();
			private HostApplicationInfo this_app;
			private HostProcessInfo this_process;
			private TimeoutSource? ping_timer;
			private bool resume_on_attach = true;

			public ControlChannel (ControlServer parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					HostSession host_session = this;
					registrations.add (connection.register_object (Frida.ObjectPath.HOST_SESSION, host_session));

					AuthenticationService null_auth = new NullAuthenticationService ();
					registrations.add (connection.register_object (Frida.ObjectPath.AUTHENTICATION_SERVICE, null_auth));
				} catch (IOError e) {
					assert_not_reached ();
				}

				uint pid = get_process_id ();
				string identifier = "re.frida.Gadget";
				string name = "Gadget";
				var no_parameters = make_parameters_dict ();
				this_app = HostApplicationInfo (identifier, name, pid, no_parameters);
				this_process = HostProcessInfo (pid, name, no_parameters);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				discard_ping_timer ();

				parent.teardown_control_channel (this);

				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
				discard_ping_timer ();

				if (interval_seconds != 0) {
					ping_timer = new TimeoutSource (interval_seconds * 1500);
					ping_timer.set_callback (on_ping_timeout);
					ping_timer.attach (MainContext.get_thread_default ());
				}
			}

			private void discard_ping_timer () {
				if (ping_timer == null)
					return;
				ping_timer.destroy ();
				ping_timer = null;
			}

			private bool on_ping_timeout () {
				connection.close.begin ();
				return false;
			}

			public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
				return compute_system_parameters ();
			}

			public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
					Cancellable? cancellable) throws Error, IOError {
				return this_app;
			}

			public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
					Cancellable? cancellable) throws Error, IOError {
				var opts = ApplicationQueryOptions._deserialize (options);

				if (opts.has_selected_identifiers ()) {
					bool gadget_is_selected = false;
					opts.enumerate_selected_identifiers (identifier => {
						if (identifier == this_app.identifier)
							gadget_is_selected = true;
					});
					if (!gadget_is_selected)
						return {};
				}

				return new HostApplicationInfo[] { this_app };
			}

			public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
					Cancellable? cancellable) throws Error, IOError {
				var opts = ProcessQueryOptions._deserialize (options);

				if (opts.has_selected_pids ()) {
					bool gadget_is_selected = false;
					opts.enumerate_selected_pids (pid => {
						if (pid == this_process.pid)
							gadget_is_selected = true;
					});
					if (!gadget_is_selected)
						return {};
				}

				return new HostProcessInfo[] { this_process };
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not yet implemented");
			}

			public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
				if (program != this_app.identifier)
					throw new Error.NOT_SUPPORTED ("Unable to spawn other apps when embedded");

				resume_on_attach = false;

				return this_process.pid;
			}

			public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				Frida.Gadget.resume ();
			}

			public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				Frida.Gadget.kill ();
			}

			public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
					Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				if (resume_on_attach)
					Frida.Gadget.resume ();

				return yield parent.attach (options, this, cancellable);
			}

			public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
				yield parent.reattach (id, this, cancellable);
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			private void validate_pid (uint pid) throws Error {
				if (pid != this_process.pid)
					throw new Error.NOT_SUPPORTED ("Unable to act on other processes when embedded");
			}
		}

		private class LiveAgentSession : BaseAgentSession {
			public ControlChannel? controller {
				get;
				set;
			}

			public uint registration_id {
				get;
				set;
			}

			public LiveAgentSession (ProcessInvader invader, AgentSessionId id, uint persist_timeout, AgentMessageSink sink,
					MainContext dbus_context) {
				Object (
					invader: invader,
					id: id,
					persist_timeout: persist_timeout,
					message_sink: sink,
					frida_context: MainContext.ref_thread_default (),
					dbus_context: dbus_context
				);
			}
		}
	}

	private class ClusterClient : BaseController {
		public SocketConnectable connectable {
			get;
			construct;
		}

		public string host {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public string? token {
			get;
			construct;
		}

		public string[]? acl {
			get;
			construct;
		}

		private PortalClient client;

		public ClusterClient (Config config, Location location) throws Error {
			var interaction = (ConnectInteraction) config.interaction;
			string? address = interaction.address;
			Object (
				config: config,
				location: location,
				connectable: parse_cluster_address (address, interaction.port),
				host: (address != null) ? address : "lolcathost",
				certificate: parse_certificate (interaction.certificate, location),
				token: interaction.token,
				acl: interaction.acl
			);
		}

		construct {
			client = new PortalClient (this, connectable, host, certificate, token, acl, compute_app_info ());
			client.eternalized.connect (on_eternalized);
			client.resume.connect (Frida.Gadget.resume);
			client.kill.connect (Frida.Gadget.kill);
		}

		protected override HostApplicationInfo compute_app_info () {
			var info = base.compute_app_info ();
			var interaction = config.interaction as ConnectInteraction;

			try {
				info.parameters["config"] = Json.gvariant_deserialize (interaction.parameters, null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			return info;
		}

		protected override async void on_start () throws Error, IOError {
			yield client.start ();
		}

		protected override async void on_terminate (TerminationReason reason) {
		}

		protected override async void on_stop () {
			try {
				yield client.stop ();
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		private void on_eternalized () {
			_is_eternal = true;
		}
	}

	private string derive_config_path_from_file_path (string path) {
		var dirname = Path.get_dirname (path);
		var filename = Path.get_basename (path);

		string stem;
		var ext_index = filename.last_index_of_char ('.');
		if (ext_index != -1)
			stem = filename[0:ext_index];
		else
			stem = filename;

		return Path.build_filename (dirname, stem + ".config");
	}

#if DARWIN
	private string? try_derive_framework_resource_dir_from_module_path (string module_path) {
#if MACOS
		string[] parts = module_path.split ("/");
		int n = parts.length;

		bool is_framework = (n >= 2 && parts[n - 2].has_suffix (".framework")) ||
			(n >= 4 && parts[n - 4].has_suffix (".framework") && parts[n - 3] == "Versions");
		if (!is_framework)
			return null;

		return Path.build_filename (Path.get_dirname (module_path), "Resources");
#else
		string module_dir = Path.get_dirname (module_path);
		if (!module_dir.has_suffix (".framework"))
			return null;
		return module_dir;
#endif
	}
#endif

	private void load_asset_text (string filename, out string text) throws FileError {
		Bytes raw_contents;
		load_asset_bytes (filename, out raw_contents);

		unowned string str = (string) raw_contents.get_data ();
		if (!str.validate ())
			throw new FileError.FAILED ("%s: invalid UTF-8", filename);

		text = str;
	}

	private void load_asset_bytes (string filename, out Bytes bytes) throws FileError {
#if ANDROID
		if (maybe_load_asset_bytes_from_apk (filename, out bytes))
			return;
#endif

		uint8[] data;
		FileUtils.get_data (filename, out data);
		bytes = new Bytes.take ((owned) data);
	}

#if ANDROID
	private bool maybe_load_asset_bytes_from_apk (string filename, out Bytes contents) throws FileError {
		contents = null;

		var tokens = filename.split ("!", 2);
		if (tokens.length != 2 || !tokens[0].has_suffix (".apk"))
			return false;
		unowned string apk_path = tokens[0];
		unowned string file_path = tokens[1];

		var reader = Minizip.Reader.create ();
		try {
			if (reader.open_file (apk_path) != OK)
				throw new FileError.FAILED ("Unable to open APK");

			if (reader.locate_entry (file_path[1:], true) != OK)
				throw new FileError.FAILED ("Unable to locate %s inside APK", file_path);

			var size = reader.entry_save_buffer_length ();
			var data = new uint8[size + 1];
			if (reader.entry_save_buffer (data[:size]) != OK)
				throw new FileError.FAILED ("Unable to extract %s from APK", file_path);

			contents = new Bytes.take ((owned) data);
			return true;
		} finally {
			reader.close ();
			Minizip.Reader.destroy (ref reader);
		}
	}
#endif

	private Json.Node make_empty_json_object () {
		return new Json.Node.alloc ().init_object (new Json.Object ());
	}

	private TlsCertificate? parse_certificate (string? str, Location location) throws Error {
		if (str == null)
			return null;

		try {
			if (str.index_of_char ('\n') != -1)
				return new TlsCertificate.from_pem (str, -1);
			else
				return new TlsCertificate.from_file (location.resolve_asset_path (str));
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}
	}

	namespace Environment {
		private extern void init ();
		private extern void deinit ();

		private extern bool can_block_at_load_time ();

		private extern Gum.ThreadId get_worker_tid ();
		private extern unowned MainContext get_worker_context ();

		private extern string? detect_bundle_id ();
		private extern string? detect_bundle_name ();
		private extern string? detect_documents_dir ();
		private extern bool has_objc_class (string name);

		private extern void set_thread_name (string name);
	}

	private extern void log_info (string message);
	private extern void log_warning (string message);

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void _on_pending_thread_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Timeout.add (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = Thread.garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}
}
```