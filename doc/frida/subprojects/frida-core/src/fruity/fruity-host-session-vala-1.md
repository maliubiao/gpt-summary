Response:
### 功能归纳

该文件是Frida工具中`fruity-host-session.vala`的源代码，主要负责与iOS设备进行交互，管理会话、注入库文件、处理调试会话等。以下是其主要功能的归纳：

1. **会话管理**：
   - 创建和管理本地与远程的`AgentSession`会话。
   - 通过`link_agent_session`方法将本地会话与远程会话关联。
   - 处理会话的关闭和断开事件，确保资源的正确释放。

2. **库文件注入**：
   - 提供`inject_library_file`和`inject_library_blob`方法，用于将库文件或二进制数据注入到目标进程中。
   - 这些方法通过远程服务器（`frida-server`）执行注入操作，支持通过文件路径或二进制数据块进行注入。

3. **调试会话管理**：
   - 通过`LLDBSession`类管理LLDB调试会话，处理调试器的输出和关闭事件。
   - 提供`resume`和`kill`方法，用于控制调试会话的恢复和终止。

4. **远程服务器连接**：
   - 通过`get_remote_server`方法连接到远程的`frida-server`，并管理连接的建立、断开和重连。
   - 处理远程服务器的各种事件，如进程崩溃、子进程添加/移除、输出等。

5. **Gadget管理**：
   - 通过`GadgetEntry`类管理iOS设备上的Gadget（Frida的注入工具），处理Gadget的加载、卸载和会话管理。
   - 提供`query_gadget_details`方法，查询Gadget的详细信息。

6. **错误处理**：
   - 处理各种错误情况，如连接失败、会话无效、注入失败等，并抛出相应的错误信息。

### 二进制底层与Linux内核相关

- **库文件注入**：`inject_library_file`和`inject_library_blob`方法涉及到底层的进程注入技术，通常通过`ptrace`或`dlopen`等系统调用实现。在Linux内核中，`ptrace`系统调用用于进程调试和注入，允许一个进程控制另一个进程的执行。
  
- **调试会话管理**：`LLDBSession`类与LLDB调试器交互，LLDB是一个底层调试工具，能够直接与操作系统的调试接口交互，如Linux内核的`ptrace`接口。

### LLDB调试示例

假设我们想要复现`LLDBSession`类的调试功能，可以使用以下LLDB Python脚本：

```python
import lldb

def create_lldb_session(pid):
    # 创建一个LLDB调试器实例
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    
    # 附加到指定PID的进程
    target = debugger.CreateTarget("")
    process = target.AttachToProcessWithID(lldb.SBListener(), pid)
    
    # 检查是否成功附加
    if process.IsValid():
        print(f"Successfully attached to process {pid}")
        return process
    else:
        print(f"Failed to attach to process {pid}")
        return None

def resume_process(process):
    # 恢复进程执行
    process.Continue()

def kill_process(process):
    # 终止进程
    process.Kill()

# 示例：附加到PID为1234的进程
pid = 1234
process = create_lldb_session(pid)
if process:
    resume_process(process)
    kill_process(process)
```

### 假设输入与输出

- **输入**：假设我们调用`inject_library_file`方法，传入PID为1234，库文件路径为`/path/to/library.dylib`，入口点为`main`，数据为空。
- **输出**：如果注入成功，返回一个`InjectorPayloadId`，表示注入的库的唯一标识符。如果注入失败，抛出`Error`或`IOError`异常。

### 常见使用错误

1. **无效的会话ID**：
   - 用户可能尝试使用一个不存在的会话ID进行链接操作，导致`Error.INVALID_ARGUMENT`错误。
   - 示例：`link_agent_session`方法中，如果传入的`id`不存在于`agent_sessions`中，会抛出`Error.INVALID_ARGUMENT`。

2. **连接失败**：
   - 用户可能尝试连接到一个未运行的`frida-server`，导致`Error.SERVER_NOT_RUNNING`错误。
   - 示例：`get_remote_server`方法中，如果无法连接到远程服务器，会抛出`Error.SERVER_NOT_RUNNING`。

3. **注入失败**：
   - 用户可能尝试注入一个不兼容的库文件，导致`Error.NOT_SUPPORTED`错误。
   - 示例：`inject_library_file`方法中，如果库文件不兼容目标进程的架构，会抛出`Error.NOT_SUPPORTED`。

### 用户操作路径

1. **启动Frida**：用户启动Frida工具，并尝试连接到目标设备。
2. **创建会话**：用户通过Frida API创建一个新的会话，Frida会调用`link_agent_session`方法将本地会话与远程会话关联。
3. **注入库文件**：用户调用`inject_library_file`方法，尝试将库文件注入到目标进程中。
4. **调试会话**：用户通过Frida的调试接口启动LLDB调试会话，Frida会调用`LLDBSession`类的方法管理调试会话。
5. **处理错误**：如果任何步骤失败，Frida会抛出相应的错误，用户需要根据错误信息进行排查和处理。

### 总结

该文件是Frida工具中与iOS设备交互的核心部分，主要负责会话管理、库文件注入、调试会话管理等功能。通过LLDB调试器和底层系统调用，Frida能够实现对目标进程的动态插桩和调试。用户在使用过程中需要注意会话ID的有效性、连接的稳定性以及库文件的兼容性，以避免常见的错误。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/fruity/fruity-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
_error (e);
			}
			var local_session_id = AgentSessionId.generate ();

			var entry = new AgentSessionEntry (remote_session_id, server.connection);

			remote_agent_sessions[remote_session_id] = local_session_id;
			agent_sessions[local_session_id] = entry;

			var transport_broker = server.transport_broker;
			if (transport_broker != null) {
				try {
					entry.connection = yield establish_direct_connection (transport_broker, remote_session_id, server,
						cancellable);
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

		private void add_lldb_session (LLDBSession session) {
			lldb_sessions[session.process.pid] = session;

			session.closed.connect (on_lldb_session_closed);
			session.output.connect (on_lldb_session_output);
		}

		private void remove_lldb_session (LLDBSession session) {
			lldb_sessions.unset (session.process.pid);

			session.closed.disconnect (on_lldb_session_closed);
			session.output.disconnect (on_lldb_session_output);
		}

		private void on_lldb_session_closed (LLDBSession session) {
			remove_lldb_session (session);
		}

		private void on_lldb_session_output (LLDBSession session, Bytes bytes) {
			output (session.process.pid, 1, bytes.get_data ());
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

		private async RemoteServer? try_get_remote_server (Cancellable? cancellable) throws Error, IOError {
			try {
				return yield get_remote_server (cancellable);
			} catch (Error e) {
				if (e is Error.SERVER_NOT_RUNNING)
					return null;
				throw e;
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
				var channel = yield connect_to_remote_server (cancellable);

				IOStream stream = channel.stream;
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

				var server = new RemoteServer (flavor, session, connection, channel, device, transport_broker);
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
					if (e is Error) {
						api_error = e;
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

		private async Fruity.TcpChannel connect_to_remote_server (Cancellable? cancellable) throws Error, IOError {
			var tunnel = yield device.find_tunnel (cancellable);
			bool tunnel_recently_opened = tunnel != null && get_monotonic_time () - tunnel.opened_at < 1000000;

			uint delays[] = { 0, 50, 250 };
			uint max_attempts = tunnel_recently_opened ? delays.length : 1;
			var main_context = MainContext.ref_thread_default ();

			Error? pending_error = null;
			for (uint attempts = 0; attempts != max_attempts; attempts++) {
				uint delay = delays[attempts];
				if (delay != 0) {
					var timeout_source = new TimeoutSource (delay);
					timeout_source.set_callback (connect_to_remote_server.callback);
					timeout_source.attach (main_context);

					var cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (connect_to_remote_server.callback);
					cancel_source.attach (main_context);

					yield;

					cancel_source.destroy ();
					timeout_source.destroy ();

					if (cancellable.is_cancelled ())
						break;
				}

				bool is_last_attempt = attempts == max_attempts - 1;
				var open_flags = is_last_attempt
					? Fruity.OpenTcpChannelFlags.ALLOW_ANY_TRANSPORT
					: Fruity.OpenTcpChannelFlags.ALLOW_TUNNEL;

				try {
					return yield device.open_tcp_channel (DEFAULT_CONTROL_PORT.to_string (), open_flags, cancellable);
				} catch (Error e) {
					pending_error = e;
					if (!(e is Error.SERVER_NOT_RUNNING))
						break;
				}
			}
			throw pending_error;
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

		private void on_remote_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		private void on_remote_child_added (HostChildInfo info) {
			child_added (info);
		}

		private void on_remote_child_removed (HostChildInfo info) {
			child_removed (info);
		}

		private void on_remote_process_crashed (CrashInfo crash) {
			process_crashed (crash);
		}

		private void on_remote_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_remote_agent_session_detached (AgentSessionId remote_id, SessionDetachReason reason, CrashInfo crash) {
			AgentSessionId? local_id;
			if (!remote_agent_sessions.unset (remote_id, out local_id))
				return;

			bool agent_session_found = agent_sessions.unset (local_id);
			assert (agent_session_found);

			agent_session_detached (local_id, reason, crash);
		}

		private void on_remote_uninjected (InjectorPayloadId id) {
			uninjected (id);
		}

		private class LLDBSession : Object {
			public signal void closed ();
			public signal void output (Bytes bytes);

			public LLDB.Client lldb {
				get;
				construct;
			}

			public LLDB.Process process {
				get;
				construct;
			}

			public string? gadget_path {
				get;
				construct;
			}

			public weak HostChannelProvider channel_provider {
				get;
				construct;
			}

			private Promise<Fruity.Injector.GadgetDetails>? gadget_request;

			public LLDBSession (LLDB.Client lldb, LLDB.Process process, string? gadget_path,
					HostChannelProvider channel_provider) {
				Object (
					lldb: lldb,
					process: process,
					gadget_path: gadget_path,
					channel_provider: channel_provider
				);
			}

			construct {
				lldb.closed.connect (on_lldb_closed);
				lldb.console_output.connect (on_lldb_console_output);
			}

			~LLDBSession () {
				lldb.closed.disconnect (on_lldb_closed);
				lldb.console_output.disconnect (on_lldb_console_output);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				yield lldb.close (cancellable);
			}

			public async void resume (Cancellable? cancellable) throws Error, IOError {
				yield lldb.detach (cancellable);
			}

			public async void kill (Cancellable? cancellable) throws Error, IOError {
				yield lldb.kill (cancellable);
			}

			public async Fruity.Injector.GadgetDetails query_gadget_details (Cancellable? cancellable) throws Error, IOError {
				while (gadget_request != null) {
					try {
						return yield gadget_request.future.wait_async (cancellable);
					} catch (Error e) {
						throw e;
					} catch (IOError e) {
						cancellable.set_error_if_cancelled ();
					}
				}
				gadget_request = new Promise<Fruity.Injector.GadgetDetails> ();

				try {
					string? path = gadget_path;
					if (path == null) {
						path = Path.build_filename (Environment.get_user_cache_dir (), "frida", "gadget-ios.dylib");
						if (!FileUtils.test (path, FileTest.EXISTS)) {
							throw new Error.NOT_SUPPORTED ("Need Gadget to attach on jailed iOS; its default location is: %s",
								path);
						}
					}

					if (process.cpu_type != ARM64)
						throw new Error.NOT_SUPPORTED ("Unsupported CPU; only arm64 is supported on jailed iOS");

					var ptrauth_support = (process.cpu_subtype == ARM64E)
						? Gum.PtrauthSupport.SUPPORTED
						: Gum.PtrauthSupport.UNSUPPORTED;
					var module = new Gum.DarwinModule.from_file (path, Gum.CpuType.ARM64, ptrauth_support);

					var details = yield Fruity.Injector.inject ((owned) module, lldb, channel_provider, cancellable);

					gadget_request.resolve (details);

					return details;
				} catch (GLib.Error e) {
					var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

					gadget_request.reject (api_error);
					gadget_request = null;

					throw api_error;
				}
			}

			private void on_lldb_closed () {
				closed ();
			}

			private void on_lldb_console_output (Bytes bytes) {
				output (bytes);
			}
		}

		private class GadgetEntry : Object {
			public signal void detached (SessionDetachReason reason);

			public AgentSessionId local_session_id {
				get;
				construct;
			}

			public HostSession host_session {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			private Promise<bool>? close_request;

			public GadgetEntry (AgentSessionId local_session_id, HostSession host_session, DBusConnection connection) {
				Object (
					local_session_id: local_session_id,
					host_session: host_session,
					connection: connection
				);
			}

			construct {
				connection.on_closed.connect (on_connection_closed);
				host_session.agent_session_detached.connect (on_session_detached);
			}

			~GadgetEntry () {
				connection.on_closed.disconnect (on_connection_closed);
				host_session.agent_session_detached.disconnect (on_session_detached);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				while (close_request != null) {
					try {
						yield close_request.future.wait_async (cancellable);
						return;
					} catch (Error e) {
						assert_not_reached ();
					} catch (IOError e) {
						cancellable.set_error_if_cancelled ();
					}
				}
				close_request = new Promise<bool> ();

				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED) {
						close_request.reject (e);
						close_request = null;

						throw (IOError) e;
					}
				}

				close_request.resolve (true);
			}

			private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
				if (close_request == null) {
					close_request = new Promise<bool> ();
					close_request.resolve (true);
				}

				detached (PROCESS_TERMINATED);
			}

			private void on_session_detached (AgentSessionId id, SessionDetachReason reason) {
				detached (reason);
			}
		}

		private class AgentSessionEntry {
			public AgentSessionId remote_session_id {
				get;
				private set;
			}

			public DBusConnection connection {
				get;
				set;
			}

			public uint sink_registration_id {
				get;
				set;
			}

			public AgentSessionEntry (AgentSessionId remote_session_id, DBusConnection connection) {
				this.remote_session_id = remote_session_id;
				this.connection = connection;
			}

			~AgentSessionEntry () {
				if (sink_registration_id != 0)
					connection.unregister_object (sink_registration_id);
			}
		}

		private class RemoteServer : Object, HostChannelProvider {
			public Flavor flavor {
				get;
				construct;
			}

			public HostSession session {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Fruity.TcpChannel channel {
				get;
				construct;
			}

			public Fruity.Device device {
				get;
				construct;
			}

			public enum Flavor {
				REGULAR,
				GADGET
			}

			public TransportBroker? transport_broker {
				get;
				set;
			}

			public RemoteServer (Flavor flavor, HostSession session, DBusConnection connection, Fruity.TcpChannel channel,
					Fruity.Device device, TransportBroker? transport_broker) {
				Object (
					flavor: flavor,
					session: session,
					connection: connection,
					channel: channel,
					device: device,
					transport_broker: transport_broker
				);
			}

			public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
				if (!address.has_prefix ("tcp:"))
					throw new Error.NOT_SUPPORTED ("Unsupported channel address");
				var flags = (channel.kind == TUNNEL)
					? Fruity.OpenTcpChannelFlags.ALLOW_TUNNEL
					: Fruity.OpenTcpChannelFlags.ALLOW_USBMUX;
				var channel = yield device.open_tcp_channel (address[4:], flags, cancellable);
				return channel.stream;
			}
		}
	}

	private sealed class PlistService : Object, Service {
		public IOStream stream {
			get;
			construct;
		}

		private State state = INACTIVE;
		private Fruity.PlistServiceClient client;
		private bool client_closed = false;

		private enum State {
			INACTIVE,
			ACTIVE,
		}

		public PlistService (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			client = new Fruity.PlistServiceClient (stream);
			client.closed.connect (on_client_closed);
		}

		public bool is_closed () {
			return client_closed;
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (state == INACTIVE) {
				state = ACTIVE;

				if (client_closed) {
					close ();
					throw new Error.INVALID_OPERATION ("Service is closed");
				}
			}
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			if (client_closed)
				return;
			client_closed = true;

			yield client.close (cancellable);
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			var reader = new VariantReader (parameters);

			string type = reader.read_member ("type").get_string_value ();
			reader.end_member ();

			try {
				if (type == "query") {
					reader.read_member ("payload");
					var payload = plist_from_variant (reader.current_object);
					var raw_response = yield client.query (payload, cancellable);
					return plist_to_variant (raw_response);
				} else if (type == "read") {
					var plist = yield client.read_message (cancellable);
					return plist_to_variant (plist);
				} else {
					throw new Error.INVALID_ARGUMENT ("Unsupported request type: %s", type);
				}
			} catch (Fruity.PlistServiceError e) {
				if (e is Fruity.PlistServiceError.CONNECTION_CLOSED)
					throw new Error.TRANSPORT ("Connection closed during request");
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private void on_client_closed () {
			client_closed = true;
			close ();
		}

		private Fruity.Plist plist_from_variant (Variant val) throws Error {
			if (!val.is_of_type (VariantType.VARDICT))
				throw new Error.INVALID_ARGUMENT ("Expected a dictionary");

			var plist = new Fruity.Plist ();

			foreach (var item in val) {
				string k;
				Variant v;
				item.get ("{sv}", out k, out v);

				plist.set_value (k, plist_value_from_variant (v));
			}

			return plist;
		}

		private Value plist_value_from_variant (Variant val) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					return val.get_boolean ();
				case INT64:
					return val.get_int64 ();
				case DOUBLE:
					return val.get_double ();
				case STRING:
					return val.get_string ();
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay")))
						return val.get_data_as_bytes ();

					if (val.is_of_type (VariantType.VARDICT)) {
						var dict = new Fruity.PlistDict ();

						foreach (var item in val) {
							string k;
							Variant v;
							item.get ("{sv}", out k, out v);

							dict.set_value (k, plist_value_from_variant (v));
						}

						return dict;
					}

					if (val.is_of_type (new VariantType ("av"))) {
						var arr = new Fruity.PlistArray ();

						foreach (var item in val) {
							Variant v;
							item.get ("v", out v);

							arr.add_value (plist_value_from_variant (v));
						}

						return arr;
					}

					break;
				default:
					break;
			}

			throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", (string) val.get_type ().peek_string ());
		}

		private Variant plist_to_variant (Fruity.Plist plist) {
			return plist_dict_to_variant (plist);
		}

		private Variant plist_dict_to_variant (Fruity.PlistDict dict) {
			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in dict.entries)
				builder.add ("{sv}", e.key, plist_value_to_variant (e.value));
			return builder.end ();
		}

		private Variant plist_array_to_variant (Fruity.PlistArray arr) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in arr.elements)
				builder.add ("v", plist_value_to_variant (e));
			return builder.end ();
		}

		private Variant plist_value_to_variant (Value * v) {
			Type t = v.type ();

			if (t == typeof (bool))
				return v.get_boolean ();

			if (t == typeof (int64))
				return v.get_int64 ();

			if (t == typeof (float))
				return (double) v.get_float ();

			if (t == typeof (double))
				return v.get_double ();

			if (t == typeof (string))
				return v.get_string ();

			if (t == typeof (Bytes)) {
				var bytes = (Bytes) v.get_boxed ();
				return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
			}

			if (t == typeof (Fruity.PlistDict))
				return plist_dict_to_variant ((Fruity.PlistDict) v.get_object ());

			if (t == typeof (Fruity.PlistArray))
				return plist_array_to_variant ((Fruity.PlistArray) v.get_object ());

			if (t == typeof (Fruity.PlistUid))
				return ((Fruity.PlistUid) v.get_object ()).uid;

			assert_not_reached ();
		}
	}

	private sealed class DTXService : Object, Service {
		public string identifier {
			get;
			construct;
		}

		public Fruity.DTXConnection connection {
			get;
			construct;
		}

		private State state = INACTIVE;
		private bool connection_closed = false;
		private Fruity.DTXChannel? channel;

		private enum State {
			INACTIVE,
			ACTIVE,
		}

		public DTXService (string identifier, Fruity.DTXConnection connection) {
			Object (identifier: identifier, connection: connection);
		}

		construct {
			connection.notify["state"].connect (on_connection_state_changed);
		}

		public bool is_closed () {
			return connection_closed;
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (state == INACTIVE) {
				state = ACTIVE;

				if (connection_closed) {
					close ();
					throw new Error.INVALID_OPERATION ("Service is closed");
				}

				channel = connection.make_channel (identifier);
				channel.invocation.connect (on_channel_invocation);
				channel.notification.connect (on_channel_notification);
			}
		}

		private void ensure_closed () {
			if (connection_closed)
				return;
			connection_closed = true;
			channel = null;
			close ();
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			ensure_closed ();
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			var reader = new VariantReader (parameters);

			string method_name = reader.read_member ("method").get_string_value ();
			reader.end_member ();

			Fruity.DTXArgumentListBuilder? args = null;
			if (reader.has_member ("args")) {
				reader.read_member ("args");
				args = new Fruity.DTXArgumentListBuilder ();
				uint n = reader.count_elements ();
				for (uint i = 0; i != n; i++) {
					reader.read_element (i);
					args.append_object (nsobject_from_variant (reader.current_object));
					reader.end_element ();
				}
			}

			var result = yield channel.invoke (method_name, args, cancellable);

			return nsobject_to_variant (result);
		}

		private void on_connection_state_changed (Object obj, ParamSpec pspec) {
			if (connection.state == CLOSED)
				ensure_closed ();
		}

		private void on_channel_invocation (string method_name, Fruity.DTXArgumentList args,
				Fruity.DTXMessageTransportFlags transport_flags) {
			var envelope = new HashTable<string, Variant> (str_hash, str_equal);
			envelope["type"] = "invocation";
			envelope["payload"] = invocation_to_variant (method_name, args);
			envelope["expects-reply"] = (transport_flags & Fruity.DTXMessageTransportFlags.EXPECTS_REPLY) != 0;
			message (envelope);
		}

		private void on_channel_notification (Fruity.NSObject obj) {
			var envelope = new HashTable<string, Variant> (str_hash, str_equal);
			envelope["type"] = "notification";
			envelope["payload"] = nsobject_to_variant (obj);
			message (envelope);
		}

		private Fruity.NSObject? nsobject_from_variant (Variant val) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					return new Fruity.NSNumber.from_boolean (val.get_boolean ());
				case INT64:
					return new Fruity.NSNumber.from_integer (val.get_int64 ());
				case DOUBLE:
					return new Fruity.NSNumber.from_double (val.get_double ());
				case STRING:
					return new Fruity.NSString (val.get_string ());
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay")))
						return new Fruity.NSData (val.get_data_as_bytes ());

					if (val.is_of_type (VariantType.VARDICT)) {
						var dict = new Fruity.NSDictionary ();

						foreach (var item in val) {
							string k;
							Variant v;
							item.get ("{sv}", out k, out v);

							dict.set_value (k, nsobject_from_variant (v));
						}

						return dict;
					}

					if (val.is_of_type (new VariantType ("av"))) {
						var arr = new Fruity.NSArray ();

						foreach (var item in val) {
							Variant v;
							item.get ("v", out v);

							arr.add_object (nsobject_from_variant (v));
						}

						return arr;
					}

					break;
				default:
					break;
			}

			throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", (string) val.get_type ().peek_string ());
		}

		private Variant nsobject_to_variant (Fruity.NSObject? obj) {
			if (obj == null)
				return new Variant ("()");

			var num = obj as Fruity.NSNumber;
			if (num != null)
				return num.integer;

			var str = obj as Fruity.NSString;
			if (str != null)
				return str.str;

			var data = obj as Fruity.NSData;
			if (data != null) {
				Bytes bytes = data.bytes;
				return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
			}

			var dict = obj as Fruity.NSDictionary;
			if (dict != null)
				return nsdictionary_to_variant (dict);

			var dict_raw = obj as Fruity.NSDictionaryRaw;
			if (dict_raw != null)
				return nsdictionary_raw_to_variant (dict_raw);

			var arr = obj as Fruity.NSArray;
			if (arr != null)
				return nsarray_to_variant (arr);

			var date = obj as Fruity.NSDate;
			if (date != null)
				return date.to_date_time ().format_iso8601 ();

			var err = obj as Fruity.NSError;
			if (err != null)
				return nserror_to_variant (err);

			var msg = obj as Fruity.DTTapMessage;
			if (msg != null)
				return nsdictionary_to_variant (msg.plist);

			assert_not_reached ();
		}

		private Variant nsdictionary_to_variant (Fruity.NSDictionary dict) {
			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in dict.entries)
				builder.add ("{sv}", e.key, nsobject_to_variant (e.value));
			return builder.end ();
		}

		private Variant nsdictionary_raw_to_variant (Fruity.NSDictionaryRaw dict) {
			var builder = new VariantBuilder (
				new VariantType.array (new VariantType.dict_entry (VariantType.VARIANT, VariantType.VARIANT)));
			foreach (var e in dict.entries)
				builder.add ("{vv}", nsobject_to_variant (e.key), nsobject_to_variant (e.value));
			return builder.end ();
		}

		private Variant nsarray_to_variant (Fruity.NSArray arr) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in arr.elements)
				builder.add ("v", nsobject_to_variant (e));
			return builder.end ();
		}

		private Variant nserror_to_variant (Fruity.NSError e) {
			var result = new HashTable<string, Variant> (str_hash, str_equal);
			result["domain"] = e.domain.str;
			result["code"] = e.code;
			result["user-info"] = nsdictionary_to_variant (e.user_info);
			return result;
		}

		private Variant invocation_to_variant (string method_name, Fruity.DTXArgumentList args) {
			var invocation = new HashTable<string, Variant> (str_hash, str_equal);
			invocation["method"] = method_name;
			invocation["args"] = invocation_args_to_variant (args);
			return invocation;
		}

		private Variant invocation_args_to_variant (Fruity.DTXArgumentList args) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in args.elements)
				builder.add ("v", value_to_variant (e));
			return builder.end ();
		}

		private Variant value_to_variant (Value v) {
			Type t = v.type ();

			if (t == typeof (int))
				return v.get_int ();

			if (t == typeof (int64))
				return v.get_int64 ();

			if (t == typeof (double))
				return v.get_double ();

			if (t == typeof (string))
				return v.get_string ();

			if (t.is_a (typeof (Fruity.NSObject)))
				return nsobject_to_variant ((Fruity.NSObject) v.get_boxed ());

			assert_not_reached ();
		}
	}

	private sealed class XpcService : Object, Service {
		public Fruity.XpcConnection connection {
			get;
			construct;
		}

		private State state = INACTIVE;
		private bool connection_closed = false;

		private enum State {
			INACTIVE,
			ACTIVE,
		}

		public XpcService (Fruity.XpcConnection connection) {
			Object (connection: connection);
		}

		construct {
			connection.close.connect (on_close);
			connection.message.connect (on_message);
		}

		public bool is_closed () {
			return connection_closed;
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (state == INACTIVE) {
				state = ACTIVE;

				if (connection_closed) {
					close ();
					throw new Error.INVALID_OPERATION ("Service is closed");
				}

				connection.activate ();
			}
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			connection.cancel ();
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			yield connection.wait_until_ready (cancellable);

			if (!parameters.is_of_type (VariantType.VARDICT))
				throw new Error.INVALID_ARGUMENT ("Expected a dictionary");

			var builder = new Fruity.XpcBodyBuilder ();
			builder.begin_dictionary ();
			add_vardict_values (parameters, builder);
			Fruity.TrustedService.add_standard_request_values (builder);
			builder.end_dictionary ();

			Fruity.XpcMessage response = yield connection.request (builder.build (), cancellable);

			return response.body;
		}

		private void on_close (Error? error) {
			connection_closed = true;
			close ();
		}

		private void on_message (Fruity.XpcMessage msg) {
			message (msg.body);
		}

		private static void add_vardict_values (Variant dict, Fruity.XpcBodyBuilder builder) throws Error {
			foreach (var item in dict) {
				string key;
				Variant val;
				item.get ("{sv}", out key, out val);

				builder.set_member_name (key);
				add_variant_value (val, builder);
			}
		}

		private static void add_vararray_values (Variant arr, Fruity.XpcBodyBuilder builder) throws Error {
			foreach (var item in arr) {
				Variant val;
				item.get ("v", out val);

				add_variant_value (val, builder);
			}
		}

		private static void add_variant_value (Variant val, Fruity.XpcBodyBuilder builder) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					builder.add_bool_value (val.get_boolean ());
					return;
				case INT64:
					builder.add_int64_value (val.get_int64 ());
					return;
				case STRING:
					builder.add_string_value (val.get_string ());
					return;
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay"))) {
						builder.add_data_value (val.get_data_as_bytes ());
						return;
					}

					if (val.is_
```