Response:
### 功能归纳

`portal-service.vala` 是 Frida 动态插桩工具的核心组件之一，主要负责管理 Frida 的 Portal 服务。Portal 服务是 Frida 的一个关键组件，用于处理远程连接、会话管理、进程控制等任务。以下是该文件的主要功能归纳：

1. **节点连接管理**：
   - 管理远程节点的连接和断开事件。通过信号 `node_connected` 和 `node_disconnected` 通知节点的连接状态。
   - 处理节点的加入和离开事件，通过信号 `node_joined` 和 `node_left` 通知节点的加入和离开。

2. **控制器连接管理**：
   - 管理控制器的连接和断开事件。通过信号 `controller_connected` 和 `controller_disconnected` 通知控制器的连接状态。

3. **会话管理**：
   - 管理会话的创建、销毁和重新连接。通过 `attach` 和 `reattach` 方法处理会话的创建和重新连接。
   - 处理会话的过期和关闭事件，通过 `on_agent_session_expired` 和 `on_agent_session_closed` 方法处理会话的生命周期。

4. **消息传递**：
   - 提供消息传递功能，支持向特定连接或所有连接广播消息。通过 `post`、`narrowcast` 和 `broadcast` 方法实现消息的发送。

5. **进程控制**：
   - 提供进程的枚举、挂起、恢复和终止功能。通过 `enumerate_applications`、`enumerate_processes`、`resume` 和 `kill` 方法实现进程的控制。

6. **权限管理**：
   - 管理节点的访问权限，通过 `can_access` 方法检查控制器是否有权限访问特定节点。

7. **调试功能**：
   - 提供调试功能，如挂起进程、恢复进程、附加到进程等。通过 `enable_spawn_gating` 和 `disable_spawn_gating` 方法实现进程的挂起和恢复。

### 涉及二进制底层和 Linux 内核的举例

1. **进程挂起与恢复**：
   - 在 Linux 系统中，进程的挂起和恢复通常涉及到 `ptrace` 系统调用。Frida 通过 `ptrace` 系统调用实现进程的挂起和恢复。例如，`enable_spawn_gating` 方法会挂起新创建的进程，直到控制器允许其继续执行。

2. **进程附加**：
   - 在 Linux 系统中，进程附加通常涉及到 `ptrace` 系统调用。Frida 通过 `ptrace` 系统调用实现进程的附加。例如，`attach` 方法会将 Frida 的调试器附加到目标进程。

### LLDB 指令或 LLDB Python 脚本示例

假设我们想要复刻 `attach` 方法的功能，即附加到目标进程并创建一个会话。以下是一个使用 LLDB Python 脚本的示例：

```python
import lldb

def attach_to_process(pid):
    # 创建一个调试器实例
    debugger = lldb.SBDebugger.Create()
    
    # 附加到目标进程
    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
    
    if error.Success():
        print(f"Successfully attached to process {pid}")
        # 在这里可以执行更多的调试操作
    else:
        print(f"Failed to attach to process {pid}: {error}")

# 使用示例
attach_to_process(1234)  # 1234 是目标进程的 PID
```

### 假设输入与输出

1. **输入**：
   - `attach` 方法的输入包括目标进程的 PID 和会话选项。
   - 例如：`attach(1234, options)`，其中 `1234` 是目标进程的 PID，`options` 是会话选项。

2. **输出**：
   - `attach` 方法的输出是一个 `AgentSessionId`，表示新创建的会话的唯一标识符。
   - 例如：`AgentSessionId("session-1234")`。

### 用户常见的使用错误

1. **权限不足**：
   - 用户尝试附加到一个需要 root 权限的进程，但没有以 root 身份运行 Frida。这会导致附加失败。
   - 解决方法：以 root 身份运行 Frida。

2. **进程不存在**：
   - 用户尝试附加到一个不存在的进程，导致 `attach` 方法抛出 `Error.PROCESS_NOT_FOUND` 异常。
   - 解决方法：确保目标进程存在并且 PID 正确。

### 用户操作如何一步步到达这里

1. **启动 Frida 服务**：
   - 用户启动 Frida 服务，Frida 会初始化 `PortalService` 并开始监听连接。

2. **连接远程节点**：
   - 用户通过 Frida 客户端连接到远程节点，触发 `node_connected` 信号。

3. **附加到进程**：
   - 用户通过 Frida 客户端发送 `attach` 请求，Frida 会调用 `attach` 方法附加到目标进程并创建会话。

4. **发送消息**：
   - 用户通过 Frida 客户端发送消息，Frida 会调用 `post` 或 `broadcast` 方法将消息发送到目标会话或所有会话。

5. **断开连接**：
   - 用户断开连接，Frida 会触发 `node_disconnected` 信号并清理相关资源。

通过以上步骤，用户可以逐步使用 Frida 的动态插桩功能进行调试和分析。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/portal-service.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
namespace Frida {
	public class PortalService : Object {
		public signal void node_connected (uint connection_id, SocketAddress remote_address);
		public signal void node_joined (uint connection_id, Application application);
		public signal void node_left (uint connection_id, Application application);
		public signal void node_disconnected (uint connection_id, SocketAddress remote_address);

		public signal void controller_connected (uint connection_id, SocketAddress remote_address);
		public signal void controller_disconnected (uint connection_id, SocketAddress remote_address);

		public signal void authenticated (uint connection_id, string session_info);
		public signal void subscribe (uint connection_id);
		public signal void message (uint connection_id, string json, Bytes? data);

		public Device device {
			get {
				return _device;
			}
		}
		private Device _device;

		public EndpointParameters cluster_params {
			get;
			construct;
		}

		public EndpointParameters? control_params {
			get;
			construct;
		}

		private State state = STOPPED;

		private WebService cluster_service;
		private WebService? control_service;

		private Gee.Map<uint, ConnectionEntry> connections = new Gee.HashMap<uint, ConnectionEntry> ();
		private Gee.MultiMap<string, ConnectionEntry> tags = new Gee.HashMultiMap<string, ConnectionEntry> ();
		private uint next_connection_id = 1;

		private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

		private Gee.Map<uint, ClusterNode> node_by_pid = new Gee.HashMap<uint, ClusterNode> ();
		private Gee.Map<string, ClusterNode> node_by_identifier = new Gee.HashMap<string, ClusterNode> ();

		private Gee.Set<ControlChannel> spawn_gaters = new Gee.HashSet<ControlChannel> ();
		private Gee.Map<uint, PendingSpawn> pending_spawn = new Gee.HashMap<uint, PendingSpawn> ();
		private Gee.Map<AgentSessionId?, AgentSessionEntry> sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Cancellable? io_cancellable;

		private enum State {
			STOPPED,
			STARTING,
			STARTED
		}

		public PortalService (EndpointParameters cluster_params, EndpointParameters? control_params = null) {
			Object (cluster_params: cluster_params, control_params: control_params);
		}

		construct {
			_device = new Device (null, new PortalHostSessionProvider (this));

			cluster_service = new WebService (cluster_params, CLUSTER);
			cluster_service.incoming.connect (on_incoming_cluster_connection);

			if (control_params != null) {
				control_service = new WebService (control_params, CONTROL);
				control_service.incoming.connect (on_incoming_control_connection);
			}
		}

		public override void dispose () {
			if (_device != null) {
				Device d = _device;
				_device = null;
				teardown_device.begin (d);
			}

			base.dispose ();
		}

		private async void teardown_device (Device d) {
			try {
				yield d._do_close (SessionDetachReason.DEVICE_LOST, true, null);
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STOPPED)
				throw new Error.INVALID_OPERATION ("Invalid operation");
			state = STARTING;

			io_cancellable = new Cancellable ();

			try {
				yield cluster_service.start (cancellable);

				if (control_service != null)
					yield control_service.start (cancellable);

				state = STARTED;
			} catch (GLib.Error e) {
				throw new Error.ADDRESS_IN_USE ("%s", e.message);
			} finally {
				if (state != STARTED)
					state = STOPPED;
			}
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : PortalServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STARTED)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			if (control_service != null)
				control_service.stop ();

			cluster_service.stop ();

			if (io_cancellable != null)
				io_cancellable.cancel ();

			foreach (var peer in peers.values.to_array ())
				peer.close ();
			peers.clear ();

			state = STOPPED;
		}

		public void stop_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StopTask> ().execute (cancellable);
		}

		private class StopTask : PortalServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.stop (cancellable);
			}
		}

		public void kick (uint connection_id) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_kick (connection_id);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_kick (connection_id);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_kick (uint connection_id) {
			ConnectionEntry? entry = connections[connection_id];
			if (entry == null)
				return;
			entry.connection.close.begin (io_cancellable);
		}

		public void post (uint connection_id, string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_post (connection_id, json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_post (connection_id, json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_post (uint connection_id, string json, Bytes? data) {
			ConnectionEntry? entry = connections[connection_id];
			if (entry != null)
				entry.post (json, data);
		}

		public void narrowcast (string tag, string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_narrowcast (tag, json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_narrowcast (tag, json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_narrowcast (string tag, string json, Bytes? data) {
			foreach (ConnectionEntry entry in tags[tag])
				entry.post (json, data);
		}

		public void broadcast (string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_broadcast (json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_broadcast (json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_broadcast (string json, Bytes? data) {
			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			foreach (Peer peer in peers.values) {
				ControlChannel? controller = peer as ControlChannel;
				if (controller == null)
					continue;

				BusService bus = controller.bus;
				if (bus.status != ATTACHED)
					continue;

				bus.message (json, has_data, data_param);
			}
		}

		public string[]? enumerate_tags (uint connection_id) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				return do_enumerate_tags (connection_id);
			} else {
				string[]? result = null;
				bool completed = false;
				var mutex = Mutex ();
				var cond = Cond ();

				var source = new IdleSource ();
				source.set_callback (() => {
					result = do_enumerate_tags (connection_id);
					mutex.lock ();
					completed = true;
					cond.signal ();
					mutex.unlock ();
					return false;
				});
				source.attach (context);

				mutex.lock ();
				while (!completed)
					cond.wait (mutex);
				mutex.unlock ();

				return result;
			}
		}

		private string[]? do_enumerate_tags (uint connection_id) {
			ConnectionEntry? entry = connections[connection_id];
			if (entry == null)
				return null;

			Gee.Set<string>? tags = entry.tags;
			if (tags == null)
				return null;

			string[] elements = tags.to_array ();
			string[] strv = new string[elements.length + 1];
			for (int i = 0; i != elements.length; i++)
				strv[i] = elements[i];
			strv.length = elements.length;
			return strv;
		}

		public void tag (uint connection_id, string tag) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_tag (connection_id, tag);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_tag (connection_id, tag);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_tag (uint connection_id, string tag) {
			ConnectionEntry? entry = connections[connection_id];
			if (entry == null)
				return;

			tags[tag] = entry;

			if (entry.tags == null)
				entry.tags = new Gee.HashSet<string> ();
			entry.tags.add (tag);
		}

		public void untag (uint connection_id, string tag) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_untag (connection_id, tag);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_untag (connection_id, tag);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_untag (uint connection_id, string tag) {
			ConnectionEntry? entry = connections[connection_id];
			if (entry == null)
				return;

			if (entry.tags == null)
				return;
			entry.tags.remove (tag);

			tags.remove (tag, entry);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PortalServiceTask<T> : AsyncTask<T> {
			public weak PortalService parent {
				get;
				construct;
			}
		}

		private void on_incoming_cluster_connection (IOStream connection, SocketAddress remote_address) {
			handle_incoming_connection.begin (connection, remote_address, cluster_params);
		}

		private void on_incoming_control_connection (IOStream connection, SocketAddress remote_address) {
			handle_incoming_connection.begin (connection, remote_address, control_params);
		}

		private async void handle_incoming_connection (IOStream web_connection, SocketAddress remote_address,
				EndpointParameters parameters) throws GLib.Error {
			var connection = yield new DBusConnection (web_connection, null, DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			uint connection_id = register_connection (connection, remote_address, parameters);

			Peer peer;
			if (parameters.auth_service != null)
				peer = setup_unauthorized_peer (connection_id, connection, parameters);
			else
				peer = yield setup_authorized_peer (connection_id, connection, parameters);
			peers[connection] = peer;
		}

		private uint register_connection (DBusConnection connection, SocketAddress address,
				EndpointParameters parameters) throws GLib.Error {
			uint id = next_connection_id++;

			var entry = new ConnectionEntry (connection, address, parameters);
			connections[id] = entry;

			if (parameters == cluster_params)
				node_connected (id, address);
			else
				controller_connected (id, address);

			return id;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Peer peer;
			if (peers.unset (connection, out peer)) {
				peer.close ();

				uint id = peer.connection_id;

				ConnectionEntry entry;
				connections.unset (id, out entry);

				Gee.Set<string> tags_to_remove = entry.tags;
				if (tags_to_remove != null) {
					foreach (string tag in tags_to_remove)
						tags.remove (tag, entry);
				}

				if (entry.parameters == cluster_params)
					node_disconnected (id, entry.address);
				else
					controller_disconnected (id, entry.address);
			}
		}

		private Peer setup_unauthorized_peer (uint connection_id, DBusConnection connection, EndpointParameters parameters) {
			var channel = new AuthenticationChannel (this, connection_id, connection, parameters);

			try {
				if (parameters == cluster_params) {
					PortalSession portal_session = new UnauthorizedPortalSession ();
					channel.take_registration (connection.register_object (ObjectPath.PORTAL_SESSION, portal_session));
				} else {
					HostSession host_session = new UnauthorizedHostSession ();
					channel.take_registration (connection.register_object (ObjectPath.HOST_SESSION, host_session));

					BusSession bus_session = new UnauthorizedBusSession ();
					channel.take_registration (connection.register_object (ObjectPath.BUS_SESSION, bus_session));
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			connection.start_message_processing ();

			return channel;
		}

		private async void promote_authentication_channel (AuthenticationChannel channel, string session_info) throws GLib.Error {
			uint connection_id = channel.connection_id;
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			channel.close ();

			peers[connection] = yield setup_authorized_peer (connection_id, connection, channel.parameters);

			authenticated (connection_id, session_info);
		}

		private void kick_authentication_channel (AuthenticationChannel channel) {
			var source = new IdleSource ();
			source.set_callback (() => {
				channel.connection.close.begin (io_cancellable);
				return false;
			});
			source.attach (MainContext.get_thread_default ());
		}

		private async Peer setup_authorized_peer (uint connection_id, DBusConnection connection,
				EndpointParameters parameters) throws GLib.Error {
			Peer peer;
			if (parameters == cluster_params)
				peer = yield setup_cluster_node (connection_id, connection);
			else
				peer = setup_control_channel (connection_id, connection);

			ConnectionEntry? entry = connections[peer.connection_id];
			if (entry == null)
				throw new Error.TRANSPORT ("Peer disconnected");
			entry.peer = peer;

			return peer;
		}

		private ControlChannel setup_control_channel (uint connection_id, DBusConnection connection) {
			var channel = new ControlChannel (this, connection_id, connection);

			connection.start_message_processing ();

			return channel;
		}

		private void teardown_control_channel (ControlChannel channel) {
			foreach (AgentSessionId id in channel.sessions) {
				AgentSessionEntry entry = sessions[id];

				AgentSession? session = entry.session;
				if (entry.persist_timeout == 0 || session == null) {
					sessions.unset (id);

					ClusterNode? node = entry.node;
					if (node != null)
						node.sessions.remove (id);

					if (session != null)
						session.close.begin (io_cancellable);
				} else {
					entry.detach_controller ();
					session.interrupt.begin (io_cancellable);
				}
			}

			disable_spawn_gating (channel);
		}

		private async ClusterNode setup_cluster_node (uint connection_id, DBusConnection connection) throws GLib.Error {
			var node = new ClusterNode (this, connection_id, connection);
			node.session_closed.connect (on_agent_session_closed);

			node.session_provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DO_NOT_LOAD_PROPERTIES,
				io_cancellable);

			connection.start_message_processing ();

			return node;
		}

		private void teardown_cluster_node (ClusterNode node) {
			var no_crash = CrashInfo.empty ();
			foreach (var id in node.sessions) {
				AgentSessionEntry entry = sessions[id];

				ControlChannel? c = entry.controller;
				if (c != null)
					c.sessions.remove (id);

				AgentSession? session = entry.session;
				if (entry.persist_timeout == 0 || session == null) {
					sessions.unset (id);
					if (c != null)
						c.agent_session_detached (id, SessionDetachReason.PROCESS_TERMINATED, no_crash);
				} else {
					entry.detach_node_and_controller ();
					if (c != null)
						c.agent_session_detached (id, SessionDetachReason.CONNECTION_TERMINATED, no_crash);
				}
			}

			Application? app = node.application;
			if (app != null) {
				uint pid = app.pid;

				node_left (node.connection_id, app);

				node_by_pid.unset (pid);
				node_by_identifier.unset (app.identifier);

				PendingSpawn spawn;
				if (pending_spawn.unset (pid, out spawn))
					notify_spawn_removed (spawn);
			}
		}

		private HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				ControlChannel requester) throws Error {
			var opts = ApplicationQueryOptions._deserialize (options);
			var scope = opts.scope;

			Gee.List<Application> apps = new Gee.ArrayList<Application> ();
			all_nodes_accessible_by (requester).foreach (node => {
				apps.add (node.application);
				return true;
			});
			apps = maybe_filter_apps_using_ids (apps, opts);

			var result = new HostApplicationInfo[apps.size];
			int i = 0;
			foreach (var app in apps) {
				result[i++] = HostApplicationInfo (app.identifier, app.name, app.pid,
					(scope != MINIMAL) ? app.parameters : make_parameters_dict ());
			}
			return result;
		}

		private HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options, ControlChannel requester) throws Error {
			var opts = ProcessQueryOptions._deserialize (options);
			var scope = opts.scope;

			Gee.List<Application> apps = new Gee.ArrayList<Application> ();
			all_nodes_accessible_by (requester).foreach (node => {
				apps.add (node.application);
				return true;
			});
			apps = maybe_filter_apps_using_pids (apps, opts);

			var result = new HostProcessInfo[apps.size];
			int i = 0;
			foreach (var app in apps) {
				result[i++] = HostProcessInfo (app.pid, app.name,
					(scope != MINIMAL) ? app.parameters : make_parameters_dict ());
			}
			return result;
		}

		private Gee.List<Application> maybe_filter_apps_using_ids (Gee.List<Application> apps, ApplicationQueryOptions options) {
			if (!options.has_selected_identifiers ())
				return apps;

			var app_by_identifier = new Gee.HashMap<string, Application> ();
			foreach (var app in apps)
				app_by_identifier[app.identifier] = app;

			var filtered_apps = new Gee.ArrayList<Application> ();
			options.enumerate_selected_identifiers (identifier => {
				Application? app = app_by_identifier[identifier];
				if (app != null)
					filtered_apps.add (app);
			});

			return filtered_apps;
		}

		private Gee.List<Application> maybe_filter_apps_using_pids (Gee.List<Application> apps, ProcessQueryOptions options) {
			if (!options.has_selected_pids ())
				return apps;

			var app_by_pid = new Gee.HashMap<uint, Application> ();
			foreach (Application app in apps)
				app_by_pid[app.pid] = app;

			var filtered_apps = new Gee.ArrayList<Application> ();
			options.enumerate_selected_pids (pid => {
				Application? app = app_by_pid[pid];
				if (app != null)
					filtered_apps.add (app);
			});

			return filtered_apps;
		}

		private void enable_spawn_gating (ControlChannel requester) {
			spawn_gaters.add (requester);
			foreach (PendingSpawn spawn in pending_spawn.values) {
				bool requester_has_access = find_node_accessible_by (requester, spawn.info.pid) != null;
				if (requester_has_access)
					spawn.pending_approvers.add (requester);
			}
		}

		private void disable_spawn_gating (ControlChannel requester) {
			if (spawn_gaters.remove (requester)) {
				foreach (uint pid in pending_spawn.keys.to_array ())
					resume (pid, requester);
			}
		}

		private HostSpawnInfo[] enumerate_pending_spawn (ControlChannel requester) {
			var result = new HostSpawnInfo[pending_spawn.size];
			int i = 0;
			foreach (PendingSpawn spawn in pending_spawn.values) {
				if (spawn.pending_approvers.contains (requester))
					result[i++] = spawn.info;
			}
			result.length = i;
			return result;
		}

		private void resume (uint pid, ControlChannel requester) {
			PendingSpawn? spawn = pending_spawn[pid];
			if (spawn == null)
				return;

			var approvers = spawn.pending_approvers;
			approvers.remove (requester);
			if (approvers.is_empty) {
				pending_spawn.unset (pid);

				ClusterNode? node = node_by_pid[pid];
				assert (node != null);
				node.resume ();

				notify_spawn_removed (spawn);
			}
		}

		private void kill (uint pid, ControlChannel requester) {
			ClusterNode? node = find_node_accessible_by (requester, pid);
			if (node == null)
				return;

			node.kill ();
		}

		private void handle_bus_attach (uint connection_id) {
			subscribe (connection_id);
		}

		private void handle_bus_message (uint connection_id, string json, Bytes? data) {
			message (connection_id, json, data);
		}

		private async AgentSessionId attach (uint pid, HashTable<string, Variant> options, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			ClusterNode? node = find_node_accessible_by (requester, pid);
			if (node == null)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			var id = AgentSessionId.generate ();

			yield node.open_session (id, options, cancellable);

			requester.sessions.add (id);

			var opts = SessionOptions._deserialize (options);

			var entry = new AgentSessionEntry (node, requester, id, opts.persist_timeout, io_cancellable);
			sessions[id] = entry;
			entry.expired.connect (on_agent_session_expired);

			yield link_session (id, entry, requester, cancellable);

			return id;
		}

		private async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry? entry = sessions[id];
			if (entry == null || entry.controller != null)
				throw new Error.INVALID_OPERATION ("Invalid session ID");
			if (entry.node == null)
				throw new Error.INVALID_OPERATION ("Cluster node is temporarily unavailable");

			entry.attach_controller (requester);
			requester.sessions.add (id);

			yield link_session (id, entry, requester, cancellable);
		}

		private async void link_session (AgentSessionId id, AgentSessionEntry entry, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			DBusConnection node_connection = entry.node.connection;

			AgentSession? session = entry.session;
			if (session == null) {
				try {
					session = yield node_connection.get_proxy (null, ObjectPath.for_agent_session (id),
						DO_NOT_LOAD_PROPERTIES, cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}
				entry.session = session;
			}

			DBusConnection? controller_connection = requester.connection;
			if (controller_connection != null) {
				AgentMessageSink sink;
				try {
					sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
						DO_NOT_LOAD_PROPERTIES, cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}

				try {
					entry.take_controller_registration (
						controller_connection.register_object (ObjectPath.for_agent_session (id), session));
					entry.take_node_registration (
						node_connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}
		}

		private async void handle_join_request (ClusterNode node, HostApplicationInfo app, SpawnStartState current_state,
				AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options, Cancellable? cancellable,
				out SpawnStartState next_state) throws Error, IOError {
			if (node.application != null)
				throw new Error.PROTOCOL ("Already joined");
			if (node.session_provider == null)
				throw new Error.PROTOCOL ("Missing session provider");

			Variant? acl = options["acl"];
			if (acl != null) {
				if (!acl.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'acl' option must be a string array");

				ConnectionEntry entry = connections[node.connection_id];

				Gee.Set<string>? tags = entry.tags;
				if (tags == null) {
					tags = new Gee.HashSet<string> ();
					entry.tags = tags;
				}
				tags.add_all_array (acl.get_strv ());
			}

			foreach (AgentSessionId id in interrupted_sessions) {
				AgentSessionEntry? entry = sessions[id];
				if (entry == null)
					continue;
				if (entry.node != null)
					throw new Error.PROTOCOL ("Session already claimed");
				entry.attach_node (node);
				node.sessions.add (id);
			}

			uint pid = app.pid;
			while (node_by_pid.has_key (pid))
				pid++;

			string real_identifier = app.identifier;
			string candidate = real_identifier;
			uint serial = 2;
			while (node_by_identifier.has_key (candidate))
				candidate = "%s[%u]".printf (real_identifier, serial++);
			string identifier = candidate;

			node.application = new Application (identifier, app.name, pid, app.parameters);

			node_by_pid[pid] = node;
			node_by_identifier[identifier] = node;

			node_joined (node.connection_id, node.application);

			if (current_state == SUSPENDED && !spawn_gaters.is_empty) {
				var eligible_gaters = all_spawn_gaters_with_access_to (node);
				if (eligible_gaters.has_next ()) {
					next_state = SUSPENDED;

					var spawn = new PendingSpawn (node, pid, identifier, eligible_gaters);
					pending_spawn[pid] = spawn;

					foreach (ControlChannel controller in spawn.pending_approvers) {
						controller.spawn_added (spawn.info);
					}
				} else {
					next_state = RUNNING;
				}
			} else {
				next_state = RUNNING;
			}
		}

		private void notify_spawn_removed (PendingSpawn spawn) {
			all_spawn_gaters_with_access_to (spawn.node).foreach (controller => {
				controller.spawn_removed (spawn.info);
				return true;
			});
		}

		private void on_agent_session_expired (AgentSessionEntry entry) {
			sessions.unset (entry.id);

			ClusterNode? node = entry.node;
			if (node != null)
				node.sessions.remove (entry.id);
		}

		private void on_agent_session_closed (AgentSessionId id) {
			AgentSessionEntry entry;
			if (sessions.unset (id, out entry)) {
				ControlChannel? controller = entry.controller;
				if (controller != null) {
					controller.sessions.remove (id);
					controller.agent_session_detached (id, SessionDetachReason.APPLICATION_REQUESTED,
						CrashInfo.empty ());
				}
			}
		}

		private Gee.Iterator<ClusterNode> all_nodes_accessible_by (ControlChannel requester) {
			if (requester.is_local)
				return node_by_pid.values.iterator ();

			Gee.Set<string>? requester_tags = connections[requester.connection_id].tags;
			return node_by_pid.values.filter (node => {
				ConnectionEntry entry = connections[node.connection_id];

				Gee.Set<string>? acl = entry.tags;
				if (acl == null)
					return true;

				if (requester_tags == null)
					return false;

				return acl.any_match (tag => requester_tags.contains (tag));
			});
		}

		private ClusterNode? find_node_accessible_by (ControlChannel requester, uint pid) {
			ClusterNode? node = node_by_pid[pid];
			if (node == null)
				return null;

			return can_access (node, requester) ? node : null;
		}

		private Gee.Iterator<ControlChannel> all_spawn_gaters_with_access_to (ClusterNode node) {
			Gee.Set<string>? acl = connections[node.connection_id].tags;
			if (acl == null)
				return spawn_gaters.iterator ();

			return spawn_gaters.filter (controller => {
				if (controller.is_local)
					return true;

				Gee.Set<string> tags = connections[controller.connection_id].tags;
				if (tags == null)
					return false;

				return acl.any_match (tag => tags.contains (tag));
			});
		}

		private bool can_access (ClusterNode node, ControlChannel requester) {
			if (requester.is_local)
				return true;

			Gee.Set<string>? acl = connections[node.connection_id].tags;
			if (acl == null)
				return true;

			Gee.Set<string> requester_tags = connections[requester.connection_id].tags;
			if (requester_tags == null)
				return false;

			return acl.any_match (tag => requester_tags.contains (tag));
		}

		private class PortalHostSessionProvider : Object, HostSessionProvider {
			public weak PortalService parent {
				get;
				construct;
			}

			public string id {
				get { return "portal"; }
			}

			public string name {
				get { return "Portal"; }
			}

			public Variant? icon {
				get { return _icon; }
			}
			private Variant _icon;

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL; }
			}

			private ControlChannel? channel;

			public PortalHostSessionProvider (PortalService parent) {
				Object (parent: parent);
			}

			construct {
				var builder = new VariantBuilder (VariantType.VARDICT);
				builder.add ("{sv}", "format", new Variant.string ("rgba"));
				builder.add ("{sv}", "width", new Variant.int64 (16));
				builder.add ("{sv}", "height", new Variant.int64 (16));
				var image = new Bytes (Base64.decode ("AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));
				builder.add ("{sv}", "image", Variant.new_from_data (new VariantType ("ay"), image.get_data (), true, image));
				_icon = builder.end ();
			}

			public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
				if (channel != null)
					throw new Error.INVALID_OPERATION ("Already created");

				channel = new ControlChannel (parent);
				channel.agent_session_detached.connect (on_agent_session_detached);

				return channel;
			}

			public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				channel.agent_session_detached.disconnect (on_agent_session_detached);

				HostSession session = channel;

				channel.close ();
				channel = null;

				host_session_detached (session);
			}

			public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
					Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				AgentSessionEntry entry = parent.sessions[id];
				if (entry == null)
					throw new Error.INVALID_ARGUMENT ("Invalid session ID");

				try {
					entry.take_node_registration (
						entry.node.connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}

				return entry.session;
			}

			private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
				agent_session_detached (id, reason, crash);
			}
		}

		private class ConnectionEntry {
			public DBusConnection connection;
			public SocketAddress address;
			public EndpointParameters parameters;
			public Peer? peer;
			public Gee.Set<string>? tags;

			public ConnectionEntry (DBusConnection connection, SocketAddress address, EndpointParameters parameters) {
				this.connection = connection;
				this.address = address;
				this.parameters = parameters;
			}

			public void post (string json, Bytes? data) {
				if (peer == null)
					return;

				ControlChannel? controller = peer as ControlChannel;
				if (controller == null)
					return;

				BusService bus = controller.bus;
				if (bus.status != ATTACHED)
					return;

				bool has_data = data != null;
				var data_param = has_data ? data.get_data () : new uint8[0];
				bus.message (json, has_data, data_param);
			}
		}

		private interface Peer : Object {
			public abstract uint connection_id {
				get;
				construct;
			}

			public abstract void close ();
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak PortalService parent {
				get;
				construct;
			}

			public uint connection_id {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construc
```