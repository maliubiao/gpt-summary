Response:
### 功能归纳

该源代码文件是Frida动态插桩工具的核心部分，主要负责处理会话（Session）相关的逻辑。以下是其主要功能的归纳：

1. **错误处理与异常抛出**：
   - `throw_api_error` 和 `throw_dbus_error` 函数用于处理API和DBus相关的错误，并将其转换为Frida特定的错误类型。
   - 这些函数在遇到特定错误时（如权限不足、超时、协议错误等）会抛出相应的异常。

2. **主机应用程序与进程信息管理**：
   - `HostApplicationInfo` 和 `HostProcessInfo` 结构体用于存储主机上运行的应用程序和进程的相关信息，如标识符、名称、PID等。
   - 这些信息通常用于在调试或插桩过程中识别和操作目标进程。

3. **查询选项管理**：
   - `FrontmostQueryOptions`、`ApplicationQueryOptions` 和 `ProcessQueryOptions` 类用于管理查询选项，如查询范围（Scope）、选择的标识符或PID等。
   - 这些选项通常用于在查询主机上的应用程序或进程时进行过滤和定制。

4. **进程生成与子进程管理**：
   - `HostSpawnOptions` 结构体用于配置生成新进程时的选项，如命令行参数、环境变量、工作目录等。
   - `HostChildInfo` 结构体用于存储子进程的相关信息，如PID、父进程PID、进程来源（fork、exec、spawn）等。

5. **会话选项管理**：
   - `SessionOptions` 类用于配置会话的选项，如会话的领域（Realm）、持久化超时、模拟代理路径等。
   - 这些选项通常用于在创建或管理会话时进行定制。

6. **脚本与快照管理**：
   - `ScriptOptions` 和 `SnapshotOptions` 类用于配置脚本和快照的选项，如脚本名称、快照数据、运行时环境等。
   - 这些选项通常用于在加载脚本或创建快照时进行定制。

7. **网络与中继管理**：
   - `PeerOptions` 和 `Relay` 类用于配置网络连接和中继选项，如STUN服务器、中继地址、用户名、密码等。
   - 这些选项通常用于在建立网络连接或配置中继时进行定制。

8. **系统参数获取**：
   - `compute_system_parameters` 函数用于获取系统参数，如操作系统类型、版本、架构等。
   - 这些参数通常用于在调试或插桩过程中识别目标系统的环境。

### 二进制底层与Linux内核相关

- **进程生成与子进程管理**：
  - `HostSpawnOptions` 和 `HostChildInfo` 结构体涉及到底层的进程生成和管理，如`fork`、`exec`、`spawn`等系统调用。
  - 例如，`HostSpawnOptions` 中的 `argv` 和 `envp` 字段对应于 `execve` 系统调用中的参数和环境变量。

- **系统参数获取**：
  - `compute_system_parameters` 函数通过读取系统文件（如 `/etc/os-release`）或调用系统API（如 `_query_windows_version`）来获取系统信息。
  - 例如，在Linux系统中，该函数会读取 `/etc/os-release` 文件来获取操作系统名称和版本。

### LLDB调试示例

假设我们想要调试 `throw_api_error` 函数，可以使用以下LLDB命令或Python脚本：

#### LLDB命令
```bash
# 设置断点
b throw_api_error

# 运行程序
run

# 当程序停在断点时，查看传入的错误对象
po e

# 继续执行
continue
```

#### LLDB Python脚本
```python
import lldb

def throw_api_error_debugger(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取传入的错误对象
    e = frame.FindVariable("e")
    print(f"Error object: {e}")

    # 继续执行
    process.Continue()

# 注册命令
debugger.HandleCommand('command script add -f throw_api_error_debugger throw_api_error_debugger')
```

### 假设输入与输出

- **输入**：一个 `GLib.Error` 对象，表示API调用失败。
- **输出**：抛出 `Frida.Error` 或 `IOError` 异常，具体取决于错误的类型。

### 用户常见错误示例

1. **权限不足**：
   - 用户尝试访问需要高权限的资源时，可能会触发 `PERMISSION_DENIED` 错误。
   - 例如，用户尝试附加到一个需要root权限的进程时，可能会遇到此错误。

2. **地址已被占用**：
   - 用户尝试绑定一个已被占用的端口时，可能会触发 `ADDRESS_IN_USE` 错误。
   - 例如，用户尝试启动一个Frida服务器，但端口已被其他进程占用。

3. **协议不匹配**：
   - 用户尝试与不兼容的Frida服务器通信时，可能会触发 `PROTOCOL` 错误。
   - 例如，用户使用的Frida客户端版本与服务器版本不匹配。

### 用户操作路径

1. **启动Frida会话**：
   - 用户通过Frida命令行工具或API启动一个会话。
   - 会话启动过程中可能会调用 `throw_api_error` 或 `throw_dbus_error` 函数来处理错误。

2. **查询主机应用程序或进程**：
   - 用户通过Frida API查询主机上运行的应用程序或进程。
   - 查询过程中可能会使用 `FrontmostQueryOptions`、`ApplicationQueryOptions` 或 `ProcessQueryOptions` 来定制查询。

3. **生成新进程**：
   - 用户通过Frida API生成一个新进程。
   - 生成过程中可能会使用 `HostSpawnOptions` 来配置进程的启动参数。

4. **加载脚本或快照**：
   - 用户通过Frida API加载一个脚本或快照。
   - 加载过程中可能会使用 `ScriptOptions` 或 `SnapshotOptions` 来定制脚本或快照的行为。

通过这些步骤，用户可以逐步深入到Frida的核心功能，并在遇到问题时通过调试工具进行排查。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/lib/base/session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
D_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}

	[NoReturn]
	public static void throw_api_error (GLib.Error e) throws Frida.Error, IOError {
		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		assert_not_reached ();
	}

	[NoReturn]
	public static void throw_dbus_error (GLib.Error e) throws Frida.Error, IOError {
		DBusError.strip_remote_error (e);

		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		if (e is DBusError.UNKNOWN_METHOD) {
			throw new Frida.Error.PROTOCOL ("Unable to communicate with remote frida-server; " +
				"please ensure that major versions match and that the remote Frida has the " +
				"feature you are trying to use");
		}

		throw new Frida.Error.TRANSPORT ("%s", e.message);
	}

	public struct HostApplicationInfo {
		public string identifier;
		public string name;
		public uint pid;
		public HashTable<string, Variant> parameters;

		public HostApplicationInfo (string identifier, string name, uint pid, owned HashTable<string, Variant> parameters) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.parameters = parameters;
		}

		public HostApplicationInfo.empty () {
			this.identifier = "";
			this.name = "";
			this.pid = 0;
			this.parameters = make_parameters_dict ();
		}
	}

	public struct HostProcessInfo {
		public uint pid;
		public string name;
		public HashTable<string, Variant> parameters;

		public HostProcessInfo (uint pid, string name, owned HashTable<string, Variant> parameters) {
			this.pid = pid;
			this.name = name;
			this.parameters = parameters;
		}
	}

	public class FrontmostQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static FrontmostQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new FrontmostQueryOptions ();

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ApplicationQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<string> identifiers = new Gee.ArrayList<string> ();

		public void select_identifier (string identifier) {
			identifiers.add (identifier);
		}

		public bool has_selected_identifiers () {
			return !identifiers.is_empty;
		}

		public void enumerate_selected_identifiers (Func<string> func) {
			foreach (var identifier in identifiers)
				func (identifier);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!identifiers.is_empty)
				dict["identifiers"] = identifiers.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ApplicationQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ApplicationQueryOptions ();

			Variant? identifiers = dict["identifiers"];
			if (identifiers != null) {
				if (!identifiers.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'identifiers' option must be a string array");
				var iter = identifiers.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_identifier (val.get_string ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ProcessQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<uint> pids = new Gee.ArrayList<uint> ();

		public void select_pid (uint pid) {
			pids.add (pid);
		}

		public bool has_selected_pids () {
			return !pids.is_empty;
		}

		public void enumerate_selected_pids (Func<uint> func) {
			foreach (var pid in pids)
				func (pid);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!pids.is_empty)
				dict["pids"] = pids.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ProcessQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ProcessQueryOptions ();

			Variant? pids = dict["pids"];
			if (pids != null) {
				if (!pids.is_of_type (new VariantType.array (VariantType.UINT32)))
					throw new Error.INVALID_ARGUMENT ("The 'pids' option must be a uint32 array");
				var iter = pids.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_pid (val.get_uint32 ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public enum Scope {
		MINIMAL,
		METADATA,
		FULL;

		public static Scope from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Scope> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Scope> (this);
		}
	}

	public struct HostSpawnOptions {
		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public bool has_env;
		public string[] env;

		public string cwd;

		public Stdio stdio;

		public HashTable<string, Variant> aux;

		public HostSpawnOptions () {
			this.argv = {};
			this.envp = {};
			this.env = {};
			this.cwd = "";
			this.stdio = INHERIT;
			this.aux = make_parameters_dict ();
		}

		public string[] compute_argv (string path) {
			return has_argv ? argv : new string[] { path };
		}

		public string[] compute_envp () {
			var base_env = has_envp ? envp : Environ.get ();
			if (!has_env)
				return base_env;

			var names = new Gee.ArrayList<string> ();
			var values = new Gee.HashMap<string, string> ();
			parse_envp (base_env, names, values);

			var overridden_names = new Gee.ArrayList<string> ();
			var overridden_values = new Gee.HashMap<string, string> ();
			parse_envp (env, overridden_names, overridden_values);

			foreach (var name in overridden_names) {
				if (!values.has_key (name))
					names.add (name);
				values[name] = overridden_values[name];
			}

			var result = new string[names.size];
			var i = 0;
			foreach (var name in names) {
				result[i] = name.concat ("=", values[name]);
				i++;
			}
			return result;
		}

		private static void parse_envp (string[] envp, Gee.ArrayList<string> names, Gee.HashMap<string, string> values) {
			foreach (var pair in envp) {
				var tokens = pair.split ("=", 2);
				if (tokens.length == 1)
					continue;
				var name = tokens[0];
				var val = tokens[1];
				names.add (name);
				values[name] = val;
			}
		}
	}

	public class SessionOptions : Object {
		public Realm realm {
			get;
			set;
			default = NATIVE;
		}

		public uint persist_timeout {
			get;
			set;
			default = 0;
		}

		public string? emulated_agent_path {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (realm != NATIVE)
				dict["realm"] = new Variant.string (realm.to_nick ());

			if (persist_timeout != 0)
				dict["persist-timeout"] = new Variant.uint32 (persist_timeout);

			if (emulated_agent_path != null)
				dict["emulated-agent-path"] = new Variant.string (emulated_agent_path);

			return dict;
		}

		public static SessionOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SessionOptions ();

			Variant? realm = dict["realm"];
			if (realm != null) {
				if (!realm.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'realm' option must be a string");
				options.realm = Realm.from_nick (realm.get_string ());
			}

			Variant? persist_timeout = dict["persist-timeout"];
			if (persist_timeout != null) {
				if (!persist_timeout.is_of_type (VariantType.UINT32))
					throw new Error.INVALID_ARGUMENT ("The 'persist-timeout' option must be a uint32");
				options.persist_timeout = persist_timeout.get_uint32 ();
			}

			Variant? path = dict["emulated-agent-path"];
			if (path != null) {
				if (!path.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'emulated-agent-path' option must be a string");
				options.emulated_agent_path = path.get_string ();
			}

			return options;
		}
	}

	public enum Stdio {
		INHERIT,
		PIPE;

		public static Stdio from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Stdio> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Stdio> (this);
		}
	}

	public struct HostSpawnInfo {
		public uint pid;
		public string identifier;

		public HostSpawnInfo (uint pid, string identifier) {
			this.pid = pid;
			this.identifier = identifier;
		}
	}

	public struct HostChildId {
		public uint handle;

		public HostChildId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (HostChildId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (HostChildId? a, HostChildId? b) {
			return a.handle == b.handle;
		}
	}

	public struct HostChildInfo {
		public uint pid;
		public uint parent_pid;

		public ChildOrigin origin;

		public string identifier;
		public string path;

		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public HostChildInfo (uint pid, uint parent_pid, ChildOrigin origin) {
			this.pid = pid;
			this.parent_pid = parent_pid;
			this.origin = origin;
			this.identifier = "";
			this.path = "";
			this.argv = {};
			this.envp = {};
		}
	}

	public enum ChildOrigin {
		FORK,
		EXEC,
		SPAWN;

		public static ChildOrigin from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ChildOrigin> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ChildOrigin> (this);
		}
	}

	public struct CrashInfo {
		public uint pid;
		public string process_name;

		public string summary;
		public string report;

		public HashTable<string, Variant> parameters;

		public CrashInfo (uint pid, string process_name, string summary, string report,
				HashTable<string, Variant>? parameters = null) {
			this.pid = pid;
			this.process_name = process_name;

			this.summary = summary;
			this.report = report;

			this.parameters = (parameters != null) ? parameters : make_parameters_dict ();
		}

		public CrashInfo.empty () {
			this.pid = 0;
			this.process_name = "";
			this.summary = "";
			this.report = "";
			this.parameters = make_parameters_dict ();
		}
	}

	public struct AgentSessionId {
		public string handle;

		public AgentSessionId (string handle) {
			this.handle = handle;
		}

		public AgentSessionId.generate () {
			this.handle = Uuid.string_random ().replace ("-", "");
		}

		public static uint hash (AgentSessionId? id) {
			return id.handle.hash ();
		}

		public static bool equal (AgentSessionId? a, AgentSessionId? b) {
			return a.handle == b.handle;
		}
	}

	public struct AgentScriptId {
		public uint handle;

		public AgentScriptId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (AgentScriptId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (AgentScriptId? a, AgentScriptId? b) {
			return a.handle == b.handle;
		}
	}

	public class ScriptOptions : Object {
		public string? name {
			get;
			set;
		}

		public Bytes? snapshot {
			get;
			set;
		}

		public SnapshotTransport snapshot_transport {
			get;
			set;
			default = INLINE;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (name != null)
				dict["name"] = new Variant.string (name);

			if (snapshot != null) {
				if (snapshot_transport == SHARED_MEMORY) {
					unowned uint8[]? data = snapshot.get_data ();
					dict["snapshot-memory-range"] = new Variant ("(tu)", (uint64) data, (uint) data.length);
				} else {
					dict["snapshot"] = Variant.new_from_data (new VariantType ("ay"), snapshot.get_data (), true, snapshot);
				}
			}

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static ScriptOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ScriptOptions ();

			Variant? name = dict["name"];
			if (name != null) {
				if (!name.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'name' option must be a string");
				options.name = name.get_string ();
			}

			Variant? snapshot = dict["snapshot"];
			if (snapshot != null) {
				if (!snapshot.is_of_type (new VariantType ("ay")))
					throw new Error.INVALID_ARGUMENT ("The 'snapshot' option must be a byte array");
				options.snapshot = snapshot.get_data_as_bytes ();
			} else {
				Variant? range = dict["snapshot-memory-range"];
				if (range != null) {
					if (!range.is_of_type (new VariantType ("(tu)")))
						throw new Error.INVALID_ARGUMENT ("The 'snapshot-memory-range' option must be a tuple");

					uint64 base_address;
					uint size;
					range.get ("(tu)", out base_address, out size);
					unowned uint8[]? data = ((uint8[]) (void *) base_address)[:size];

					options.snapshot = new Bytes.static (data);
				}
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum SnapshotTransport {
		INLINE,
		SHARED_MEMORY
	}

	public class SnapshotOptions : Object {
		public string? warmup_script {
			get;
			set;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (warmup_script != null)
				dict["warmup-script"] = new Variant.string (warmup_script);

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static SnapshotOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SnapshotOptions ();

			Variant? warmup_script = dict["warmup-script"];
			if (warmup_script != null) {
				if (!warmup_script.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'warmup-script' option must be a string");
				options.warmup_script = warmup_script.get_string ();
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum ScriptRuntime {
		DEFAULT,
		QJS,
		V8;

		public static ScriptRuntime from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ScriptRuntime> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ScriptRuntime> (this);
		}
	}

	public struct PortalMembershipId {
		public uint handle;

		public PortalMembershipId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (PortalMembershipId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (PortalMembershipId? a, PortalMembershipId? b) {
			return a.handle == b.handle;
		}
	}

	public class PortalOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}

		public string[]? acl {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (certificate != null)
				dict["certificate"] = new Variant.string (certificate.certificate_pem);

			if (token != null)
				dict["token"] = new Variant.string (token);

			if (acl != null)
				dict["acl"] = new Variant.strv (acl);

			return dict;
		}

		public static PortalOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PortalOptions ();

			Variant? cert_pem = dict["certificate"];
			if (cert_pem != null) {
				if (!cert_pem.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'certificate' option must be a string");
				try {
					options.certificate = new TlsCertificate.from_pem (cert_pem.get_string (), -1);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("%s", e.message);
				}
			}

			Variant? token = dict["token"];
			if (token != null) {
				if (!token.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'token' option must be a string");
				options.token = token.get_string ();
			}

			Variant? acl = dict["acl"];
			if (acl != null) {
				if (!acl.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'acl' option must be a string array");
				options.acl = acl.get_strv ();
			}

			return options;
		}
	}

	public class PeerOptions : Object {
		public string? stun_server {
			get;
			set;
		}

		private Gee.List<Relay> relays = new Gee.ArrayList<Relay> ();

		public void clear_relays () {
			relays.clear ();
		}

		public void add_relay (Relay relay) {
			relays.add (relay);
		}

		public void enumerate_relays (Func<Relay> func) {
			foreach (var relay in relays)
				func (relay);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (stun_server != null)
				dict["stun-server"] = new Variant.string (stun_server);

			if (!relays.is_empty) {
				var builder = new VariantBuilder (new VariantType.array (Relay.get_variant_type ()));
				foreach (var relay in relays)
					builder.add_value (relay.to_variant ());
				dict["relays"] = builder.end ();
			}

			return dict;
		}

		public static PeerOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PeerOptions ();

			Variant? stun_server = dict["stun-server"];
			if (stun_server != null) {
				if (!stun_server.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'stun-server' option must be a string");
				options.stun_server = stun_server.get_string ();
			}

			Variant? relays_val = dict["relays"];
			if (relays_val != null) {
				if (!relays_val.is_of_type (new VariantType.array (Relay.get_variant_type ())))
					throw new Error.INVALID_ARGUMENT ("The 'relays' option must be an array of tuples");
				var iter = relays_val.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.add_relay (Relay.from_variant (val));
			}

			return options;
		}
	}

	public class Relay : Object {
		public string address {
			get;
			construct;
		}

		public string username {
			get;
			construct;
		}

		public string password {
			get;
			construct;
		}

		public RelayKind kind {
			get;
			construct;
		}

		public Relay (string address, string username, string password, RelayKind kind) {
			Object (
				address: address,
				username: username,
				password: password,
				kind: kind
			);
		}

		internal static VariantType get_variant_type () {
			return new VariantType ("(sssu)");
		}

		internal Variant to_variant () {
			return new Variant ("(sssu)", address, username, password, (uint) kind);
		}

		internal static Relay from_variant (Variant val) {
			string address, username, password;
			uint kind;
			val.get ("(sssu)", out address, out username, out password, out kind);

			return new Relay (address, username, password, (RelayKind) kind);
		}
	}

	public enum RelayKind {
		TURN_UDP,
		TURN_TCP,
		TURN_TLS
	}

	public HashTable<string, Variant> make_parameters_dict () {
		return new HashTable<string, Variant> (str_hash, str_equal);
	}

	public HashTable<string, Variant> compute_system_parameters () {
		var parameters = new HashTable<string, Variant> (str_hash, str_equal);

		var os = new HashTable<string, Variant> (str_hash, str_equal);
		string id;
#if WINDOWS
		id = "windows";
#elif MACOS
		id = "macos";
#elif LINUX && !ANDROID
		id = "linux";
#elif IOS
		id = "ios";
#elif WATCHOS
		id = "watchos";
#elif TVOS
		id = "tvos";
#elif ANDROID
		id = "android";
#elif FREEBSD
		id = "freebsd";
#elif QNX
		id = "qnx";
#else
		id = FIXME;
#endif
		os["id"] = id;
#if WINDOWS
		os["name"] = "Windows";
		os["version"] = _query_windows_version ();
#elif DARWIN
		try {
			string plist;
			FileUtils.get_contents ("/System/Library/CoreServices/SystemVersion.plist", out plist);

			MatchInfo info;
			if (/<key>ProductName<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["name"] = info.fetch (1);
			}
			if (/<key>ProductVersion<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["version"] = info.fetch (1);
			}
		} catch (FileError e) {
		}
#elif LINUX && !ANDROID
		try {
			string details;
			FileUtils.get_contents ("/etc/os-release", out details);

			MatchInfo info;
			if (/^ID=(.+)$/m.match (details, 0, out info)) {
				os["id"] = Shell.unquote (info.fetch (1));
			}
			if (/^NAME=(.+)$/m.match (details, 0, out info)) {
				os["name"] = Shell.unquote (info.fetch (1));
			}
			if (/^VERSION_ID=(.+)$/m.match (details, 0, out info)) {
				os["version"] = Shell.unquote (info.fetch (1));
			}
		} catch (GLib.Error e) {
		}
#elif ANDROID
		os["name"] = "Android";
		os["version"] = _query_android_system_property ("ro.build.version.release");
#elif QNX
		os["name"] = "QNX";
#endif
		parameters["os"] = os;

		string platform;
#if WINDOWS
		platform = "windows";
#elif DARWIN
		platform = "darwin";
#elif LINUX
		platform = "linux";
#elif FREEBSD
		platform = "freebsd";
#elif QNX
		platform = "qnx";
#else
		platform = FIXME;
#endif
		parameters["platform"] = platform;

		string arch;
#if X86
		arch = "ia32";
#elif X86_64
		arch = "x64";
#elif ARM
		arch = "arm";
#elif ARM64
		arch = "arm64";
#elif MIPS
		arch = "mips";
#else
		arch = FIXME;
#endif
		parameters["arch"] = arch;

		parameters["access"] = "full";

#if WINDOWS
		parameters["name"] = _query_windows_computer_name ();
#elif IOS
		import_mg_property (parameters, "name", "UserAssignedDeviceName");
		import_mg_property (parameters, "udid", "UniqueDeviceID");

		add_interfaces (parameters);
#elif ANDROID
		parameters["api-level"] = int64.parse (_query_android_system_property ("ro.build.version.sdk"));
#else
		parameters["name"] = Environment.get_host_name ();
#endif

		return parameters;
	}

#if WINDOWS
	public extern string _query_windows_version ();
	public extern string _query_windows_computer_name ();
#elif IOS
	private void import_mg_property (HashTable<string, Variant> parameters, string key, string query) {
		string? val = try_resolve_mg_property (query);
		if (val != null)
			parameters[key] = val;
	}

	private void add_interfaces (HashTable<string, Variant> parameters) {
		var ifaces = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

		maybe_add_network_interface (ifaces, "ethernet", "EthernetMacAddress");
		maybe_add_network_interface (ifaces, "wifi", "WifiAddress");
		maybe_add_network_interface (ifaces, "bluetooth", "BluetoothAddress");

		string? phone = try_resolve_mg_property ("PhoneNumber");
		if (phone != null) {
			ifaces.open (VariantType.VARDICT);
			ifaces.add ("{sv}", "type", new Variant.string ("cellular"));
			ifaces.add ("{sv}", "phone-number", new Variant.string (phone));
			ifaces.close ();
		}

		parameters["interfaces"] = ifaces.end ();
	}

	private void maybe_add_network_interface (VariantBuilder ifaces, string type, string query) {
		string? address = try_resolve_mg_property (query);
		if (address == null)
			return;
		ifaces.open (VariantType.VARDICT);
		ifaces.add ("{sv}", "type", new Variant.string (type));
		ifaces.add ("{sv}", "address", new Variant.string (address));
		ifaces.close ();
	}

	private string? try_resolve_mg_property (string query) {
		var answer = _query_mobile_gestalt (query);
		if (answer == null || !answer.is_of_type (VariantType.STRING))
			return null;

		string val = answer.get_string ();
		if (val.length == 0)
			return null;

		return val;
	}

	public extern Variant? _query_mobile_gestalt (string query);
#elif ANDROID
	public extern string _query_android_system_property (string name);
#endif

	namespace ServerGuid {
		public const string HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461";
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
		public const string AGENT_CONTROLLER = "/re/frida/AgentController";
		public const string AGENT_MESSAGE_SINK = "/re/frida/AgentMessageSink";
		public const string CHILD_SESSION = "/re/frida/ChildSession";
		public const string TRANSPORT_BROKER = "/re/frida/TransportBroker";
		public const string PORTAL_SESSION = "/re/frida/PortalSession";
		public const string BUS_SESSION = "/re/frida/BusSession";
		public const string AUTHENTICATION_SERVICE = "/re/frida/AuthenticationService";

		public static string for_agent_session (AgentSessionId id) {
			return AGENT_SESSION + "/" + id.handle;
		}

		public static string for_agent_message_sink (AgentSessionId id) {
			return AGENT_MESSAGE_SINK + "/" + id.handle;
		}
	}

	namespace Marshal {
		public static T enum_from_nick<T> (string nick) throws Error {
			var klass = (EnumClass) typeof (T).class_ref ();
			var v = klass.get_value_by_nick (nick);
			if (v == null)
				throw new Error.INVALID_ARGUMENT ("Invalid %s", klass.get_type ().name ());
			return (T) v.value;
		}

		public static string enum_to_nick<T> (int val) {
			var klass = (EnumClass) typeof (T).class_ref ();
			return klass.get_value (val).value_nick;
		}
	}

	namespace Numeric {
		public uint int64_hash (int64? val) {
			uint64 v = (uint64) val.abs ();
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool int64_equal (int64? val_a, int64? val_b) {
			int64 a = val_a;
			int64 b = val_b;
			return a == b;
		}

		public uint uint64_hash (uint64? val) {
			uint64 v = val;
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool uint64_equal (uint64? val_a, uint64? val_b) {
			uint64 a = val_a;
			uint64 b = val_b;
			return a == b;
		}
	}
}

"""


```