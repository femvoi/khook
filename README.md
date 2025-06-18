
## usage

### example hook
```cpp
NTSTATUS NtOpenProcess_Hook(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
) {
	hook::disable_hook(&NtOpenProcess_Hook);

	NTSTATUS status;

	if (ClientId) {
		ULONG pid = HandleToULong(ClientId->UniqueProcess);
		if (pid == 4000) {
			status = STATUS_ACCESS_DENIED;
			hook::enable_hook(&NtOpenProcess_Hook);
			return status;
		}
	}

	status = NtOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
	);

	hook::enable_hook(&NtOpenProcess_Hook);

	return status;
}

```

### creating hook


```cpp 
if (!hook::add_hook(NtOpenProcess, NtOpenProcess_Hook)) {
		DbgPrint("failed to add hook!");
		return STATUS_UNSUCCESSFUL;
}

hook::enable_hook(NtOpenProcess_Hook);

```

# any problems please open an issue.
