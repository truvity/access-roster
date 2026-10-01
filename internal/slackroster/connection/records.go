package connection

// RecordsSecretName is the Secret holding a recovery MIRROR of the records
// ConfigMap: exactly its `<workspace>.json`, `_shared.<name>.json` and
// `_channel.<workspace>.<name>.json` entries. The ConfigMap cannot be the thing an External Secrets PushSecret
// copies, because a PushSecret reads Secrets only, so the service keeps this
// one beside it for the chart to copy.
func RecordsSecretName(release string) string { return release + "-slack-records" }

// Mirrored reports whether a key of the records ConfigMap belongs in the
// mirror: a workspace's own record, a shared channel's definition or a
// console channel's record. An
// operator's confirmation (`_confirm.*`) and a pass marker (`_pass.*`) are
// transient and are deliberately left out.
func Mirrored(key string) bool {
	if _, ok := ParseSharedKey(key); ok {
		return true
	}
	if _, _, ok := ParseConsoleKey(key); ok {
		return true
	}
	if Reserved(key) {
		return false
	}
	_, ok := WorkspaceOfKey(key)
	return ok
}
