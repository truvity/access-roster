package writerd

import (
	"encoding/base64"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// An entry of the log is RFC 8785 canonical JSON of one of two kinds (0029, "Sealing" and "Encryption").
//
// A record entry is the clear envelope of a record plus the record sealed under the tenant's evidence key. The
// envelope uses the OCSF names of the record (metadata.uid, time, metadata.tenant_uid, class_uid, activity_id,
// status_id, actor.user.type_id) and is a projection of the record computed before sealing, so a reader that opens
// the record can check the two agree. It leaves out metadata.event_code, which says more than the class does. The
// writer adds its stamps, "writer.instance" and "writer.recorded_at" (milliseconds), to the envelope and never to
// the record. The boundary and the project are the log's own, so no field names them.
//
// A seal entry ends every batch. It is in clear because it holds no tenant data: the number of records, of
// duplicates and of refusals of the batch, the writer instance, its stamp and the observed clock offset
// (REQ-AUDIT-017, REQ-AUDIT-036).
const (
	entryRecord = "record"
	entrySeal   = "seal"
)

// recordEntry builds the entry of one sealed record. tenant is the tenant the record was routed to (REQ-AUDIT-020:
// the operator's own tenant when the record names none).
func recordEntry(info recordInfo, tenant string, sealed []byte, instance string, recordedMS int64) ([]byte, error) {
	return audit.Canonical(map[string]any{
		"entry":       entryRecord,
		"time":        info.timeMS,
		"class_uid":   info.classUID,
		"activity_id": info.activityID,
		"status_id":   info.statusID,
		"actor":       map[string]any{"user": map[string]any{"type_id": info.actorTypeID}},
		"metadata":    map[string]any{"uid": info.uid, "tenant_uid": tenant},
		"sealed":      base64.StdEncoding.EncodeToString(sealed),
		"writer":      map[string]any{"instance": instance, "recorded_at": recordedMS},
	})
}

// clockObservation is what the writer saw of its clock when it sealed a batch.
type clockObservation struct {
	Observed     bool  // the kernel was asked and answered
	Synced       bool  // the kernel says its clock is synchronised
	OffsetMicros int64 // the kernel's estimate of the offset, in microseconds
}

func (c clockObservation) value() map[string]any {
	if !c.Observed {
		return map[string]any{"observed": false}
	}
	return map[string]any{"observed": true, "synced": c.Synced, "offset_us": c.OffsetMicros}
}

// batchCounts are the numbers a seal entry states.
type batchCounts struct{ records, duplicates, refused int }

// sealEntry builds the seal entry of a batch.
func sealEntry(n batchCounts, instance string, recordedMS int64, clock clockObservation) ([]byte, error) {
	return audit.Canonical(map[string]any{
		"entry":      entrySeal,
		"records":    int64(n.records),
		"duplicates": int64(n.duplicates),
		"refused":    int64(n.refused),
		"clock":      clock.value(),
		"writer":     map[string]any{"instance": instance, "recorded_at": recordedMS},
	})
}
