package lambdaext

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TelemetryEvent is one element of a batch the Telemetry API POSTs
// (schema 2022-12-13). Record is an object for platform events and a string
// (or, for JSON-formatted functions, an object) for function and extension
// logs.
type TelemetryEvent struct {
	Time   string          `json:"time"`
	Type   string          `json:"type"`
	Record json.RawMessage `json:"record"`
}

// platformRecord is the union of the fields platform.* records carry.
type platformRecord struct {
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Version   string `json:"version"`
	Metrics   struct {
		DurationMs        *float64 `json:"durationMs"`
		BilledDurationMs  *float64 `json:"billedDurationMs"`
		MemorySizeMB      *float64 `json:"memorySizeMB"`
		MaxMemoryUsedMB   *float64 `json:"maxMemoryUsedMB"`
		InitDurationMs    *float64 `json:"initDurationMs"`
		RestoreDurationMs *float64 `json:"restoreDurationMs"`
		ProducedBytes     *float64 `json:"producedBytes"`
	} `json:"metrics"`
	Tracing struct {
		SpanID string `json:"spanId"`
		Type   string `json:"type"`
		Value  string `json:"value"`
	} `json:"tracing"`
	InitializationType string `json:"initializationType"`
	Phase              string `json:"phase"`
	RuntimeVersion     string `json:"runtimeVersion"`
	// platform.logsDropped
	DroppedBytes   *float64 `json:"droppedBytes"`
	DroppedRecords *float64 `json:"droppedRecords"`
	Reason         string   `json:"reason"`
	// platform.telemetrySubscription
	Name  string   `json:"name"`
	State string   `json:"state"`
	Types []string `json:"types"`
}

// Resource builds the OTLP resource every record of this function carries.
func Resource(getenv func(string) string) []Attr {
	fn := getenv("AWS_LAMBDA_FUNCTION_NAME")
	service := strings.TrimSpace(getenv("OTEL_SERVICE_NAME"))
	if service == "" {
		service = fn
	}
	var attrs []Attr
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, strAttr(k, v))
		}
	}
	add("service.name", service)
	add("cloud.provider", "aws")
	add("cloud.platform", "aws_lambda")
	add("cloud.region", getenv("AWS_REGION"))
	add("faas.name", fn)
	add("faas.version", getenv("AWS_LAMBDA_FUNCTION_VERSION"))
	add("faas.instance", getenv("AWS_LAMBDA_LOG_STREAM_NAME"))
	if mem, err := strconv.ParseInt(getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"), 10, 64); err == nil {
		attrs = append(attrs, intAttr("faas.max_memory", mem<<20))
	}
	return attrs
}

// MapEvent turns one Telemetry API event into an OTLP log record. ok is
// false for an event that carries nothing worth storing (an unknown type or
// an unparsable record); the caller drops those.
func MapEvent(ev TelemetryEvent, now time.Time) (rec *LogRecord, ok bool) {
	ts := now
	if t, err := time.Parse(time.RFC3339Nano, ev.Time); err == nil {
		ts = t
	}
	rec = &LogRecord{
		TimeUnixNano:         uint64(ts.UnixNano()),  //nolint:gosec // a post-1970 time
		ObservedTimeUnixNano: uint64(now.UnixNano()), //nolint:gosec // same
		Severity:             SeverityInfo,
		Attrs:                []Attr{strAttr("event.name", ev.Type)},
	}
	switch {
	case strings.HasPrefix(ev.Type, "platform."):
		var p platformRecord
		if err := json.Unmarshal(ev.Record, &p); err != nil {
			return nil, false
		}
		mapPlatform(rec, ev.Type, &p)
		return rec, true
	case ev.Type == "function" || ev.Type == "extension":
		mapPlain(rec, ev.Record)
		return rec, true
	}
	return nil, false
}

// failed reports whether a platform record describes something going wrong:
// a status other than success, or an errorType (Runtime.OutOfMemory,
// Runtime.ExitError, Task.Timedout, Extension.*, ...).
func (p *platformRecord) failed() bool {
	return (p.Status != "" && p.Status != "success") || p.ErrorType != ""
}

func mapPlatform(rec *LogRecord, typ string, p *platformRecord) {
	add := func(kv Attr) { rec.Attrs = append(rec.Attrs, kv) }
	str := func(k, v string) {
		if v != "" {
			add(strAttr(k, v))
		}
	}
	num := func(k string, v *float64) {
		if v != nil {
			add(floatAttr(k, *v))
		}
	}
	str("requestId", p.RequestID)
	str("faas.invocation_id", p.RequestID)
	str("status", p.Status)
	str("errorType", p.ErrorType)
	str("initializationType", p.InitializationType)
	str("phase", p.Phase)
	num("durationMs", p.Metrics.DurationMs)
	num("billedDurationMs", p.Metrics.BilledDurationMs)
	num("memorySizeMB", p.Metrics.MemorySizeMB)
	num("maxMemoryUsedMB", p.Metrics.MaxMemoryUsedMB)
	num("initDurationMs", p.Metrics.InitDurationMs)
	num("restoreDurationMs", p.Metrics.RestoreDurationMs)
	num("producedBytes", p.Metrics.ProducedBytes)
	if p.failed() {
		rec.Severity = SeverityError
	}
	rec.TraceID, rec.SpanID, rec.Flags = traceContext(p)

	var b strings.Builder
	head := strings.ToUpper(strings.TrimPrefix(typ, "platform."))
	switch typ {
	case "platform.start":
		fmt.Fprintf(&b, "START RequestId: %s Version: %s", p.RequestID, p.Version)
	case "platform.runtimeDone":
		fmt.Fprintf(&b, "RUNTIME_DONE RequestId: %s Status: %s", p.RequestID, p.Status)
	case "platform.report":
		fmt.Fprintf(&b, "REPORT RequestId: %s", p.RequestID)
		metric(&b, "Duration", p.Metrics.DurationMs, "ms")
		metric(&b, "Billed Duration", p.Metrics.BilledDurationMs, "ms")
		metric(&b, "Memory Size", p.Metrics.MemorySizeMB, "MB")
		metric(&b, "Max Memory Used", p.Metrics.MaxMemoryUsedMB, "MB")
		metric(&b, "Init Duration", p.Metrics.InitDurationMs, "ms")
		metric(&b, "Restore Duration", p.Metrics.RestoreDurationMs, "ms")
		if p.Status != "" {
			fmt.Fprintf(&b, " Status: %s", p.Status)
		}
	case "platform.initStart":
		fmt.Fprintf(&b, "INIT_START Runtime Version: %s Phase: %s", p.RuntimeVersion, p.Phase)
	case "platform.initRuntimeDone":
		fmt.Fprintf(&b, "INIT_RUNTIME_DONE Phase: %s Status: %s", p.Phase, p.Status)
	case "platform.initReport":
		fmt.Fprintf(&b, "INIT_REPORT Phase: %s Status: %s", p.Phase, p.Status)
		metric(&b, "Duration", p.Metrics.DurationMs, "ms")
	case "platform.restoreStart":
		fmt.Fprintf(&b, "RESTORE_START Runtime Version: %s", p.RuntimeVersion)
	case "platform.restoreRuntimeDone":
		fmt.Fprintf(&b, "RESTORE_RUNTIME_DONE Status: %s", p.Status)
	case "platform.restoreReport":
		fmt.Fprintf(&b, "RESTORE_REPORT Status: %s", p.Status)
		metric(&b, "Duration", p.Metrics.DurationMs, "ms")
	case "platform.logsDropped":
		rec.Severity = SeverityWarn
		num("droppedRecords", p.DroppedRecords)
		num("droppedBytes", p.DroppedBytes)
		fmt.Fprintf(&b, "LOGS_DROPPED Reason: %s", p.Reason)
		metric(&b, "Dropped Records", p.DroppedRecords, "")
	case "platform.telemetrySubscription":
		fmt.Fprintf(&b, "TELEMETRY_SUBSCRIPTION %s State: %s Types: %s", p.Name, p.State, strings.Join(p.Types, ","))
	default:
		b.WriteString(head)
		if p.Status != "" {
			fmt.Fprintf(&b, " Status: %s", p.Status)
		}
	}
	if p.ErrorType != "" {
		fmt.Fprintf(&b, " ErrorType: %s", p.ErrorType)
	}
	rec.Body = b.String()
}

func metric(b *strings.Builder, name string, v *float64, unit string) {
	if v == nil {
		return
	}
	fmt.Fprintf(b, " %s: %s", name, strconv.FormatFloat(*v, 'f', -1, 64))
	if unit != "" {
		b.WriteString(" " + unit)
	}
}

// traceContext extracts the trace id from tracing.value
// ("Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;
// Sampled=1") and the span from tracing.spanId, else Parent. Anything that
// does not parse yields no correlation, never an error.
func traceContext(p *platformRecord) (traceID, spanID []byte, flags uint32) {
	var parent string
	for part := range strings.SplitSeq(p.Tracing.Value, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "Root":
			// "1-<8 hex time>-<24 hex id>" is the 32 hex digits of a trace id.
			if segs := strings.Split(v, "-"); len(segs) == 3 && len(segs[1]) == 8 && len(segs[2]) == 24 {
				if b, err := hex.DecodeString(segs[1] + segs[2]); err == nil {
					traceID = b
				}
			}
		case "Parent":
			parent = v
		case "Sampled":
			if v == "1" {
				flags = 1
			}
		}
	}
	if traceID == nil {
		return nil, nil, 0
	}
	for _, s := range []string{p.Tracing.SpanID, parent} {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 8 {
			spanID = b
			break
		}
	}
	return traceID, spanID, flags
}

// mapPlain maps a function or extension log line. The record is a string, or
// an object for a function configured to log JSON (timestamp, level,
// message); the level, when there is one, sets the severity.
func mapPlain(rec *LogRecord, raw json.RawMessage) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		s = strings.TrimRight(s, "\n")
		rec.Body = s
		return
	}
	var obj struct {
		Level     string `json:"level"`
		Message   any    `json:"message"`
		RequestID string `json:"requestId"`
	}
	text := string(raw)
	if json.Unmarshal(raw, &obj) == nil {
		switch strings.ToUpper(obj.Level) {
		case "TRACE", "DEBUG":
			rec.Severity = SeverityDebug
		case "WARN", "WARNING":
			rec.Severity = SeverityWarn
		case "ERROR":
			rec.Severity = SeverityError
		case "FATAL", "CRITICAL":
			rec.Severity = SeverityFatal
		}
		if m, ok := obj.Message.(string); ok {
			text = m
		}
		if obj.RequestID != "" {
			rec.Attrs = append(rec.Attrs, strAttr("requestId", obj.RequestID), strAttr("faas.invocation_id", obj.RequestID))
		}
	}
	rec.Body = text
}
