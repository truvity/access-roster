package lambdaext

import (
	"encoding/binary"
	"math"
)

// The extension writes the OTLP logs protobuf by hand. The generated
// packages (and the protobuf runtime behind them) add about 6.7 MB to a
// binary that is 10 MB, and the part of the schema used here is small and
// frozen: opentelemetry/proto/{collector/logs,logs,common,resource}/v1.

// OTLP severity numbers.
const (
	SeverityDebug int32 = 5
	SeverityInfo  int32 = 9
	SeverityWarn  int32 = 13
	SeverityError int32 = 17
	SeverityFatal int32 = 21
)

// Attr is a key with a string, integer or double value.
type Attr struct {
	Key   string
	Kind  AttrKind
	Str   string
	Int   int64
	Float float64
}

// AttrKind says which of Attr's value fields is set.
type AttrKind uint8

// Attribute value kinds.
const (
	KindString AttrKind = iota
	KindInt
	KindFloat
)

func strAttr(k, v string) Attr       { return Attr{Key: k, Kind: KindString, Str: v} }
func intAttr(k string, v int64) Attr { return Attr{Key: k, Kind: KindInt, Int: v} }
func floatAttr(k string, v float64) Attr {
	return Attr{Key: k, Kind: KindFloat, Float: v}
}

// LogRecord is one OTLP log record.
type LogRecord struct {
	TimeUnixNano, ObservedTimeUnixNano uint64
	Severity                           int32
	Body                               string
	Attrs                              []Attr
	TraceID, SpanID                    []byte
	Flags                              uint32
}

// severityText is the OTLP short name of a severity number.
func severityText(n int32) string {
	switch {
	case n >= SeverityFatal:
		return "FATAL"
	case n >= SeverityError:
		return "ERROR"
	case n >= SeverityWarn:
		return "WARN"
	case n >= SeverityInfo:
		return "INFO"
	}
	return "DEBUG"
}

// Wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

func appendTag(b []byte, field, wire int) []byte {
	return binary.AppendUvarint(b, uint64(field)<<3|uint64(wire)) //nolint:gosec // small constants
}

func appendBytes(b []byte, field int, v []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendString(b []byte, field int, v string) []byte {
	b = appendTag(b, field, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendVarint(b []byte, field int, v uint64) []byte {
	return binary.AppendUvarint(appendTag(b, field, wireVarint), v)
}

func appendAttr(b []byte, field int, a Attr) []byte {
	var v []byte // AnyValue
	switch a.Kind {
	case KindInt:
		v = appendVarint(v, 3, uint64(a.Int)) //nolint:gosec // int64 is two's complement on the wire
	case KindFloat:
		v = appendTag(v, 4, wireI64)
		v = binary.LittleEndian.AppendUint64(v, math.Float64bits(a.Float))
	default:
		v = appendString(v, 1, a.Str)
	}
	kv := appendString(nil, 1, a.Key)
	kv = appendBytes(kv, 2, v)
	return appendBytes(b, field, kv)
}

func appendRecord(b []byte, r *LogRecord) []byte {
	var m []byte
	if r.TimeUnixNano != 0 {
		m = appendTag(m, 1, wireI64)
		m = binary.LittleEndian.AppendUint64(m, r.TimeUnixNano)
	}
	m = appendVarint(m, 2, uint64(r.Severity)) //nolint:gosec // positive constants
	m = appendString(m, 3, severityText(r.Severity))
	m = appendBytes(m, 5, appendString(nil, 1, r.Body)) // AnyValue{string_value}
	for _, a := range r.Attrs {
		m = appendAttr(m, 6, a)
	}
	if r.Flags != 0 {
		m = appendTag(m, 8, wireI32)
		m = binary.LittleEndian.AppendUint32(m, r.Flags)
	}
	if len(r.TraceID) > 0 {
		m = appendBytes(m, 9, r.TraceID)
	}
	if len(r.SpanID) > 0 {
		m = appendBytes(m, 10, r.SpanID)
	}
	if r.ObservedTimeUnixNano != 0 {
		m = appendTag(m, 11, wireI64)
		m = binary.LittleEndian.AppendUint64(m, r.ObservedTimeUnixNano)
	}
	return appendBytes(b, 2, m) // ScopeLogs.log_records
}

// EncodeLogs is an ExportLogsServiceRequest with one ResourceLogs and one
// ScopeLogs holding recs.
func EncodeLogs(resource []Attr, recs []*LogRecord) []byte {
	var res []byte
	for _, a := range resource {
		res = appendAttr(res, 1, a)
	}
	scope := appendBytes(nil, 1, appendString(nil, 1, "access-roster-lambda-telemetry"))
	for _, r := range recs {
		scope = appendRecord(scope, r)
	}
	rl := appendBytes(nil, 1, res)
	rl = appendBytes(rl, 2, scope)
	return appendBytes(nil, 1, rl)
}
