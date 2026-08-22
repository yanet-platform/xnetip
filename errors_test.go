package xnetip

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// verifies that a semantic rejection wraps the sentinel alone and echoes
// the function name and the input in the message.
func Test_WrapParseError_WrapsSentinelAlone(t *testing.T) {
	err := wrapParseError("ParseNetwork4", "10.0.0.0/33", ErrParse, nil)
	require.ErrorIs(t, err, ErrParse)
	require.Equal(t, `xnetip.ParseNetwork4("10.0.0.0/33"): invalid address or network text`, err.Error())
}

// verifies that a rejection carrying a net/netip cause wraps both the
// sentinel and the cause, so each is visible to errors.Is.
func Test_WrapParseError_WrapsSentinelAndDetail(t *testing.T) {
	detail := errors.New("ParseAddr: detail")
	err := wrapParseError("ParseNetwork6", "::1/", ErrParse, detail)
	require.ErrorIs(t, err, ErrParse)
	require.ErrorIs(t, err, detail)
	require.Equal(t, `xnetip.ParseNetwork6("::1/"): invalid address or network text: ParseAddr: detail`, err.Error())
}

// verifies that every package sentinel and both cause shapes retain the
// exact message produced by the eager formatter.
func Test_WrapParseError_RendersByteIdenticalMessages(t *testing.T) {
	cases := []struct {
		name     string
		function string
		input    string
		sentinel error
		detail   error
		want     string
	}{
		{
			name:     "parse error with netip detail and escaped input",
			function: "ParseNetwork",
			input:    "bad\n\"\\",
			sentinel: ErrParse,
			detail:   errors.New(`ParseAddr("bad"): unable to parse IP`),
			want:     `xnetip.ParseNetwork("bad\n\"\\"): invalid address or network text: ParseAddr("bad"): unable to parse IP`,
		},
		{
			name:     "address family mismatch without detail",
			function: "Network4From",
			input:    "2001:db8::1/255.255.255.0",
			sentinel: ErrAddrFamilyMismatch,
			want:     `xnetip.Network4From("2001:db8::1/255.255.255.0"): address family mismatch`,
		},
		{
			name:     "zone rejection without detail",
			function: "ParseNetwork6",
			input:    "fe80::1%eth0/64",
			sentinel: ErrZone,
			want:     `xnetip.ParseNetwork6("fe80::1%eth0/64"): zone not allowed`,
		},
		{
			name:     "prefix overflow without detail",
			function: "Network4FromCIDR",
			input:    "10.0.0.1/33",
			sentinel: ErrCIDROverflow,
			want:     `xnetip.Network4FromCIDR("10.0.0.1/33"): prefix length out of range`,
		},
		{
			name:     "invalid mask with family detail",
			function: "ParseNetwork4",
			input:    "10.0.0.0/ffff::",
			sentinel: ErrInvalidMask,
			detail:   ErrAddrFamilyMismatch,
			want:     `xnetip.ParseNetwork4("10.0.0.0/ffff::"): invalid network mask: address family mismatch`,
		},
		{
			name:     "non-contiguous mask without detail",
			function: "ParseContiguous4",
			input:    "10.0.0.0/255.0.255.0",
			sentinel: ErrNonContiguousMask,
			want:     `xnetip.ParseContiguous4("10.0.0.0/255.0.255.0"): mask not contiguous`,
		},
		{
			name:     "non-bi-contiguous mask without detail",
			function: "ParseBiContiguous",
			input:    "::/ffff:0:ffff::",
			sentinel: ErrNonBiContiguousMask,
			want:     `xnetip.ParseBiContiguous("::/ffff:0:ffff::"): mask not bi-contiguous`,
		},
		{
			name:     "empty input without detail",
			function: "Network.UnmarshalText",
			input:    "",
			sentinel: ErrEmptyInput,
			want:     `xnetip.Network.UnmarshalText(""): empty input`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := wrapParseError(
				testCase.function,
				testCase.input,
				testCase.sentinel,
				testCase.detail,
			)
			require.Equal(t, testCase.want, err.Error())
		})
	}
}

// verifies that multi-cause traversal exposes exactly the sentinel and
// optional detail while a single-cause rejection never gains a nil cause.
func Test_WrapParseError_ErrorsIsMatrix(t *testing.T) {
	detail := errors.New("detail")
	withDetail := wrapParseError("ParseNetwork", "bad", ErrParse, detail)
	withoutDetail := wrapParseError("ParseNetwork6", "fe80::1%eth0", ErrZone, nil)
	cases := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{name: "detail shape matches sentinel", err: withDetail, target: ErrParse, want: true},
		{name: "detail shape matches detail", err: withDetail, target: detail, want: true},
		{name: "detail shape rejects unrelated sentinel", err: withDetail, target: ErrZone, want: false},
		{name: "single shape matches sentinel", err: withoutDetail, target: ErrZone, want: true},
		{name: "single shape rejects unrelated sentinel", err: withoutDetail, target: ErrParse, want: false},
		{name: "single shape rejects nil target", err: withoutDetail, target: nil, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, errors.Is(testCase.err, testCase.target))
		})
	}
}

// verifies that the multi-error view contains only the sentinel when no
// detailed cause exists.
func Test_ParseError_Unwrap_OmitsNilDetail(t *testing.T) {
	err := wrapParseError("ParseNetwork6", "fe80::1%eth0", ErrZone, nil)
	require.Equal(t, []error{ErrZone}, err.(*parseError).Unwrap())
}

// verifies that the concrete net/netip parse failure remains reachable
// through errors.As when it is the detailed cause.
func Test_WrapParseError_ErrorsAsReachesNetipDetail(t *testing.T) {
	_, detail := netip.ParseAddr("01.2.3.4")
	require.Error(t, detail)

	err := wrapParseError("ParseNetwork4", "01.2.3.4/8", ErrParse, detail)
	target := reflect.New(reflect.TypeOf(detail))
	require.ErrorAs(t, err, target.Interface())
	matched := target.Elem().Interface().(error)
	require.Equal(t, detail.Error(), matched.Error())
}

// verifies that construction does not render either cause and every
// message request renders the current causes afresh.
func Test_WrapParseError_DefersRendering(t *testing.T) {
	detail := &renderProbeError{}
	err := wrapParseError("ParseNetwork", "bad", ErrParse, detail)
	require.Zero(t, detail.renders)

	want := `xnetip.ParseNetwork("bad"): invalid address or network text: detail`
	require.Equal(t, want, err.Error())
	require.Equal(t, 1, detail.renders)
	require.Equal(t, want, err.Error())
	require.Equal(t, 2, detail.renders)
}

// verifies that immutable deferred errors render identical messages when
// requested concurrently.
func Test_WrapParseError_RendersConcurrently(t *testing.T) {
	err := wrapParseError("ParseNetwork", "bad", ErrParse, errors.New("detail"))
	const workers = 32
	rendered := make([]string, workers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for idx := range workers {
		go func() {
			defer waitGroup.Done()
			rendered[idx] = err.Error()
		}()
	}
	waitGroup.Wait()

	want := `xnetip.ParseNetwork("bad"): invalid address or network text: detail`
	for _, message := range rendered {
		require.Equal(t, want, message)
	}
}

// verifies that arbitrary function and input strings render exactly like
// the former eager formatter for both cause shapes.
func Test_WrapParseError_MatchesFmtReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		function := rapid.String().Draw(t, "function")
		input := rapid.String().Draw(t, "input")
		hasDetail := rapid.Bool().Draw(t, "has detail")
		sentinel := errors.New("sentinel")
		var detail error
		if hasDetail {
			detail = errors.New("detail")
		}

		got := wrapParseError(function, input, sentinel, detail).Error()
		var want string
		if detail == nil {
			want = fmt.Errorf("xnetip.%s(%q): %w", function, input, sentinel).Error()
		} else {
			want = fmt.Errorf("xnetip.%s(%q): %w: %w", function, input, sentinel, detail).Error()
		}
		require.Equal(t, want, got)
	})
}

type renderProbeError struct {
	renders int
}

func (m *renderProbeError) Error() string {
	m.renders++
	return "detail"
}
