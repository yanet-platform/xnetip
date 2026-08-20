package xnetip

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// verifies that a semantic rejection wraps the sentinel alone and echoes
// the function name and the input in the message.
func Test_WrapParseError_WrapsSentinelAlone(t *testing.T) {
	err := wrapParseError("ParseIPv4Network", "10.0.0.0/33", ErrParse, nil)
	require.ErrorIs(t, err, ErrParse)
	require.Equal(t, `xnetip.ParseIPv4Network("10.0.0.0/33"): invalid address or network text`, err.Error())
}

// verifies that a rejection carrying a net/netip cause wraps both the
// sentinel and the cause, so each is visible to errors.Is.
func Test_WrapParseError_WrapsSentinelAndDetail(t *testing.T) {
	detail := errors.New("ParseAddr: detail")
	err := wrapParseError("ParseIPv6Network", "::1/", ErrParse, detail)
	require.ErrorIs(t, err, ErrParse)
	require.ErrorIs(t, err, detail)
	require.Equal(t, `xnetip.ParseIPv6Network("::1/"): invalid address or network text: ParseAddr: detail`, err.Error())
}
