package daemon_test

import (
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/assert"
)

func TestProtocolConstants(t *testing.T) {
	t.Run("ClientMagic", func(t *testing.T) {
		assert.Equal(t, uint64(0x6e697863), daemon.ClientMagic)
	})

	t.Run("ServerMagic", func(t *testing.T) {
		assert.Equal(t, uint64(0x6478696f), daemon.ServerMagic)
	})

	t.Run("ProtocolVersion", func(t *testing.T) {
		assert.Equal(t, uint64(0x0125), daemon.ProtocolVersion)
		// Version 1.37 => major=1, minor=37
		assert.Equal(t, uint64(1), daemon.ProtocolVersion>>8)
		assert.Equal(t, uint64(37), daemon.ProtocolVersion&0xff)
	})
}

func TestOperationCodes(t *testing.T) {
	tests := []struct {
		name string
		op   daemon.Operation
		want uint64
	}{
		{"OpIsValidPath", daemon.OpIsValidPath, 1},
		{"OpQueryReferrers", daemon.OpQueryReferrers, 6},
		{"OpAddToStore", daemon.OpAddToStore, 7},
		{"OpBuildPaths", daemon.OpBuildPaths, 9},
		{"OpEnsurePath", daemon.OpEnsurePath, 10},
		{"OpAddTempRoot", daemon.OpAddTempRoot, 11},
		{"OpAddIndirectRoot", daemon.OpAddIndirectRoot, 12},
		{"OpFindRoots", daemon.OpFindRoots, 14},
		{"OpSetOptions", daemon.OpSetOptions, 19},
		{"OpCollectGarbage", daemon.OpCollectGarbage, 20},
		{"OpQueryAllValidPaths", daemon.OpQueryAllValidPaths, 23},
		{"OpQueryPathInfo", daemon.OpQueryPathInfo, 26},
		{"OpQueryPathFromHashPart", daemon.OpQueryPathFromHashPart, 29},
		{"OpQueryValidPaths", daemon.OpQueryValidPaths, 31},
		{"OpQuerySubstitutablePaths", daemon.OpQuerySubstitutablePaths, 32},
		{"OpQueryValidDerivers", daemon.OpQueryValidDerivers, 33},
		{"OpOptimiseStore", daemon.OpOptimiseStore, 34},
		{"OpVerifyStore", daemon.OpVerifyStore, 35},
		{"OpBuildDerivation", daemon.OpBuildDerivation, 36},
		{"OpAddSignatures", daemon.OpAddSignatures, 37},
		{"OpNarFromPath", daemon.OpNarFromPath, 38},
		{"OpAddToStoreNar", daemon.OpAddToStoreNar, 39},
		{"OpQueryMissing", daemon.OpQueryMissing, 40},
		{"OpQueryDerivationOutputMap", daemon.OpQueryDerivationOutputMap, 41},
		{"OpRegisterDrvOutput", daemon.OpRegisterDrvOutput, 42},
		{"OpQueryRealisation", daemon.OpQueryRealisation, 43},
		{"OpAddMultipleToStore", daemon.OpAddMultipleToStore, 44},
		{"OpAddBuildLog", daemon.OpAddBuildLog, 45},
		{"OpBuildPathsWithResults", daemon.OpBuildPathsWithResults, 46},
		{"OpAddPermRoot", daemon.OpAddPermRoot, 47},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, daemon.Operation(tt.want), tt.op)
		})
	}
}

func TestOperationString(t *testing.T) {
	assert.Equal(t, "IsValidPath", daemon.OpIsValidPath.String())
	assert.Equal(t, "QueryPathInfo", daemon.OpQueryPathInfo.String())
	assert.Equal(t, "BuildDerivation", daemon.OpBuildDerivation.String())
	assert.Equal(t, "AddPermRoot", daemon.OpAddPermRoot.String())
	assert.Equal(t, "Operation(999)", daemon.Operation(999).String())
}

func TestLogMessageTypes(t *testing.T) {
	tests := []struct {
		name string
		msg  daemon.LogMessageType
		want uint64
	}{
		{"LogLast", daemon.LogLast, 0x616c7473},
		{"LogError", daemon.LogError, 0x63787470},
		{"LogNext", daemon.LogNext, 0x6f6c6d67},
		{"LogRead", daemon.LogRead, 0x64617461},
		{"LogWrite", daemon.LogWrite, 0x64617416},
		{"LogStartActivity", daemon.LogStartActivity, 0x53545254},
		{"LogStopActivity", daemon.LogStopActivity, 0x53544f50},
		{"LogResult", daemon.LogResult, 0x52534c54},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, daemon.LogMessageType(tt.want), tt.msg)
		})
	}
}

func TestActivityTypes(t *testing.T) {
	assert.Equal(t, daemon.ActivityType(100), daemon.ActUnknown)
	assert.Equal(t, daemon.ActivityType(101), daemon.ActCopyPath)
	assert.Equal(t, daemon.ActivityType(102), daemon.ActFileTransfer)
	assert.Equal(t, daemon.ActivityType(103), daemon.ActRealise)
	assert.Equal(t, daemon.ActivityType(104), daemon.ActCopyPaths)
	assert.Equal(t, daemon.ActivityType(105), daemon.ActBuilds)
	assert.Equal(t, daemon.ActivityType(106), daemon.ActBuild)
	assert.Equal(t, daemon.ActivityType(107), daemon.ActOptimiseStore)
	assert.Equal(t, daemon.ActivityType(108), daemon.ActVerifyPaths)
	assert.Equal(t, daemon.ActivityType(109), daemon.ActSubstitute)
	assert.Equal(t, daemon.ActivityType(110), daemon.ActQueryPathInfo)
	assert.Equal(t, daemon.ActivityType(111), daemon.ActPostBuildHook)
	assert.Equal(t, daemon.ActivityType(112), daemon.ActBuildWaiting)
}

func TestResultTypes(t *testing.T) {
	assert.Equal(t, daemon.ResultType(100), daemon.ResFileLinked)
	assert.Equal(t, daemon.ResultType(101), daemon.ResBuildLogLine)
	assert.Equal(t, daemon.ResultType(102), daemon.ResUntrustedPath)
	assert.Equal(t, daemon.ResultType(103), daemon.ResCorruptedPath)
	assert.Equal(t, daemon.ResultType(104), daemon.ResSetPhase)
	assert.Equal(t, daemon.ResultType(105), daemon.ResProgress)
	assert.Equal(t, daemon.ResultType(106), daemon.ResSetExpected)
	assert.Equal(t, daemon.ResultType(107), daemon.ResPostBuildLogLine)
	assert.Equal(t, daemon.ResultType(108), daemon.ResFetchStatus)
}

func TestVerbosity(t *testing.T) {
	assert.Equal(t, daemon.Verbosity(0), daemon.VerbError)
	assert.Equal(t, daemon.Verbosity(1), daemon.VerbWarn)
	assert.Equal(t, daemon.Verbosity(2), daemon.VerbNotice)
	assert.Equal(t, daemon.Verbosity(3), daemon.VerbInfo)
	assert.Equal(t, daemon.Verbosity(4), daemon.VerbTalkative)
	assert.Equal(t, daemon.Verbosity(5), daemon.VerbChatty)
	assert.Equal(t, daemon.Verbosity(6), daemon.VerbDebug)
	assert.Equal(t, daemon.Verbosity(7), daemon.VerbVomit)
}

func TestBuildMode(t *testing.T) {
	assert.Equal(t, daemon.BuildMode(0), daemon.BuildModeNormal)
	assert.Equal(t, daemon.BuildMode(1), daemon.BuildModeRepair)
	assert.Equal(t, daemon.BuildMode(2), daemon.BuildModeCheck)
}

func TestBuildStatusString(t *testing.T) {
	tests := []struct {
		status daemon.BuildStatus
		want   string
	}{
		{daemon.BuildStatusBuilt, "Built"},
		{daemon.BuildStatusSubstituted, "Substituted"},
		{daemon.BuildStatusAlreadyValid, "AlreadyValid"},
		{daemon.BuildStatusPermanentFailure, "PermanentFailure"},
		{daemon.BuildStatusInputRejected, "InputRejected"},
		{daemon.BuildStatusOutputRejected, "OutputRejected"},
		{daemon.BuildStatusTransientFailure, "TransientFailure"},
		{daemon.BuildStatusCachedFailure, "CachedFailure"},
		{daemon.BuildStatusTimedOut, "TimedOut"},
		{daemon.BuildStatusMiscFailure, "MiscFailure"},
		{daemon.BuildStatusDependencyFailed, "DependencyFailed"},
		{daemon.BuildStatusLogLimitExceeded, "LogLimitExceeded"},
		{daemon.BuildStatusNotDeterministic, "NotDeterministic"},
		{daemon.BuildStatusResolvesToAlreadyValid, "ResolvesToAlreadyValid"},
		{daemon.BuildStatusNoSubstituters, "NoSubstituters"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.status.String())
		})
	}

	// Unknown status
	assert.Equal(t, "BuildStatus(99)", daemon.BuildStatus(99).String())
}

func TestBuildStatusValues(t *testing.T) {
	assert.Equal(t, daemon.BuildStatus(0), daemon.BuildStatusBuilt)
	assert.Equal(t, daemon.BuildStatus(1), daemon.BuildStatusSubstituted)
	assert.Equal(t, daemon.BuildStatus(2), daemon.BuildStatusAlreadyValid)
	assert.Equal(t, daemon.BuildStatus(3), daemon.BuildStatusPermanentFailure)
	assert.Equal(t, daemon.BuildStatus(4), daemon.BuildStatusInputRejected)
	assert.Equal(t, daemon.BuildStatus(5), daemon.BuildStatusOutputRejected)
	assert.Equal(t, daemon.BuildStatus(6), daemon.BuildStatusTransientFailure)
	assert.Equal(t, daemon.BuildStatus(7), daemon.BuildStatusCachedFailure)
	assert.Equal(t, daemon.BuildStatus(8), daemon.BuildStatusTimedOut)
	assert.Equal(t, daemon.BuildStatus(9), daemon.BuildStatusMiscFailure)
	assert.Equal(t, daemon.BuildStatus(10), daemon.BuildStatusDependencyFailed)
	assert.Equal(t, daemon.BuildStatus(11), daemon.BuildStatusLogLimitExceeded)
	assert.Equal(t, daemon.BuildStatus(12), daemon.BuildStatusNotDeterministic)
	assert.Equal(t, daemon.BuildStatus(13), daemon.BuildStatusResolvesToAlreadyValid)
	assert.Equal(t, daemon.BuildStatus(14), daemon.BuildStatusNoSubstituters)
}

func TestTrustLevel(t *testing.T) {
	assert.Equal(t, daemon.TrustLevel(0), daemon.TrustUnknown)
	assert.Equal(t, daemon.TrustLevel(1), daemon.TrustTrusted)
	assert.Equal(t, daemon.TrustLevel(2), daemon.TrustNotTrusted)
}

func TestGCAction(t *testing.T) {
	assert.Equal(t, daemon.GCAction(0), daemon.GCReturnLive)
	assert.Equal(t, daemon.GCAction(1), daemon.GCReturnDead)
	assert.Equal(t, daemon.GCAction(2), daemon.GCDeleteDead)
	assert.Equal(t, daemon.GCAction(3), daemon.GCDeleteSpecific)
}
