package daemon_test

import (
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func TestProtocolConstants(t *testing.T) {
	t.Run("ClientMagic", func(t *testing.T) {
		require.Equal(t, uint64(0x6e697863), daemon.ClientMagic)
	})

	t.Run("ServerMagic", func(t *testing.T) {
		require.Equal(t, uint64(0x6478696f), daemon.ServerMagic)
	})

	t.Run("ProtocolVersion", func(t *testing.T) {
		rq := require.New(t)
		rq.Equal(uint64(0x0126), daemon.ProtocolVersion)
		// Version 1.38 => major=1, minor=38
		rq.Equal(uint64(1), daemon.ProtocolVersion>>8)
		rq.Equal(uint64(38), daemon.ProtocolVersion&0xff)
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
			require.Equal(t, daemon.Operation(tt.want), tt.op)
		})
	}
}

func TestOperationString(t *testing.T) {
	rq := require.New(t)
	rq.Equal("IsValidPath", daemon.OpIsValidPath.String())
	rq.Equal("QueryPathInfo", daemon.OpQueryPathInfo.String())
	rq.Equal("BuildDerivation", daemon.OpBuildDerivation.String())
	rq.Equal("AddPermRoot", daemon.OpAddPermRoot.String())
	rq.Equal("Operation(999)", daemon.Operation(999).String())
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
			require.Equal(t, daemon.LogMessageType(tt.want), tt.msg)
		})
	}
}

func TestActivityTypes(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.ActivityType(0), daemon.ActUnknown)
	rq.Equal(daemon.ActivityType(100), daemon.ActCopyPath)
	rq.Equal(daemon.ActivityType(101), daemon.ActFileTransfer)
	rq.Equal(daemon.ActivityType(102), daemon.ActRealise)
	rq.Equal(daemon.ActivityType(103), daemon.ActCopyPaths)
	rq.Equal(daemon.ActivityType(104), daemon.ActBuilds)
	rq.Equal(daemon.ActivityType(105), daemon.ActBuild)
	rq.Equal(daemon.ActivityType(106), daemon.ActOptimiseStore)
	rq.Equal(daemon.ActivityType(107), daemon.ActVerifyPaths)
	rq.Equal(daemon.ActivityType(108), daemon.ActSubstitute)
	rq.Equal(daemon.ActivityType(109), daemon.ActQueryPathInfo)
	rq.Equal(daemon.ActivityType(110), daemon.ActPostBuildHook)
	rq.Equal(daemon.ActivityType(111), daemon.ActBuildWaiting)
	rq.Equal(daemon.ActivityType(112), daemon.ActFetchTree)
}

func TestResultTypes(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.ResultType(100), daemon.ResFileLinked)
	rq.Equal(daemon.ResultType(101), daemon.ResBuildLogLine)
	rq.Equal(daemon.ResultType(102), daemon.ResUntrustedPath)
	rq.Equal(daemon.ResultType(103), daemon.ResCorruptedPath)
	rq.Equal(daemon.ResultType(104), daemon.ResSetPhase)
	rq.Equal(daemon.ResultType(105), daemon.ResProgress)
	rq.Equal(daemon.ResultType(106), daemon.ResSetExpected)
	rq.Equal(daemon.ResultType(107), daemon.ResPostBuildLogLine)
	rq.Equal(daemon.ResultType(108), daemon.ResFetchStatus)
}

func TestVerbosity(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.Verbosity(0), daemon.VerbError)
	rq.Equal(daemon.Verbosity(1), daemon.VerbWarn)
	rq.Equal(daemon.Verbosity(2), daemon.VerbNotice)
	rq.Equal(daemon.Verbosity(3), daemon.VerbInfo)
	rq.Equal(daemon.Verbosity(4), daemon.VerbTalkative)
	rq.Equal(daemon.Verbosity(5), daemon.VerbChatty)
	rq.Equal(daemon.Verbosity(6), daemon.VerbDebug)
	rq.Equal(daemon.Verbosity(7), daemon.VerbVomit)
}

func TestBuildMode(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.BuildMode(0), daemon.BuildModeNormal)
	rq.Equal(daemon.BuildMode(1), daemon.BuildModeRepair)
	rq.Equal(daemon.BuildMode(2), daemon.BuildModeCheck)
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
			require.Equal(t, tt.want, tt.status.String())
		})
	}

	// Unknown status
	require.Equal(t, "BuildStatus(99)", daemon.BuildStatus(99).String())
}

func TestBuildStatusValues(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.BuildStatus(0), daemon.BuildStatusBuilt)
	rq.Equal(daemon.BuildStatus(1), daemon.BuildStatusSubstituted)
	rq.Equal(daemon.BuildStatus(2), daemon.BuildStatusAlreadyValid)
	rq.Equal(daemon.BuildStatus(3), daemon.BuildStatusPermanentFailure)
	rq.Equal(daemon.BuildStatus(4), daemon.BuildStatusInputRejected)
	rq.Equal(daemon.BuildStatus(5), daemon.BuildStatusOutputRejected)
	rq.Equal(daemon.BuildStatus(6), daemon.BuildStatusTransientFailure)
	rq.Equal(daemon.BuildStatus(7), daemon.BuildStatusCachedFailure)
	rq.Equal(daemon.BuildStatus(8), daemon.BuildStatusTimedOut)
	rq.Equal(daemon.BuildStatus(9), daemon.BuildStatusMiscFailure)
	rq.Equal(daemon.BuildStatus(10), daemon.BuildStatusDependencyFailed)
	rq.Equal(daemon.BuildStatus(11), daemon.BuildStatusLogLimitExceeded)
	rq.Equal(daemon.BuildStatus(12), daemon.BuildStatusNotDeterministic)
	rq.Equal(daemon.BuildStatus(13), daemon.BuildStatusResolvesToAlreadyValid)
	rq.Equal(daemon.BuildStatus(14), daemon.BuildStatusNoSubstituters)
}

func TestTrustLevel(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.TrustLevel(0), daemon.TrustUnknown)
	rq.Equal(daemon.TrustLevel(1), daemon.TrustTrusted)
	rq.Equal(daemon.TrustLevel(2), daemon.TrustNotTrusted)
}

func TestGCAction(t *testing.T) {
	rq := require.New(t)
	rq.Equal(daemon.GCAction(0), daemon.GCReturnLive)
	rq.Equal(daemon.GCAction(1), daemon.GCReturnDead)
	rq.Equal(daemon.GCAction(2), daemon.GCDeleteDead)
	rq.Equal(daemon.GCAction(3), daemon.GCDeleteSpecific)
}

func TestMinProtocolVersion(t *testing.T) {
	require.Equal(t, uint64(0x0117), daemon.MinProtocolVersion)
}

func TestProtoVersion(t *testing.T) {
	rq := require.New(t)
	rq.Equal(uint64(0x0125), daemon.ProtoVersion(1, 37))
	rq.Equal(uint64(0x010c), daemon.ProtoVersion(1, 12))
	rq.Equal(uint64(0x0115), daemon.ProtoVersion(1, 21))
}

func TestProtoVersionConstants(t *testing.T) {
	rq := require.New(t)
	rq.Equal(uint64(0x010c), uint64(daemon.ProtoVersionOverrides))
	rq.Equal(uint64(0x0110), uint64(daemon.ProtoVersionPathInfoMeta))
	rq.Equal(uint64(0x011b), uint64(daemon.ProtoVersionSubstituteOk))
	rq.Equal(uint64(0x011c), uint64(daemon.ProtoVersionBuiltOutputs))
	rq.Equal(uint64(0x011d), uint64(daemon.ProtoVersionBuildTimes))
	rq.Equal(uint64(0x011e), uint64(daemon.ProtoVersionQueryDerivationOutputMap))
	rq.Equal(uint64(0x011f), uint64(daemon.ProtoVersionRealisationJSON))
	rq.Equal(uint64(0x0120), uint64(daemon.ProtoVersionAddMultipleToStore))
	rq.Equal(uint64(0x0122), uint64(daemon.ProtoVersionBuildPathsWithResults))
	rq.Equal(uint64(0x0125), uint64(daemon.ProtoVersionCPUTimes))
}
