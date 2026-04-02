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

	t.Run("MinProtocolVersion", func(t *testing.T) {
		require.Equal(t, uint64(0x0117), daemon.MinProtocolVersion)
	})

	t.Run("ProtoVersion", func(t *testing.T) {
		rq := require.New(t)
		rq.Equal(uint64(0x0125), daemon.ProtoVersion(1, 37))
		rq.Equal(uint64(0x010c), daemon.ProtoVersion(1, 12))
		rq.Equal(uint64(0x0115), daemon.ProtoVersion(1, 21))
	})

	t.Run("ProtoVersionConstants", func(t *testing.T) {
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

	t.Run("String", func(t *testing.T) {
		rq := require.New(t)
		rq.Equal("IsValidPath", daemon.OpIsValidPath.String())
		rq.Equal("QueryPathInfo", daemon.OpQueryPathInfo.String())
		rq.Equal("BuildDerivation", daemon.OpBuildDerivation.String())
		rq.Equal("AddPermRoot", daemon.OpAddPermRoot.String())
		rq.Equal("Operation(999)", daemon.Operation(999).String())
	})
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
	tests := []struct {
		name string
		typ  daemon.ActivityType
		want daemon.ActivityType
	}{
		{"Unknown", daemon.ActUnknown, 0},
		{"CopyPath", daemon.ActCopyPath, 100},
		{"FileTransfer", daemon.ActFileTransfer, 101},
		{"Realise", daemon.ActRealise, 102},
		{"CopyPaths", daemon.ActCopyPaths, 103},
		{"Builds", daemon.ActBuilds, 104},
		{"Build", daemon.ActBuild, 105},
		{"OptimiseStore", daemon.ActOptimiseStore, 106},
		{"VerifyPaths", daemon.ActVerifyPaths, 107},
		{"Substitute", daemon.ActSubstitute, 108},
		{"QueryPathInfo", daemon.ActQueryPathInfo, 109},
		{"PostBuildHook", daemon.ActPostBuildHook, 110},
		{"BuildWaiting", daemon.ActBuildWaiting, 111},
		{"FetchTree", daemon.ActFetchTree, 112},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.typ)
		})
	}
}

func TestResultTypes(t *testing.T) {
	tests := []struct {
		name string
		typ  daemon.ResultType
		want daemon.ResultType
	}{
		{"FileLinked", daemon.ResFileLinked, 100},
		{"BuildLogLine", daemon.ResBuildLogLine, 101},
		{"UntrustedPath", daemon.ResUntrustedPath, 102},
		{"CorruptedPath", daemon.ResCorruptedPath, 103},
		{"SetPhase", daemon.ResSetPhase, 104},
		{"Progress", daemon.ResProgress, 105},
		{"SetExpected", daemon.ResSetExpected, 106},
		{"PostBuildLogLine", daemon.ResPostBuildLogLine, 107},
		{"FetchStatus", daemon.ResFetchStatus, 108},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.typ)
		})
	}
}

func TestVerbosity(t *testing.T) {
	tests := []struct {
		name string
		v    daemon.Verbosity
		want daemon.Verbosity
	}{
		{"Error", daemon.VerbError, 0},
		{"Warn", daemon.VerbWarn, 1},
		{"Notice", daemon.VerbNotice, 2},
		{"Info", daemon.VerbInfo, 3},
		{"Talkative", daemon.VerbTalkative, 4},
		{"Chatty", daemon.VerbChatty, 5},
		{"Debug", daemon.VerbDebug, 6},
		{"Vomit", daemon.VerbVomit, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.v)
		})
	}
}

func TestBuildMode(t *testing.T) {
	tests := []struct {
		name string
		m    daemon.BuildMode
		want daemon.BuildMode
	}{
		{"Normal", daemon.BuildModeNormal, 0},
		{"Repair", daemon.BuildModeRepair, 1},
		{"Check", daemon.BuildModeCheck, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.m)
		})
	}
}

func TestBuildStatus(t *testing.T) {
	t.Run("String", func(t *testing.T) {
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
	})

	t.Run("Values", func(t *testing.T) {
		tests := []struct {
			name   string
			status daemon.BuildStatus
			want   daemon.BuildStatus
		}{
			{"Built", daemon.BuildStatusBuilt, 0},
			{"Substituted", daemon.BuildStatusSubstituted, 1},
			{"AlreadyValid", daemon.BuildStatusAlreadyValid, 2},
			{"PermanentFailure", daemon.BuildStatusPermanentFailure, 3},
			{"InputRejected", daemon.BuildStatusInputRejected, 4},
			{"OutputRejected", daemon.BuildStatusOutputRejected, 5},
			{"TransientFailure", daemon.BuildStatusTransientFailure, 6},
			{"CachedFailure", daemon.BuildStatusCachedFailure, 7},
			{"TimedOut", daemon.BuildStatusTimedOut, 8},
			{"MiscFailure", daemon.BuildStatusMiscFailure, 9},
			{"DependencyFailed", daemon.BuildStatusDependencyFailed, 10},
			{"LogLimitExceeded", daemon.BuildStatusLogLimitExceeded, 11},
			{"NotDeterministic", daemon.BuildStatusNotDeterministic, 12},
			{"ResolvesToAlreadyValid", daemon.BuildStatusResolvesToAlreadyValid, 13},
			{"NoSubstituters", daemon.BuildStatusNoSubstituters, 14},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.Equal(t, tt.want, tt.status)
			})
		}
	})
}

func TestTrustLevel(t *testing.T) {
	tests := []struct {
		name string
		lvl  daemon.TrustLevel
		want daemon.TrustLevel
	}{
		{"Unknown", daemon.TrustUnknown, 0},
		{"Trusted", daemon.TrustTrusted, 1},
		{"NotTrusted", daemon.TrustNotTrusted, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.lvl)
		})
	}
}

func TestGCAction(t *testing.T) {
	tests := []struct {
		name string
		a    daemon.GCAction
		want daemon.GCAction
	}{
		{"ReturnLive", daemon.GCReturnLive, 0},
		{"ReturnDead", daemon.GCReturnDead, 1},
		{"DeleteDead", daemon.GCDeleteDead, 2},
		{"DeleteSpecific", daemon.GCDeleteSpecific, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.a)
		})
	}
}
