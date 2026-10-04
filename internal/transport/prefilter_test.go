package transport

import "testing"

func TestCompilePrefilterReturnsProgramsForSupportedModes(t *testing.T) {
	for _, tc := range []struct {
		mode   PrefilterMode
		expect []byte
	}{
		{PrefilterAll, allFramesProgram()},
		{PrefilterManagement, managementFramesProgram("")},
		{PrefilterBeacon, beaconFramesProgram("")},
		{PrefilterAssessment, assessmentFramesProgram("")},
	} {
		instr, err := CompilePrefilter(PrefilterSpec{Mode: tc.mode})
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if len(instr.Program) == 0 {
			t.Errorf("%s returned empty program", tc.mode)
		}
	}
}

func TestCompilePrefilterRejectsUnknownMode(t *testing.T) {
	_, err := CompilePrefilter(PrefilterSpec{Mode: "unknown"})
	if err == nil {
		t.Fatal("expected an error for an unknown prefilter mode")
	}
}
