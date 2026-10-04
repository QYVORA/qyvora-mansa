package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/credentials"
	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/internal/wpa"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// newCredentialsCmd groups the offline credential assessment commands.
func newCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Assess captured WPA/WPA2 handshake material against candidate passphrases",
		Long: "Assess captured WPA/WPA2 handshake material against candidate passphrases.\n\n" +
			"A candidate is reported only when the message integrity code recomputed from\n" +
			"the candidate-derived temporal key equals the code the peer transmitted. The\n" +
			"capture is never modified and no packet is transmitted, so the command is\n" +
			"offline analysis. Candidates are never written to disk or to the session.",
	}
	cmd.AddCommand(newCredentialsVerifyCmd())
	return cmd
}

func newCredentialsVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify candidate passphrases against a captured four-way handshake",
		Long: "Verify candidate passphrases against a captured four-way handshake.\n\n" +
			"The capture must contain an M1 and a later message with a message integrity\n" +
			"code at the same replay counter, plus a beacon or probe response naming the\n" +
			"network, because the SSID is required to derive a pairwise master key.\n\n" +
			"Exactly one authorized target must be supplied with --ssid or --bssid so the\n" +
			"assessment is scoped to a network the operator is responsible for.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			capturePath, _ := cmd.Flags().GetString("capture")
			ssid, _ := cmd.Flags().GetString("ssid")
			bssid, _ := cmd.Flags().GetString("bssid")
			maxCandidates, _ := cmd.Flags().GetUint64("max-candidates")
			kdfName, _ := cmd.Flags().GetString("kdf")

			if capturePath == "" {
				return usagef("--capture is required and must name an existing PCAP file")
			}
			if (ssid == "") == (bssid == "") {
				return usagef("exactly one of --ssid or --bssid is required so the assessment is scoped to one network")
			}
			if maxCandidates == 0 {
				return usagef("--max-candidates must be greater than zero")
			}
			kdf, err := parseCredentialKDF(kdfName)
			if err != nil {
				return usagef("%v", err)
			}
			cfg, err := credentialConfig(cmd)
			if err != nil {
				return usagef("%v", err)
			}

			// The capture is read before authorization so a missing file is reported
			// as a usage problem rather than as a refused assessment.
			observations, aps, readErr := readCredentialCapture(capturePath)
			if readErr != nil {
				return readErr
			}

			target := &models.Target{
				ID: models.NewID("target"), Type: models.TargetSSID,
				Value: ssid, CreatedAt: time.Now().UTC(),
			}
			if bssid != "" {
				target.Type = models.TargetBSSID
				target.Value = bssid
			}
			authorized, err := appState.Authorize(target, authorizedFrom(cmd))
			if err != nil {
				if appState.Events != nil {
					appState.Events.Info(events.OperationRefused, map[string]any{
						"operation": "credentials.verify", "target": target.Value,
						"reason": err.Error(), "authorization": false,
					})
				}
				return usageErr(err)
			}
			_ = appState.Targets.Set(authorized)

			handshakes, err := credentials.HandshakesFromObservations(observations)
			if err != nil {
				return fmt.Errorf("%v; a verifiable capture needs an M1, a later integrity-coded message at the same replay counter, and a beacon or probe response naming the network", err)
			}
			// A handshake captured without a network name cannot derive a master
			// key, so it is refused rather than reported as a candidate miss.
			usable, err := credentials.PassphraseHandshakes(handshakes)
			if err != nil {
				return err
			}
			verifier, err := credentials.NewWPAVerifier(usable)
			if err != nil {
				return err
			}
			verifier.KDF = kdf
			if !verifier.Supports(authorized.Type) {
				return fmt.Errorf("the WPA verifier does not accept a %q target", authorized.Type)
			}

			ctx := ctxOf(cmd)
			if appState.Events != nil {
				appState.Events.Info(events.CredentialAssessmentStarted, map[string]any{
					"target": authorized.Value, "target_type": string(authorized.Type),
					"capture": capturePath, "handshakes": len(handshakes),
					"kdf": kdf.String(), "max_candidates": maxCandidates,
					"authorized": true, "simulated": false, "offline": true,
				})
			}
			result, runErr := credentials.Run(ctx, authorized, cfg, verifier, func(progress credentials.Progress) {
				if appState.Events != nil && progress.Processed%1000 == 0 {
					appState.Events.Info(events.CredentialCandidateTested, map[string]any{
						"processed": progress.Processed, "source": progress.Source,
					})
				}
			})
			if runErr != nil {
				if appState.Events != nil {
					appState.Events.Fail(events.Error, map[string]any{"operation": "credentials.verify", "error": runErr.Error()})
				}
				return runErr
			}

			// A nil result means the pipeline exhausted its candidates without a
			// cryptographic match. That is reported as an explicit negative result
			// rather than as a silent success.
			report := credentialReport{
				Target: authorized.Value, TargetType: string(authorized.Type),
				Capture: capturePath, Verified: result != nil && result.Verified,
				KDF: kdf.String(), Handshakes: len(handshakes),
				AccessPoints: len(aps), Offline: true,
				Note: credentialReportNote,
			}
			if result != nil {
				report.CandidateSHA256 = result.CandidateSHA256
				report.Source = result.Source
				report.Evidence = result.Evidence
			}
			saveCredentialSession(authorized, capturePath, report, aps)
			if appState.Events != nil {
				level := events.CredentialAssessmentCompleted
				payload := map[string]any{
					"target": authorized.Value, "verified": report.Verified,
					"candidates_exhausted": true, "session_id": credentialSessionID(),
				}
				if report.Verified {
					level = events.CredentialCandidateConfirmed
					payload["candidate_sha256"] = report.CandidateSHA256
				}
				appState.Events.Info(level, payload)
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(report)
				return nil
			}
			printCredentialReport(cmd, report)
			return nil
		},
	}
	cmd.Flags().String("capture", "", "existing PCAP file containing a captured four-way handshake")
	cmd.Flags().String("ssid", "", "authorized target SSID; must match a network named in the capture")
	cmd.Flags().String("bssid", "", "authorized target BSSID; must match an access point in the capture")
	cmd.Flags().String("kdf", "sha1", "passphrase derivation: sha1 for the WPA/WPA2-PTK suites, sha256 for the SHA-256 suites")
	cmd.Flags().Bool("builtin", true, "check the small MANSA-owned built-in candidate set")
	cmd.Flags().StringSlice("wordlist", nil, "read candidates from this file; may be repeated")
	cmd.Flags().String("wordlist-dir", "", "read candidates from every regular file in this directory")
	cmd.Flags().StringSlice("candidate", nil, "check this literal candidate; may be repeated")
	cmd.Flags().String("mutation-prefix", "", "prefix each candidate with this value before checking it")
	cmd.Flags().String("mutation-suffix", "", "suffix each candidate with this value before checking it")
	cmd.Flags().Uint64("max-candidates", 1_000_000, "upper bound on candidates checked in this run")
	cmd.Flags().String("min-length", "", "skip candidates shorter than this length")
	cmd.Flags().String("max-length", "", "skip candidates longer than this length")
	return cmd
}

func parseCredentialKDF(name string) (wpa.KDF, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha1", "":
		return wpa.KDFSHA1, nil
	case "sha256":
		return wpa.KDFSHA256, nil
	default:
		return wpa.KDFSHA1, fmt.Errorf("unknown --kdf %q; use sha1 or sha256", name)
	}
}

// credentialConfig assembles the candidate configuration from the command flags.
// A length bound is compiled into a filter rather than applied after the fact, so
// an out-of-range candidate is never passed to the verifier at all.
func credentialConfig(cmd *cobra.Command) (credentials.Config, error) {
	cfg := credentials.Config{}
	cfg.Builtin, _ = cmd.Flags().GetBool("builtin")
	cfg.Wordlists, _ = cmd.Flags().GetStringSlice("wordlist")
	cfg.WordlistDir, _ = cmd.Flags().GetString("wordlist-dir")
	cfg.Generated, _ = cmd.Flags().GetStringSlice("candidate")
	cfg.MaxCandidates, _ = cmd.Flags().GetUint64("max-candidates")
	prefix, _ := cmd.Flags().GetString("mutation-prefix")
	suffix, _ := cmd.Flags().GetString("mutation-suffix")
	if prefix != "" || suffix != "" {
		cfg.Mutations = append(cfg.Mutations, credentials.Mutation{Prefix: prefix, Suffix: suffix})
	}
	minLength, err := lengthBound(cmd, "min-length")
	if err != nil {
		return credentials.Config{}, err
	}
	maxLength, err := lengthBound(cmd, "max-length")
	if err != nil {
		return credentials.Config{}, err
	}
	if maxLength != 0 && minLength != 0 && maxLength < minLength {
		return credentials.Config{}, fmt.Errorf("--max-length %d is below --min-length %d", maxLength, minLength)
	}
	if minLength != 0 || maxLength != 0 {
		cfg.Filter = func(candidate string) bool {
			if minLength != 0 && len([]rune(candidate)) < minLength {
				return false
			}
			if maxLength != 0 && len([]rune(candidate)) > maxLength {
				return false
			}
			return true
		}
	}
	return cfg, nil
}

func lengthBound(cmd *cobra.Command, name string) (int, error) {
	raw, _ := cmd.Flags().GetString(name)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("--%s must be a non-negative integer", name)
	}
	return value, nil
}

// readCredentialCapture reads the bounded offline inventory from a capture.
func readCredentialCapture(path string) ([]models.WirelessAuthenticationObservation, []models.AccessPoint, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, usagef("--capture %s could not be read: %v", path, err)
	}
	if info.IsDir() {
		return nil, nil, usagef("--capture %s is a directory, not a PCAP file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, usagef("--capture %s could not be opened: %v", path, err)
	}
	defer file.Close()
	inventory, err := wireless.ReadPCAPInventoryContext(context.Background(), file)
	if err != nil {
		return nil, nil, fmt.Errorf("read capture %s: %w", path, err)
	}
	return inventory.Authentication, inventory.AccessPoints, nil
}

// credentialReport is the machine-readable outcome. It records only a hash of the
// matching candidate, never the candidate itself.
type credentialReport struct {
	Target          string   `json:"target"`
	TargetType      string   `json:"target_type"`
	Capture         string   `json:"capture"`
	Verified        bool     `json:"verified"`
	CandidateSHA256 string   `json:"candidate_sha256,omitempty"`
	Source          string   `json:"source,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
	KDF             string   `json:"kdf"`
	Handshakes      int      `json:"handshakes_considered"`
	AccessPoints    int      `json:"access_points_observed"`
	Offline         bool     `json:"offline_analysis"`
	Note            string   `json:"note"`
}

const credentialReportNote = "Offline comparison against captured message integrity codes. " +
	"A verified result means the recomputed code matched the transmitted code for the " +
	"named handshake; it does not establish access to any live network."

func saveCredentialSession(target *models.Target, capturePath string, report credentialReport, aps []models.AccessPoint) {
	sess := models.NewSession(target)
	sess.Offline = true
	sess.AccessPoints = aps
	if appState.Events != nil {
		sess.ExecutionID = appState.Events.ExecutionID()
	}
	sess.AddEvidence(models.Evidence{
		ID: models.NewID("evidence"), Kind: models.EvidenceProtocol,
		Source: "classic-pcap", Target: report.Target,
		Detail: fmt.Sprintf("%s; %s; %d handshakes considered; kdf %s; candidate sha256 %s; %s",
			report.Note, captureName(capturePath), report.Handshakes, report.KDF,
			report.CandidateSHA256, verifiedWording(report.Verified)),
	})
	for _, line := range report.Evidence {
		sess.AddEvidence(models.Evidence{
			ID: models.NewID("evidence"), Kind: models.EvidenceObservation,
			Source: "wpa-four-way-mic", Target: report.Target,
			Detail: line,
		})
	}
	if appState.Events != nil {
		sess.ID = appState.Events.ExecutionID()
	}
	_, _ = appState.Store.Save(sess)
}

func printCredentialReport(cmd *cobra.Command, report credentialReport) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Credential assessment for %s %s (%s)\n", report.TargetType, report.Target, report.KDF)
	fmt.Fprintf(out, "  capture:       %s\n", report.Capture)
	fmt.Fprintf(out, "  access points: %d\n", report.AccessPoints)
	fmt.Fprintf(out, "  handshakes:    %d considered\n", report.Handshakes)
	if !report.Verified {
		fmt.Fprintf(out, "  result:        no candidate reproduced a captured message integrity code\n")
	} else {
		fmt.Fprintf(out, "  result:        a candidate reproduced a captured message integrity code\n")
		fmt.Fprintf(out, "  candidate:     sha256:%s (from %s; the value itself is not recorded)\n", report.CandidateSHA256, report.Source)
		for _, line := range report.Evidence {
			fmt.Fprintf(out, "  evidence:      %s\n", line)
		}
	}
	fmt.Fprintf(out, "\n%s\n", credentialReportNote)
}

// credentialSessionID returns the identifier of the session the run just wrote,
// or an empty string when no session could be saved.
func credentialSessionID() string {
	if saved, err := appState.Store.Latest(); err == nil && saved != nil {
		return saved.ID
	}
	return ""
}

func verifiedWording(verified bool) string {
	if verified {
		return "a candidate-derived message integrity code matched the captured code"
	}
	return "no candidate reproduced a captured message integrity code"
}

// captureName reduces a path to its base name so evidence does not record an
// operator's directory layout.
func captureName(path string) string {
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[index+1:]
	}
	return path
}
