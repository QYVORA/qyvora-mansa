package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func newCaptureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture live wireless frames or analyze offline capture files",
	}
	cmd.AddCommand(newCaptureAnalyzeCmd())
	cmd.AddCommand(newCaptureLiveCmd())
	return cmd
}

func newCaptureLiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "live",
		Short: "Passively capture raw 802.11 frames from an existing or temporary monitor interface",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			iface, _ := cmd.Flags().GetString("interface")
			simulated, _ := cmd.Flags().GetBool("sim")
			outPath, _ := cmd.Flags().GetString("out")
			duration, _ := cmd.Flags().GetDuration("duration")
			fixedChannel, _ := cmd.Flags().GetInt("channel")
			hopChannels, _ := cmd.Flags().GetStringSlice("hop")
			dwell, _ := cmd.Flags().GetDuration("dwell")
			monitorName, _ := cmd.Flags().GetString("monitor-interface")
			prefilterMode, _ := cmd.Flags().GetString("prefilter")
			prefilterAddress, _ := cmd.Flags().GetString("prefilter-address")
			prefilter := transport.PrefilterSpec{Mode: transport.PrefilterMode(prefilterMode), Filter: prefilterAddress}
			if simulated && prefilter.Enabled() {
				return usagef("--prefilter cannot be used with --sim")
			}
			if simulated && iface == "" {
				iface = "sim0"
			}
			if iface == "" {
				return usagef("--interface is required")
			}
			if duration <= 0 || duration > time.Hour {
				return usagef("--duration must be between 1ns and 1h")
			}
			if fixedChannel < 0 || (fixedChannel > 0 && len(hopChannels) > 0) || dwell <= 0 {
				return usagef("--channel must be positive and cannot be combined with --hop; --dwell must be positive")
			}
			backend := appState.Backend
			if simulated {
				backend = transport.New()
			}
			provider, ok := backend.(transport.CaptureProvider)
			if !ok {
				return fmt.Errorf("selected backend does not support live capture")
			}
			// Establishing a real target enforces the framework's explicit
			// authorization flow before opening a raw packet socket.
			target, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			var monitorLease *transport.MonitorLease
			var monitorCleanup func() error
			if monitorName != "" {
				if simulated {
					return usagef("--monitor-interface cannot be used with --sim")
				}
				if _, ok := backend.(*transport.LinuxBackend); !ok {
					return usagef("temporary monitor interfaces require the Linux backend")
				}
				monitorLease, err = transport.CreateMonitorInterface(ctxOf(cmd), iface, monitorName)
				if err != nil {
					return err
				}
				monitorRemoved := false
				monitorCleanup = func() error {
					err := monitorLease.Close()
					if err == nil && !monitorRemoved {
						monitorRemoved = true
						if appState.Events != nil {
							appState.Events.Info(events.MonitorInterfaceRemoved, map[string]any{"interface": monitorLease.Name, "temporary": true})
						}
					}
					return err
				}
				defer func() { _ = monitorCleanup() }()
				if appState.Events != nil {
					appState.Events.Info(events.MonitorInterfaceCreated, map[string]any{"interface": monitorLease.Name, "parent_interface": iface, "temporary": true})
				}
				iface = monitorLease.Name
			}
			linkType, err := provider.CaptureLinkType(iface)
			if err != nil {
				return err
			}
			file, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				return fmt.Errorf("create capture output: %w", err)
			}
			defer file.Close()
			writer, err := wireless.NewPCAPWriter(file, linkType)
			if err != nil {
				return fmt.Errorf("write capture header: %w", err)
			}
			ctx, cancel := context.WithTimeout(ctxOf(cmd), duration)
			defer cancel()
			var channelController transport.ChannelController
			var previousChannel transport.RadioChannel
			var stopSchedule context.CancelFunc
			var scheduleDone chan error
			if fixedChannel > 0 || len(hopChannels) > 0 {
				_, ok := backend.(*transport.LinuxBackend)
				if !ok {
					return usagef("channel controls require the Linux backend")
				}
				channelController = transport.LinuxChannelController{Interface: iface}
				previousChannel, err = channelController.CurrentChannel(ctx)
				if err != nil {
					return err
				}
			}
			var assignments []transport.ChannelAssignment
			if fixedChannel > 0 || len(hopChannels) > 0 {
				channels, channelErr := channelController.Channels(ctx)
				if channelErr != nil {
					return channelErr
				}
				requested := hopChannels
				if fixedChannel > 0 {
					requested = []string{strconv.Itoa(fixedChannel)}
				}
				for _, raw := range requested {
					number, parseErr := strconv.Atoi(raw)
					if parseErr != nil || number <= 0 {
						return usagef("invalid channel %q in --hop", raw)
					}
					found := false
					for _, ch := range channels {
						if ch.Number == number && !ch.Disabled {
							assignments = append(assignments, transport.ChannelAssignment{Interface: iface, Channel: ch})
							found = true
							break
						}
					}
					if !found {
						return usagef("channel %d is unavailable on %s", number, iface)
					}
				}
			}
			if fixedChannel > 0 {
				if err := channelController.SetChannel(ctx, assignments[0].Channel); err != nil {
					return err
				}
			} else if len(assignments) > 0 {
				// Hopping runs beside the receiver and uses the same deadline. Any
				// scheduler failure cancels capture; the scheduler restores radio state.
				channelCtx, stopChannels := context.WithCancel(ctx)
				stopSchedule = stopChannels
				scheduleDone = make(chan error, 1)
				go func() {
					err := transport.RunChannelScheduleObserved(channelCtx, map[string]transport.ChannelController{iface: channelController}, assignments, dwell, func(changedInterface string, channel transport.RadioChannel) {
						if appState.Events != nil {
							appState.Events.Info(events.ChannelChanged, map[string]any{"interface": changedInterface, "channel": channel.Number, "frequency_mhz": channel.Frequency, "band": channel.Band, "reason": "capture-hop"})
						}
					})
					if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
						cancel()
					}
					scheduleDone <- err
				}()
			}
			if appState.Events != nil {
				appState.Events.Info(events.CaptureStarted, map[string]any{"interface": iface, "output": filepath.Base(outPath), "duration": duration.String(), "target": target.Value, "simulated": simulated, "channel": fixedChannel, "hop_channels": hopChannels, "dwell": dwell.String(), "temporary_monitor_interface": monitorLease != nil, "kernel_prefilter": prefilterMode, "kernel_prefilter_address": prefilterAddress})
			}
			tracker := wireless.NewTopologyTracker()
			stats, captureErr := transport.CaptureQueuedWithPrefilter(ctx, provider, iface, transport.DefaultCaptureQueueSize, prefilter, func(at time.Time, packet []byte) error {
				if err := writer.WritePacket(at, packet); err != nil {
					return err
				}
				update, err := tracker.ObserveDetailed(linkType, at, packet)
				if err != nil {
					return err
				}
				if appState.Events != nil {
					if record, frameErr := wireless.ParseCapturePacket(linkType, at, packet); frameErr == nil && record.FrameError == nil {
						if observation, ok, authErr := wireless.ParseAuthenticationObservation(record); authErr == nil && ok {
							appState.Events.Info(events.WirelessAuthenticationObserved, map[string]any{"bssid": observation.BSSID, "station": observation.Station, "kind": observation.Kind, "message": observation.Message, "replay_counter": observation.ReplayCounter, "pmkid_sha256": observation.PMKIDSHA256, "source": "live-capture"})
						}
					}
				}
				if appState.Events != nil {
					if ap := update.AccessPoint; ap != nil {
						event := events.AccessPointUpdated
						if update.AccessPointNew {
							event = events.AccessPointDiscovered
						}
						appState.Events.Info(event, map[string]any{
							"bssid": ap.BSSID, "ssid": ap.SSID, "channel": ap.Channel,
							"security": ap.Security.Auth, "vendor": ap.Vendor, "hidden": ap.Hidden, "source": "live-capture",
						})
					}
					if station := update.Station; station != nil {
						event := events.ClientUpdated
						if update.StationNew {
							event = events.ClientDiscovered
						}
						data := map[string]any{
							"mac": station.MAC, "ap": station.APBSSID,
							"associated": station.Associated, "source": "live-capture",
						}
						appState.Events.Info(event, data)
						if update.RoamedFrom != "" {
							data["previous_ap"] = update.RoamedFrom
							appState.Events.Info(events.ClientRoamed, data)
						}
					}
				}
				return nil
			})
			if stopSchedule != nil {
				stopSchedule()
				if scheduleErr := <-scheduleDone; scheduleErr != nil && scheduleErr != context.Canceled && scheduleErr != context.DeadlineExceeded {
					return fmt.Errorf("channel schedule: %w", scheduleErr)
				}
			}
			if fixedChannel > 0 {
				if restoreErr := channelController.SetChannel(context.Background(), previousChannel); restoreErr != nil {
					return fmt.Errorf("restore channel after capture: %w", restoreErr)
				}
			}
			if monitorLease != nil {
				if cleanupErr := monitorCleanup(); cleanupErr != nil {
					return cleanupErr
				}
			}
			if captureErr != nil && (captureErr != context.DeadlineExceeded || ctxOf(cmd).Err() != nil) {
				if appState.Events != nil {
					appState.Events.Fail(events.Error, map[string]any{"operation": "capture.live", "error": captureErr.Error()})
				}
				return fmt.Errorf("live capture: %w", captureErr)
			}
			if err := file.Sync(); err != nil {
				return fmt.Errorf("sync capture output: %w", err)
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("rewind capture output: %w", err)
			}
			hash := sha256.New()
			inventory, err := wireless.ReadPCAPInventoryContext(ctxOf(cmd), io.TeeReader(file, hash))
			if err != nil {
				return fmt.Errorf("analyze captured frames: %w", err)
			}
			captureTarget := &models.Target{ID: models.NewID("target"), Type: models.TargetCapture, Value: filepath.Base(outPath), Interface: iface, Authorization: target.Authorization, CreatedAt: time.Now().UTC()}
			session := models.NewSession(captureTarget)
			if appState.Events != nil {
				session.ExecutionID = appState.Events.ExecutionID()
			}
			session.Simulated = simulated
			session.AccessPoints = inventory.AccessPoints
			session.Stations = inventory.Stations
			session.Authentication = inventory.Authentication
			session.Attributes = map[string]string{
				"capture_format": "pcap", "capture_file": filepath.Base(outPath),
				"capture_interface": iface, "capture_packets": strconv.FormatUint(stats.Packets, 10),
				"capture_malformed_frames": strconv.FormatUint(inventory.Summary.Malformed, 10),
			}
			if simulated {
				session.Attributes["capture_source"] = "simulation-fixture"
			}
			session.AddEvidence(models.Evidence{
				ID: models.NewID("evidence"), Kind: models.EvidenceProtocol,
				Source: "live-pcap", Target: filepath.Base(outPath),
				Detail: fmt.Sprintf("%d packets; %d malformed frames; %d access points; %d clients; %d EAPOL messages; %d four-way message sets observed; %d PMKID observations; %d WEP encrypted frames; %d unique IVs; %d duplicate IVs; WEP IV tracking truncated: %t", stats.Packets, inventory.Summary.Malformed, len(inventory.AccessPoints), len(inventory.Stations), inventory.Summary.HandshakeMessages, inventory.Summary.FourWayMessageSets, inventory.Summary.PMKIDObservations, inventory.Summary.WEPEncryptedFrames, inventory.Summary.WEPUniqueIVs, inventory.Summary.WEPDuplicateIVs, inventory.Summary.WEPIVTrackingTruncated),
				Hash:   hex.EncodeToString(hash.Sum(nil)),
			})
			analyzed, err := appState.AnalyzeSession(ctxOf(cmd), session)
			if err != nil {
				return fmt.Errorf("analyze captured session: %w", err)
			}
			if appState.Events != nil {
				appState.Events.Info(events.CaptureCompleted, map[string]any{"interface": iface, "output": filepath.Base(outPath), "packets": stats.Packets, "bytes": stats.Bytes, "link_type": stats.LinkType, "authorized": target.Authorized(), "simulated": simulated, "session_id": analyzed.ID})
			}
			if appState.Printer.Format() == "terminal" {
				fmt.Fprintf(cliTerminalOut(cmd), "Captured %d packets (%d bytes) to %s (session %s)\n", stats.Packets, stats.Bytes, outPath, analyzed.ID)
			} else {
				appState.Printer.Print(analyzed)
			}
			return nil
		},
	}
	cmd.Flags().String("interface", "", "preconfigured monitor interface")
	cmd.Flags().String("monitor-interface", "", "create this temporary monitor interface from --interface, then remove it after capture")
	cmd.Flags().String("out", "capture.pcap", "new PCAP output path (must not already exist)")
	cmd.Flags().Duration("duration", time.Minute, "capture duration (maximum 1h)")
	cmd.Flags().Int("channel", 0, "capture on this radio-reported channel, then restore the prior channel")
	cmd.Flags().StringSlice("hop", nil, "cycle through these radio-reported channel numbers")
	cmd.Flags().Duration("dwell", 500*time.Millisecond, "time to dwell on each --hop channel")
	cmd.Flags().String("prefilter", string(transport.PrefilterAll), "kernel prefilter mode: assessment, management, beacon, or all")
	cmd.Flags().String("prefilter-address", "", "restrict the kernel prefilter to frames involving this MAC address")
	cmd.Flags().Bool("sim", false, "write and analyze deterministic simulated wireless frames")
	return cmd
}

func newCaptureAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze <pcap-file>",
		Short: "Analyze access points and clients observed in a PCAP/PCAPNG capture",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open capture: %w", err)
			}
			defer file.Close()

			base := filepath.Base(path)
			if appState.Events != nil {
				appState.Events.Info(events.CaptureAnalysisStarted, map[string]any{"file": base})
			}
			hash := sha256.New()
			inventory, err := wireless.ReadPCAPInventoryContext(ctxOf(cmd), io.TeeReader(file, hash))
			if err != nil {
				if appState.Events != nil {
					appState.Events.Fail(events.Error, map[string]any{"operation": "capture.analysis", "error": err.Error()})
				}
				return fmt.Errorf("analyze capture: %w", err)
			}
			if err := ctxOf(cmd).Err(); err != nil {
				return err
			}
			aps, stations, summary := inventory.AccessPoints, inventory.Stations, inventory.Summary

			target := &models.Target{
				ID: models.NewID("target"), Type: models.TargetCapture,
				Value: base, CreatedAt: time.Now().UTC(),
			}
			sess := models.NewSession(target)
			if appState.Events != nil {
				sess.ExecutionID = appState.Events.ExecutionID()
			}
			sess.Offline = true
			sess.AccessPoints = aps
			sess.Stations = stations
			sess.Authentication = inventory.Authentication
			sess.Attributes = map[string]string{
				"capture_format":           "pcap",
				"capture_file":             base,
				"capture_packets":          strconv.FormatUint(summary.Packets, 10),
				"capture_malformed_frames": strconv.FormatUint(summary.Malformed, 10),
			}
			sess.AddEvidence(models.Evidence{
				ID: models.NewID("evidence"), Kind: models.EvidenceProtocol,
				Source: "classic-pcap", Target: base,
				Detail: fmt.Sprintf("%d packets; %d malformed frames; %d access points; %d clients; %d EAPOL messages; %d four-way message sets observed; %d PMKID observations; %d WEP encrypted frames; %d unique IVs; %d duplicate IVs; WEP IV tracking truncated: %t", summary.Packets, summary.Malformed, len(aps), len(stations), summary.HandshakeMessages, summary.FourWayMessageSets, summary.PMKIDObservations, summary.WEPEncryptedFrames, summary.WEPUniqueIVs, summary.WEPDuplicateIVs, summary.WEPIVTrackingTruncated),
				Hash:   hex.EncodeToString(hash.Sum(nil)),
			})
			if appState.Events != nil {
				sess.ExecutionID = appState.Events.ExecutionID()
				sess.ID = sess.ExecutionID
				for _, ap := range aps {
					appState.Events.Info(events.AccessPointDiscovered, map[string]any{
						"bssid": ap.BSSID, "ssid": ap.SSID, "channel": ap.Channel,
						"security": ap.Security.Auth, "source": "pcap",
					})
				}
				for _, station := range stations {
					appState.Events.Info(events.ClientDiscovered, map[string]any{
						"mac": station.MAC, "ap": station.APBSSID,
						"associated": station.Associated, "source": "pcap",
					})
				}
				for _, observation := range inventory.Authentication {
					appState.Events.Info(events.WirelessAuthenticationObserved, map[string]any{"bssid": observation.BSSID, "station": observation.Station, "kind": observation.Kind, "message": observation.Message, "four_way_message_set_observed": observation.FourWaySetComplete, "replay_counter": observation.ReplayCounter, "pmkid_sha256": observation.PMKIDSHA256, "wep_encrypted_frames": observation.WEPEncryptedFrames, "wep_unique_ivs": observation.WEPUniqueIVs, "wep_duplicate_ivs": observation.WEPDuplicateIVs, "wep_iv_tracking_truncated": observation.WEPIVTrackingTruncated, "source": "pcap"})
				}
			}
			analyzed, err := appState.AnalyzeSession(ctxOf(cmd), sess)
			if err != nil {
				return err
			}
			if appState.Events != nil {
				appState.Events.Info(events.CaptureAnalysisCompleted, map[string]any{
					"session_id": analyzed.ID, "packets": summary.Packets,
					"access_points": len(aps), "clients": len(stations), "malformed_frames": summary.Malformed,
				})
			}
			renderSessionSummary(cmd, analyzed)
			return nil
		},
	}
}
