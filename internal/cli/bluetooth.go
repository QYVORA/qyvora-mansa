package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func newBluetoothCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "bluetooth", Short: "Bluetooth and BLE analysis"}
	scanCmd := &cobra.Command{
		Use: "scan", Short: "Passively scan BLE advertisements from an already powered adapter", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			adapter, _ := cmd.Flags().GetString("adapter")
			duration, _ := cmd.Flags().GetDuration("duration")
			simulated, _ := cmd.Flags().GetBool("sim")
			if adapter == "" {
				return usagef("--adapter is required")
			}
			if duration <= 0 || duration > 10*time.Minute {
				return usagef("--duration must be between 1ns and 10m")
			}
			backend := appState.Backend
			if simulated {
				backend = transport.New()
			}
			provider, ok := backend.(transport.BLEScanProvider)
			if !ok {
				return fmt.Errorf("selected backend does not support live BLE discovery")
			}
			target := &models.Target{ID: models.NewID("target"), Type: models.TargetBluetoothAdapter, Value: adapter, CreatedAt: time.Now().UTC()}
			if simulated {
				target.Authorization = models.Authorization{Granted: true, GrantedAt: time.Now().UTC(), Scope: "offline Bluetooth simulation fixture only; no HCI I/O", Method: "simulation"}
			} else if _, err := appState.Authorize(target, authorizedFrom(cmd)); err != nil {
				return usageErr(err)
			}
			ctx, cancel := context.WithTimeout(ctxOf(cmd), duration)
			defer cancel()
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothScanStarted, map[string]any{"adapter": adapter, "duration": duration.String(), "authorized": target.Authorized(), "simulated": simulated, "passive": true})
			}
			devices := make(map[string]models.BluetoothDeviceObservation)
			stats, scanErr := provider.ScanBLE(ctx, adapter, func(observation models.BluetoothDeviceObservation) error {
				_, exists := devices[observation.Address]
				if exists || len(devices) < 4096 {
					devices[observation.Address] = observation
				}
				if appState.Events != nil {
					name := events.BluetoothDeviceDiscovered
					if exists {
						name = events.BluetoothDeviceUpdated
					}
					appState.Events.Info(name, map[string]any{"address": observation.Address, "address_type": observation.AddressType, "rssi": observation.RSSI, "name": observation.Advertisement.Name, "service_uuids": observation.Advertisement.ServiceUUIDs, "adapter": adapter, "source": map[bool]string{true: "simulation", false: "hci"}[simulated], "simulated": simulated})
				}
				return nil
			})
			if scanErr != nil && (scanErr != context.DeadlineExceeded || ctxOf(cmd).Err() != nil) {
				return fmt.Errorf("BLE scan: %w", scanErr)
			}
			ordered := make([]models.BluetoothDeviceObservation, 0, len(devices))
			for _, device := range devices {
				ordered = append(ordered, device)
			}
			sort.Slice(ordered, func(i, j int) bool { return ordered[i].Address < ordered[j].Address })
			session := models.NewSession(target)
			if appState.Events != nil {
				session.ExecutionID = appState.Events.ExecutionID()
			}
			session.Simulated, session.BluetoothDevices = simulated, ordered
			session.Attributes["bluetooth_adapter"] = adapter
			session.Attributes["bluetooth_reports"] = strconv.FormatUint(stats.Reports, 10)
			session.Attributes["bluetooth_malformed_reports"] = strconv.FormatUint(stats.Malformed, 10)
			for _, device := range ordered {
				data, _ := json.Marshal(device)
				digest := sha256.Sum256(data)
				session.AddEvidence(models.Evidence{ID: models.NewID("evidence"), Kind: models.EvidenceObservation, Source: "ble-hci-scan", Target: device.Address, Detail: fmt.Sprintf("LE advertisement observed; RSSI available=%t", device.RSSIAvailable), Hash: hex.EncodeToString(digest[:])})
			}
			session.Finish()
			if appState.Events != nil {
				session.ID = appState.Events.ExecutionID()
			}
			if _, err := appState.Store.Save(session); err != nil {
				return fmt.Errorf("save BLE scan session: %w", err)
			}
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothScanCompleted, map[string]any{"adapter": adapter, "reports": stats.Reports, "devices": len(ordered), "malformed": stats.Malformed, "authorized": target.Authorized(), "simulated": simulated, "session_id": session.ID})
			}
			appState.Printer.Print(map[string]any{"session_id": session.ID, "adapter": adapter, "reports": stats.Reports, "devices": ordered, "simulated": simulated})
			return nil
		},
	}
	scanCmd.Flags().String("adapter", "hci0", "already powered HCI adapter")
	scanCmd.Flags().Duration("duration", 15*time.Second, "passive scan duration (maximum 10m)")
	scanCmd.Flags().Bool("sim", false, "consume a deterministic BLE fixture without radio hardware")
	cmd.AddCommand(scanCmd)
	cmd.AddCommand(&cobra.Command{
		Use:   "adapters",
		Short: "List local Linux Bluetooth HCI adapters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			provider, ok := appState.Backend.(transport.BluetoothAdapterProvider)
			if !ok {
				return fmt.Errorf("selected backend does not support Bluetooth adapter discovery")
			}
			adapters, err := provider.DiscoverBluetoothAdapters()
			if err != nil {
				return err
			}
			if appState.Events != nil {
				for _, adapter := range adapters {
					appState.Events.Info(events.BluetoothAdapterDiscovered, map[string]any{"id": adapter.ID, "address": adapter.Address, "state": adapter.State})
				}
			}
			appState.Printer.Print(adapters)
			return nil
		},
	})
	parseAdvertisementCmd := &cobra.Command{
		Use:   "parse-advertisement [hex-payload]",
		Short: "Parse captured BLE advertising data",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			simulated, _ := cmd.Flags().GetBool("sim")
			var payload []byte
			if simulated {
				if len(args) != 0 {
					return usagef("do not pass a payload with --sim")
				}
				payload = bluetooth.SimulatedAdvertisementData()
			} else {
				if len(args) != 1 {
					return usagef("provide a payload or use --sim")
				}
				var err error
				payload, err = hex.DecodeString(args[0])
				if err != nil {
					return usagef("payload must be an even-length hexadecimal string: %v", err)
				}
			}
			parsed, err := bluetooth.ParseAdvertisement(payload)
			if err != nil {
				return fmt.Errorf("parse BLE advertisement: %w", err)
			}
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothAdvertisementParsed, map[string]any{"name": parsed.Name, "service_uuids": parsed.ServiceUUIDs, "manufacturer_ids": len(parsed.ManufacturerData), "simulated": simulated})
			}
			appState.Printer.Print(parsed)
			return nil
		},
	}
	parseAdvertisementCmd.Flags().Bool("sim", false, "parse Mansa's deterministic BLE advertisement fixture")
	cmd.AddCommand(parseAdvertisementCmd)
	parseHCIEventCmd := &cobra.Command{
		Use:   "parse-hci-event [hex-packet]",
		Short: "Parse captured HCI LE Advertising Report events",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			simulated, _ := cmd.Flags().GetBool("sim")
			var packet []byte
			if simulated {
				if len(args) != 0 {
					return usagef("do not pass a packet with --sim")
				}
				packet = bluetooth.SimulatedLEAdvertisingReport()
			} else {
				if len(args) != 1 {
					return usagef("provide an HCI packet or use --sim")
				}
				var err error
				packet, err = hex.DecodeString(args[0])
				if err != nil {
					return usagef("HCI packet must be an even-length hexadecimal string: %v", err)
				}
			}
			observations, err := bluetooth.ParseLEAdvertisingReports(packet)
			if err != nil {
				return fmt.Errorf("parse HCI advertising event: %w", err)
			}
			if appState.Events != nil {
				for _, observation := range observations {
					appState.Events.Info(events.BluetoothDeviceDiscovered, map[string]any{"address": observation.Address, "address_type": observation.AddressType, "rssi": observation.RSSI, "name": observation.Advertisement.Name, "service_uuids": observation.Advertisement.ServiceUUIDs, "source": map[bool]string{true: "simulation", false: "hci-capture"}[simulated], "simulated": simulated})
				}
			}
			appState.Printer.Print(observations)
			return nil
		},
	}
	parseHCIEventCmd.Flags().Bool("sim", false, "parse Mansa's deterministic simulated HCI event")
	cmd.AddCommand(parseHCIEventCmd)
	gattCmd := &cobra.Command{
		Use:   "analyze-gatt [database.json]",
		Short: "Review a saved GATT metadata snapshot for write access-control concerns",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			simulated, _ := cmd.Flags().GetBool("sim")
			var database models.GATTDatabase
			if simulated {
				if len(args) != 0 {
					return usagef("do not pass a file with --sim")
				}
				database = bluetooth.SimulatedGATTDatabase()
			} else {
				if len(args) != 1 {
					return usagef("provide a GATT database JSON file or use --sim")
				}
				file, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open GATT database: %w", err)
				}
				defer file.Close()
				data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
				if err != nil {
					return fmt.Errorf("read GATT database: %w", err)
				}
				if len(data) > 1<<20 {
					return usagef("GATT database exceeds 1 MiB limit")
				}
				if err := json.Unmarshal(data, &database); err != nil {
					return usagef("decode GATT database JSON: %v", err)
				}
			}
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothGATTAnalysisStarted, map[string]any{"device_address": database.DeviceAddress, "simulated": database.Simulated})
			}
			findings := bluetooth.AnalyzeGATT(database)
			if appState.Events != nil {
				for _, finding := range findings {
					appState.Events.Info(events.FindingDiscovered, map[string]any{"rule_id": finding.RuleID, "finding_id": finding.ID, "target": finding.Target})
				}
				appState.Events.Info(events.BluetoothGATTAnalysisCompleted, map[string]any{"device_address": database.DeviceAddress, "findings": len(findings), "simulated": database.Simulated})
			}
			appState.Printer.Print(findings)
			return nil
		},
	}
	gattCmd.Flags().Bool("sim", false, "analyze Mansa's deterministic simulated GATT fixture")
	cmd.AddCommand(gattCmd)
	cmd.AddCommand(newEnumerateGATTCmd())
	return cmd
}

// newEnumerateGATTCmd enumerates a connected peer's GATT table over ATT.
//
// The enumeration opens a link, reads the peer's attribute table with the
// read-only ATT requests, and closes the link. It writes no attribute, subscribes
// to nothing, and does not pair, so a peer that requires authorization answers
// with an ATT error and the walk ends there rather than being worked around.
func newEnumerateGATTCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enumerate-gatt",
		Short: "Enumerate a peer's live GATT services, characteristics, and descriptors over ATT",
		Long: "Enumerate a peer's live GATT services, characteristics, and descriptors over ATT.\n\n" +
			"The enumeration opens an LE link, walks the peer's attribute table with\n" +
			"read-only ATT requests, and disconnects. No attribute is written, nothing is\n" +
			"subscribed to, and no pairing is attempted. A peer that requires pairing\n" +
			"answers with an ATT error, which is reported rather than bypassed.\n\n" +
			"There is no simulated enumeration: a fixture must never be presented as a\n" +
			"statement about a real peer.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			adapter, _ := cmd.Flags().GetString("adapter")
			address, _ := cmd.Flags().GetString("address")
			timeout, _ := cmd.Flags().GetDuration("timeout")
			mtu, _ := cmd.Flags().GetUint16("mtu")
			discoverDescriptors, _ := cmd.Flags().GetBool("descriptors")
			maxServices, _ := cmd.Flags().GetInt("max-services")
			maxCharacteristics, _ := cmd.Flags().GetInt("max-characteristics")
			maxDescriptors, _ := cmd.Flags().GetInt("max-descriptors")

			if adapter == "" {
				return usagef("--adapter is required")
			}
			if address == "" {
				return usagef("--address is required and must be the peer's Bluetooth address")
			}
			if timeout <= 0 || timeout > 10*time.Minute {
				return usagef("--timeout must be between 1ns and 10m")
			}
			if mtu != 0 && mtu < 23 {
				return usagef("--mtu must be at least 23")
			}
			provider, ok := appState.Backend.(transport.GATTEnumerationProvider)
			if !ok {
				return fmt.Errorf("the selected backend cannot enumerate a GATT table")
			}
			target := &models.Target{
				ID: models.NewID("target"), Type: models.TargetBluetoothAdapter,
				Value: address, Interface: adapter, CreatedAt: time.Now().UTC(),
			}
			if _, err := appState.Authorize(target, authorizedFrom(cmd)); err != nil {
				if appState.Events != nil {
					appState.Events.Info(events.OperationRefused, map[string]any{
						"operation": "bluetooth.enumerate_gatt", "target": address,
						"reason": err.Error(), "authorization": false,
					})
				}
				return usageErr(err)
			}
			options := transport.GATTEnumerationOptions{
				Timeout: timeout, MTU: mtu, DiscoverDescriptors: discoverDescriptors,
				MaxServices: maxServices, MaxCharacteristics: maxCharacteristics,
				MaxDescriptors: maxDescriptors,
			}
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothGATTEnumerationStarted, map[string]any{
					"adapter": adapter, "address": address, "descriptors": discoverDescriptors,
					"timeout": timeout.String(), "authorized": true, "simulated": false,
					"read_only_requests": true,
				})
			}
			stats, err := provider.EnumerateGATT(ctxOf(cmd), adapter, address, options)
			if err != nil {
				if appState.Events != nil {
					appState.Events.Fail(events.Error, map[string]any{"operation": "bluetooth.enumerate_gatt", "error": err.Error()})
				}
				return fmt.Errorf("enumerate GATT for %s: %w", address, err)
			}
			session := models.NewSession(target)
			if appState.Events != nil {
				session.ExecutionID = appState.Events.ExecutionID()
			}
			session.Attributes["bluetooth_adapter"] = adapter
			session.Attributes["bluetooth_gatt_address"] = address
			session.Attributes["bluetooth_gatt_services"] = strconv.Itoa(stats.Services)
			session.Attributes["bluetooth_gatt_characteristics"] = strconv.Itoa(stats.Characteristics)
			session.Attributes["bluetooth_gatt_descriptors"] = strconv.Itoa(stats.Descriptors)
			session.Attributes["bluetooth_gatt_att_mtu"] = strconv.Itoa(int(stats.MTU))
			session.Attributes["bluetooth_gatt_truncated"] = strconv.FormatBool(stats.Truncated)
			digest := sha256.Sum256(mustJSON(stats.Database))
			session.AddEvidence(models.Evidence{
				ID: models.NewID("evidence"), Kind: models.EvidenceProtocol,
				Source: "att-read-by-group-type-and-read-by-type", Target: address,
				Detail: fmt.Sprintf("ATT enumeration of a live peer: %d services, %d characteristics, %d descriptors, %d requests, negotiated MTU %d, truncated %t; only read-only ATT requests were sent and no pairing was attempted",
					stats.Services, stats.Characteristics, stats.Descriptors, stats.Requests, stats.MTU, stats.Truncated),
				Hash: hex.EncodeToString(digest[:]),
			})
			session.Finish()
			if appState.Events != nil {
				session.ID = appState.Events.ExecutionID()
			}
			if _, err := appState.Store.Save(session); err != nil {
				return fmt.Errorf("save GATT enumeration session: %w", err)
			}
			if appState.Events != nil {
				appState.Events.Info(events.BluetoothGATTEnumerationCompleted, map[string]any{
					"adapter": adapter, "address": address, "services": stats.Services,
					"characteristics": stats.Characteristics, "descriptors": stats.Descriptors,
					"requests": stats.Requests, "att_mtu": stats.MTU, "truncated": stats.Truncated,
					"findings":   len(bluetooth.GATTAccessVerdicts(stats.Database)),
					"session_id": session.ID, "simulated": false,
				})
			}
			appState.Printer.Print(map[string]any{
				"session_id": session.ID, "adapter": adapter, "address": address,
				"att_mtu": stats.MTU, "services": stats.Services,
				"characteristics": stats.Characteristics, "descriptors": stats.Descriptors,
				"requests": stats.Requests, "truncated": stats.Truncated,
				"database": stats.Database, "access_control": bluetooth.GATTAccessVerdicts(stats.Database),
				"simulated": false,
			})
			return nil
		},
	}
	cmd.Flags().String("adapter", "hci0", "already powered HCI adapter")
	cmd.Flags().String("address", "", "peer Bluetooth address to enumerate")
	cmd.Flags().Duration("timeout", 30*time.Second, "overall enumeration timeout (maximum 10m)")
	cmd.Flags().Uint16("mtu", 0, "ATT receive MTU to request from the peer; defaults to 247")
	cmd.Flags().Bool("descriptors", true, "also discover characteristic descriptors")
	cmd.Flags().Int("max-services", 0, "stop after this many services; 0 uses the built-in bound")
	cmd.Flags().Int("max-characteristics", 0, "stop after this many characteristics; 0 uses the built-in bound")
	cmd.Flags().Int("max-descriptors", 0, "stop after this many descriptors; 0 uses the built-in bound")
	return cmd
}

// mustJSON marshals a value for hashing, returning the bytes of an empty object
// if the value cannot be encoded, which keeps hashing from masking the real
// result of an enumeration.
func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}
	return data
}
