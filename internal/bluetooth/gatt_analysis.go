package bluetooth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// gattAccessRuleID identifies the writable-without-restriction review rule. It is
// a review signal over collected metadata, not proof of a reachable write.
const gattAccessRuleID = "ble.gatt.access.control"

// GATTAccessVerdict is one characteristic's access-control summary.
type GATTAccessVerdict struct {
	// Service and Characteristic locate the attribute in the database.
	Service        string `json:"service"`
	Characteristic string `json:"characteristic"`

	// Handle is the characteristic value handle a write would target.
	Handle uint16 `json:"handle"`

	// Writable reports that the characteristic advertises a write property.
	Writable bool `json:"writable"`

	// RestrictionFree reports that the characteristic is writable and the
	// provider reported no encryption, authentication, or authorization
	// requirement for writing it.
	RestrictionFree bool `json:"restriction_free"`

	// Permission is the reported write permission set, kept verbatim so a
	// reader can see exactly what the provider claimed.
	Permission models.GATTPermissions `json:"permissions"`
}

// GATTAccessVerdicts summarizes the access control of every characteristic in a
// database, in declaration order.
//
// A verdict is derived only from what the provider reported. A characteristic
// whose provider simply did not fill in the permission fields is reported as
// restriction-free, because an unreported restriction is not a restriction; the
// accompanying finding says so explicitly rather than implying the attribute is
// reachable.
func GATTAccessVerdicts(database models.GATTDatabase) []GATTAccessVerdict {
	verdicts := make([]GATTAccessVerdict, 0)
	for _, service := range database.Services {
		for _, characteristic := range service.Characteristics {
			permissions := characteristic.Permissions
			verdicts = append(verdicts, GATTAccessVerdict{
				Service:         service.UUID,
				Characteristic:  characteristic.UUID,
				Handle:          characteristic.Handle,
				Writable:        isWritable(characteristic),
				RestrictionFree: isWritable(characteristic) && writeUnrestricted(permissions),
				Permission:      permissions,
			})
		}
	}
	return verdicts
}

// isWritable reports whether the characteristic advertises any write property.
func isWritable(characteristic models.GATTCharacteristic) bool {
	for _, property := range characteristic.Properties {
		if property == models.GATTPropertyWrite || property == models.GATTPropertyWriteWithoutResponse {
			return true
		}
	}
	return false
}

// writeUnrestricted reports whether the provider stated any requirement for a
// write. Every field is a statement about what was reported, so an unreported
// field leaves the verdict unrestricted rather than assumed safe.
func writeUnrestricted(permissions models.GATTPermissions) bool {
	return !permissions.WriteEncrypted && !permissions.WriteAuthenticated && !permissions.WriteAuthorized
}

// AnalyzeGATT reviews a saved GATT database for characteristics that advertise a
// write with no reported encryption, authentication, or authorization
// requirement.
//
// The result is a cautious review signal over metadata that was already
// collected. It is not evidence that a remote client can write the attribute: a
// provider that reported nothing is indistinguishable from a provider that did
// not look, and a device may enforce policy in firmware the metadata never
// mentions. Each finding states that limitation.
func AnalyzeGATT(database models.GATTDatabase) []models.Finding {
	now := time.Now().UTC()
	findings := make([]models.Finding, 0)
	for _, service := range database.Services {
		for _, characteristic := range service.Characteristics {
			if !isWritable(characteristic) || !writeUnrestricted(characteristic.Permissions) {
				continue
			}
			properties := ""
			for i, property := range characteristic.Properties {
				if i > 0 {
					properties += ", "
				}
				properties += string(property)
			}
			target := fmt.Sprintf("%s/%s", service.UUID, characteristic.UUID)
			if service.Primary {
				target = service.UUID + "/" + characteristic.UUID
			}
			finding := models.Finding{
				ID:         models.BuildFindingID(gattAccessRuleID, "bluetooth"),
				RuleID:     gattAccessRuleID,
				Title:      "Writable GATT characteristic with no reported access restriction",
				Category:   "bluetooth",
				Severity:   models.SeverityLow,
				Confidence: models.ConfPossible,
				Description: fmt.Sprintf(
					"Characteristic %s in service %s advertises write properties (%s) and the provider reported no encryption, authentication, or authorization requirement for writing it.",
					characteristic.UUID, service.UUID, properties),
				Target:         target,
				Status:         models.FindingDetected,
				Timestamp:      now,
				Recommendation: "Confirm with the vendor how the characteristic is protected in firmware, and pair the device or restrict access at the application layer if the attribute must not be writable.",
				Evidence: []models.Evidence{{
					ID:     models.NewID("evidence"),
					Kind:   models.EvidenceConfig,
					Source: database.DeviceAddress,
					Target: target,
					Detail: fmt.Sprintf("service %s characteristic %s handle 0x%04x properties [%s] write_encrypted=%t write_authenticated=%t write_authorized=%t",
						service.UUID, characteristic.UUID, characteristic.Handle, properties,
						characteristic.Permissions.WriteEncrypted,
						characteristic.Permissions.WriteAuthenticated,
						characteristic.Permissions.WriteAuthorized),
				}},
				References: []string{
					"Core Specification Supplement, Part A, section 3.3.1.7 (Characteristic Properties)",
					"Core Specification Supplement, Part A, section 3.3.4.6 (Characteristic Value attribute)",
				},
			}
			if database.Simulated {
				finding.Description += " This database came from a simulation fixture."
				finding.Severity = models.SeverityInfo
				finding.Confidence = models.ConfPossible
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

// SimulatedGATTDatabase returns a deterministic attribute table with one
// writable characteristic that reports no write restriction and one writable
// characteristic that reports an encrypted write, so a simulated run exercises
// both branches of the analyzer.
func SimulatedGATTDatabase() models.GATTDatabase {
	return models.GATTDatabase{
		DeviceAddress: "de:ad:be:ef:00:01",
		Simulated:     true,
		Services: []models.GATTService{{
			UUID:        "0000180f-0000-1000-8000-00805f9b34fb",
			Primary:     true,
			StartHandle: 0x0010,
			EndHandle:   0x0020,
			Characteristics: []models.GATTCharacteristic{{
				UUID:              "00002a19-0000-1000-8000-00805f9b34fb",
				Handle:            0x0012,
				DeclarationHandle: 0x0011,
				Properties:        []models.GATTProperty{models.GATTPropertyRead, models.GATTPropertyWrite},
				Permissions:       models.GATTPermissions{Read: true, Write: true},
			}, {
				UUID:              "00002a1c-0000-1000-8000-00805f9b34fb",
				Handle:            0x0015,
				DeclarationHandle: 0x0014,
				Properties:        []models.GATTProperty{models.GATTPropertyRead, models.GATTPropertyWriteWithoutResponse},
				Permissions:       models.GATTPermissions{Read: true, WriteEncrypted: true},
			}},
		}, {
			UUID:        "0000180a-0000-1000-8000-00805f9b34fb",
			Primary:     true,
			StartHandle: 0x0021,
			EndHandle:   0x0028,
			Characteristics: []models.GATTCharacteristic{{
				UUID:              "00002a29-0000-1000-8000-00805f9b34fb",
				Handle:            0x0023,
				DeclarationHandle: 0x0022,
				Properties:        []models.GATTProperty{models.GATTPropertyRead},
				Permissions:       models.GATTPermissions{Read: true},
			}},
		}},
	}
}

// LoadGATTDatabase reads a saved GATT attribute table from disk.
//
// A file that does not parse is an error rather than an empty table. Reviewing
// an empty table and reporting that nothing was found would be indistinguishable
// from reviewing a real table that has nothing wrong with it, which is the one
// outcome a validation module must never produce by accident.
func LoadGATTDatabase(path string) (models.GATTDatabase, error) {
	if strings.TrimSpace(path) == "" {
		return models.GATTDatabase{}, errors.New("a GATT attribute table path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return models.GATTDatabase{}, fmt.Errorf("read GATT attribute table %s: %w", path, err)
	}
	var database models.GATTDatabase
	if err := json.Unmarshal(data, &database); err != nil {
		return models.GATTDatabase{}, fmt.Errorf("parse GATT attribute table %s: %w", path, err)
	}
	if database.DeviceAddress == "" {
		return models.GATTDatabase{}, fmt.Errorf("GATT attribute table %s names no device address", path)
	}
	return database, nil
}

// SaveGATTDatabase writes a GATT attribute table to disk.
func SaveGATTDatabase(path string, database models.GATTDatabase) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("a GATT attribute table path is required")
	}
	data, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		return fmt.Errorf("encode GATT attribute table: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write GATT attribute table %s: %w", path, err)
	}
	return nil
}
