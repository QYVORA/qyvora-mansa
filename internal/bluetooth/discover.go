package bluetooth

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Discovery limits. Every walk of a peer's attribute table is bounded so a peer
// cannot make the client allocate without limit or loop forever.
const (
	// MaxDiscoveredServices bounds how many services one enumeration accepts.
	MaxDiscoveredServices = 128
	// MaxDiscoveredCharacteristics bounds characteristics across all services.
	MaxDiscoveredCharacteristics = 512
	// MaxDiscoveredDescriptors bounds descriptors across all characteristics.
	MaxDiscoveredDescriptors = 1024
	// MaxDiscoveryRequests bounds the total number of ATT requests issued for one
	// peer, which caps a peer that answers every request with another page.
	MaxDiscoveryRequests = 4096
	// DefaultDiscoveryTimeout bounds one enumeration when the caller sets no
	// deadline of its own.
	DefaultDiscoveryTimeout = 30 * time.Second
	// DefaultDiscoveryMTU is the ATT receive MTU requested from a peer. It matches
	// the largest ACL data payload a controller reports, so no request is fragmented
	// when the peer agrees.
	DefaultDiscoveryMTU = 247
)

// ErrDiscoveryLimit reports that a peer's attribute table exceeded a bound. It is
// a refusal to continue, not evidence that the peer is malformed.
var ErrDiscoveryLimit = errors.New("the peer's attribute table exceeded the discovery limit")

// DiscoveryLimits bounds one enumeration. A zero field takes the package default,
// so a caller that only wants to bound one dimension can say so.
type DiscoveryLimits struct {
	Services        int
	Characteristics int
	Descriptors     int
	Requests        int
}

// withDefaults fills every unset field with its package default.
func (l DiscoveryLimits) withDefaults() DiscoveryLimits {
	if l.Services <= 0 {
		l.Services = MaxDiscoveredServices
	}
	if l.Characteristics <= 0 {
		l.Characteristics = MaxDiscoveredCharacteristics
	}
	if l.Descriptors <= 0 {
		l.Descriptors = MaxDiscoveredDescriptors
	}
	if l.Requests <= 0 {
		l.Requests = MaxDiscoveryRequests
	}
	return l
}

// DiscoveryStats counts what one enumeration observed. The counters are what the
// command reports, so a truncated walk is visible rather than implied.
type DiscoveryStats struct {
	Services        int  `json:"services"`
	Characteristics int  `json:"characteristics"`
	Descriptors     int  `json:"descriptors"`
	Requests        int  `json:"requests"`
	Truncated       bool `json:"truncated"`
}

// DiscoveredAttribute is one attribute the peer reported.
//
// Type is the declaration type that identified the attribute during discovery and
// UUID is the value the peer reported for it. A service declaration has a type of
// 0x2800 and a UUID of the service it declares, so the two must not be conflated.
type DiscoveredAttribute struct {
	Handle    uint16
	EndHandle uint16
	Type      string
	UUID      string
	// Properties and ValueHandle are set only for characteristic declarations.
	Properties  uint8
	ValueHandle uint16
}

// Discoverer accumulates the responses from one peer into a GATT database.
//
// The type holds no I/O state: a caller performs each request, feeds the
// response to the matching method, and stops when the method reports the range is
// complete. That keeps the protocol rules testable without a controller.
type Discoverer struct {
	deviceAddress   string
	limits          DiscoveryLimits
	attributes      []DiscoveredAttribute
	requests        int
	services        int
	characteristics int
	descriptors     int
	truncated       bool
}

// NewDiscoverer returns a discoverer for a peer address using the package bounds.
func NewDiscoverer(address string) *Discoverer {
	return NewDiscovererWithLimits(address, DiscoveryLimits{})
}

// NewDiscovererWithLimits returns a discoverer for a peer address with explicit
// bounds, so a caller can hold a walk to less than the package defaults.
func NewDiscovererWithLimits(address string, limits DiscoveryLimits) *Discoverer {
	return &Discoverer{deviceAddress: address, limits: limits.withDefaults()}
}

// Requests reports how many responses have been consumed.
func (d *Discoverer) Requests() int { return d.requests }

// Truncated reports whether a discovery bound stopped the walk before the peer's
// attribute table was fully described.
func (d *Discoverer) Truncated() bool { return d.truncated }

// Services reports how many services of a declaration type have been recorded, so
// a caller can stop paging a range once its own bound is reached.
func (d *Discoverer) Services(serviceType uint16) int {
	wanted := FormatUUID(serviceType)
	count := 0
	for _, attribute := range d.attributes {
		if attribute.Type == wanted {
			count++
		}
	}
	return count
}

// Attributes returns everything recorded so far, in discovery order, so a walk
// can be audited or resumed.
func (d *Discoverer) Attributes() []DiscoveredAttribute {
	return append([]DiscoveredAttribute(nil), d.attributes...)
}

// countRequest accounts for one request, refusing to continue past the bound.
func (d *Discoverer) countRequest() error {
	d.requests++
	if d.requests > d.limits.Requests {
		d.truncated = true
		return fmt.Errorf("%w: more than %d responses", ErrDiscoveryLimit, d.limits.Requests)
	}
	return nil
}

// record appends one attribute against the bound for the kind of declaration it
// is. A refusal marks the walk truncated so a partial table is never presented as
// the peer's complete one.
func (d *Discoverer) record(kind string, attribute DiscoveredAttribute, limit int) error {
	switch kind {
	case "service":
		if d.services+1 > limit {
			d.truncated = true
			return fmt.Errorf("%w: more than %d services", ErrDiscoveryLimit, limit)
		}
		d.services++
	case "characteristic":
		if d.characteristics+1 > limit {
			d.truncated = true
			return fmt.Errorf("%w: more than %d characteristics", ErrDiscoveryLimit, limit)
		}
		d.characteristics++
	default:
		if d.descriptors+1 > limit {
			d.truncated = true
			return fmt.Errorf("%w: more than %d descriptors", ErrDiscoveryLimit, limit)
		}
		d.descriptors++
	}
	d.attributes = append(d.attributes, attribute)
	return nil
}

// RecordServices consumes one read-by-group-type response listing services. It
// returns the handle the next request must start from and whether the range is
// complete.
func (d *Discoverer) RecordServices(serviceType uint16, pdu []byte) (nextStart uint16, done bool, err error) {
	if err := d.countRequest(); err != nil {
		return 0, true, err
	}
	entries, nextStart, done, err := ParseServiceResponse(pdu)
	if err != nil {
		return 0, false, err
	}
	if done {
		return 0, true, nil
	}
	for _, entry := range entries {
		if err := d.record("service", DiscoveredAttribute{
			Handle:    entry.DeclarationHandle,
			EndHandle: entry.EndGroupHandle,
			Type:      FormatUUID(serviceType),
			UUID:      entry.UUID,
		}, d.limits.Services); err != nil {
			return 0, true, err
		}
	}
	return nextStart, false, nil
}

// RecordCharacteristics consumes one read-by-type response listing characteristics
// and appends each declaration together with its value attribute, which carries
// the characteristic UUID.
func (d *Discoverer) RecordCharacteristics(pdu []byte) (nextStart uint16, done bool, err error) {
	if err := d.countRequest(); err != nil {
		return 0, true, err
	}
	entries, nextStart, done, err := ParseCharacteristicResponse(pdu)
	if err != nil {
		return 0, false, err
	}
	if done {
		return 0, true, nil
	}
	for _, entry := range entries {
		if err := d.record("characteristic", DiscoveredAttribute{
			Handle: entry.DeclarationHandle, Type: FormatUUID(UUIDCharacteristicDeclaration),
			Properties: entry.Properties, ValueHandle: entry.ValueHandle,
		}, d.limits.Characteristics); err != nil {
			return 0, true, err
		}
		d.attributes = append(d.attributes, DiscoveredAttribute{
			Handle: entry.ValueHandle, Type: entry.UUID, UUID: entry.UUID,
		})
	}
	return nextStart, false, nil
}

// RecordAttributeRange consumes one find-information response covering the
// descriptors after a characteristic value and appends the attributes it
// described. The handle after the last one is returned so the caller can page
// through the range.
func (d *Discoverer) RecordAttributeRange(pdu []byte, limit int) (nextStart uint16, done bool, err error) {
	if err := d.countRequest(); err != nil {
		return 0, true, err
	}
	attributes, nextStart, _, err := ParseFindInformationResponse(pdu)
	if err != nil {
		return 0, false, err
	}
	if limit <= 0 || limit > d.limits.Descriptors {
		limit = d.limits.Descriptors
	}
	for _, attribute := range attributes {
		if err := d.record("descriptor", DiscoveredAttribute{
			Handle: attribute.Handle, Type: attribute.UUID, UUID: attribute.UUID,
		}, limit); err != nil {
			return 0, true, err
		}
	}
	return nextStart, false, nil
}

// Database builds the normalized snapshot from everything recorded.
//
// Permissions are derived from the characteristic properties the peer reported.
// The encryption and authorization flags stay false because ATT does not report
// them; a false flag means no restriction was reported, not that a remote client
// can reach the attribute.
func (d *Discoverer) Database() (models.GATTDatabase, DiscoveryStats) {
	byHandle := make(map[uint16]DiscoveredAttribute, len(d.attributes))
	for _, attribute := range d.attributes {
		byHandle[attribute.Handle] = attribute
	}
	ordered := make([]DiscoveredAttribute, 0, len(byHandle))
	for _, attribute := range byHandle {
		ordered = append(ordered, attribute)
	}
	sortByHandle(ordered)

	database := models.GATTDatabase{DeviceAddress: d.deviceAddress}
	primaryType := FormatUUID(UUIDPrimaryService)
	secondaryType := FormatUUID(UUIDSecondaryService)
	includeType := FormatUUID(UUIDInclude)
	declarationType := FormatUUID(UUIDCharacteristicDeclaration)

	// The counters describe what was attached to the snapshot, not what was
	// received. A declaration whose service or value attribute is missing, and an
	// include that names another service, are recorded but cannot appear in the
	// database, so counting them would overstate the result.
	stats := DiscoveryStats{Requests: d.requests, Truncated: d.truncated}
	for _, attribute := range ordered {
		switch attribute.Type {
		case primaryType, secondaryType:
			database.Services = append(database.Services, models.GATTService{
				UUID:        attribute.UUID,
				Primary:     attribute.Type == primaryType,
				StartHandle: attribute.Handle,
				EndHandle:   attribute.EndHandle,
			})
			stats.Services++
		case declarationType:
			// The declaration identifies the characteristic; the value attribute
			// carries its UUID and is attached by handle.
			service := serviceForHandle(database.Services, attribute.Handle)
			if service == nil {
				continue
			}
			value, ok := byHandle[attribute.ValueHandle]
			if !ok || value.UUID == "" {
				continue
			}
			service.Characteristics = append(service.Characteristics, models.GATTCharacteristic{
				UUID:              value.UUID,
				Handle:            value.Handle,
				DeclarationHandle: attribute.Handle,
				Properties:        propertiesFor(attribute.Properties),
				Permissions:       permissionsFor(attribute.Properties),
			})
			stats.Characteristics++
		case includeType:
			// An include names another service and needs the included service
			// resolved, which the caller may request separately. It is neither a
			// characteristic nor a descriptor, so nothing is attached here.
		default:
			characteristic := characteristicForHandle(database.Services, attribute.Handle)
			if characteristic == nil {
				continue
			}
			if isCharacteristicValue(byHandle, attribute.Handle) {
				continue
			}
			if len(characteristic.Descriptors) >= d.limits.Descriptors {
				d.truncated = true
				continue
			}
			characteristic.Descriptors = append(characteristic.Descriptors, models.GATTDescriptor{
				UUID: attribute.UUID, Handle: attribute.Handle,
			})
			stats.Descriptors++
		}
	}
	return database, stats
}

// serviceForHandle returns the service whose handle range covers a handle.
func serviceForHandle(services []models.GATTService, handle uint16) *models.GATTService {
	for i := range services {
		if handle >= services[i].StartHandle && handle <= services[i].EndHandle {
			return &services[i]
		}
	}
	return nil
}

// characteristicForHandle returns the characteristic a descriptor belongs to. A
// descriptor always follows its characteristic's value attribute, so the owner is
// the last characteristic whose value handle precedes the descriptor.
func characteristicForHandle(services []models.GATTService, handle uint16) *models.GATTCharacteristic {
	for i := range services {
		if handle < services[i].StartHandle || handle > services[i].EndHandle {
			continue
		}
		for j := range services[i].Characteristics {
			if handle > services[i].Characteristics[j].Handle {
				return &services[i].Characteristics[j]
			}
		}
	}
	return nil
}

// isCharacteristicValue reports whether a handle is the value attribute of a
// characteristic declaration, which must not be recorded as a descriptor.
func isCharacteristicValue(byHandle map[uint16]DiscoveredAttribute, handle uint16) bool {
	for _, attribute := range byHandle {
		if attribute.ValueHandle != 0 && attribute.ValueHandle == handle {
			return true
		}
	}
	return false
}

func propertiesFor(bits uint8) []models.GATTProperty {
	var properties []models.GATTProperty
	if bits&0x02 != 0 {
		properties = append(properties, models.GATTPropertyRead)
	}
	if bits&0x08 != 0 {
		properties = append(properties, models.GATTPropertyWrite)
	}
	if bits&0x04 != 0 {
		properties = append(properties, models.GATTPropertyWriteWithoutResponse)
	}
	if bits&0x10 != 0 {
		properties = append(properties, models.GATTPropertyNotify)
	}
	if bits&0x20 != 0 {
		properties = append(properties, models.GATTPropertyIndicate)
	}
	return properties
}

func permissionsFor(bits uint8) models.GATTPermissions {
	// Only the plain read and write properties can be read from an ATT
	// declaration. No encryption or authorization property exists in ATT, so
	// those flags stay false and the model's documentation records what that means.
	return models.GATTPermissions{Read: bits&0x02 != 0, Write: bits&0x08 != 0}
}

// sortByHandle orders attributes ascending so services, characteristics, and
// descriptors appear in the handle order the peer reported.
func sortByHandle(attributes []DiscoveredAttribute) {
	sort.Slice(attributes, func(i, j int) bool { return attributes[i].Handle < attributes[j].Handle })
}
