package safenet

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

var safeNetInitializationFASCN = []byte{
	0xD4, 0xE7, 0x39, 0xDA, 0x73,
	0x9C, 0xED, 0x39, 0xCE, 0x73,
	0x9D, 0x83, 0x68, 0x58, 0x21,
	0x08, 0x42, 0x10, 0x84, 0x36,
	0xCF, 0x08, 0xD1, 0x43, 0xEB,
}

// DescribeInitialization reports the inputs required for SafeNet token initialization.
func (a *Adapter) DescribeInitialization(session *adapters.Session) (adapters.InitializationRequirements, error) {
	if err := requireSession(session); err != nil {
		return adapters.InitializationRequirements{}, err
	}
	session.Observe(adapters.LogLevelDebug, a, "describe-initialization", "reporting SafeNet initialization capabilities")
	req := adapters.DefaultInitializationRequirementsFromFields(nil)
	req.SupportsClearContainers = true
	req.SupportsProvisionIdentity = true
	return req, nil
}

// InitializeToken runs the SafeNet initialization flow against the provided
// session client.
func (a *Adapter) InitializeToken(session *adapters.Session, params adapters.InitializeTokenParams) (*adapters.InitializationResult, error) {
	if err := requireSessionReaderName(session); err != nil {
		return nil, err
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}

	result := &adapters.InitializationResult{}
	flowSession := session.Clone()
	if len(flowSession.ManagementKey) == 0 {
		flowSession.ManagementKey = append([]byte(nil), defaultManagementKey...)
		flowSession.Observe(adapters.LogLevelDebug, a, "initialize-token", "using default SafeNet management key for initialization")
	}
	if flowSession.ManagementAlgorithm == 0 {
		flowSession.ManagementAlgorithm = piv.AlgAES128
		flowSession.Observe(adapters.LogLevelDebug, a, "initialize-token", "defaulting management key algorithm to AES-128")
	}
	if flowSession.Client == nil {
		return nil, fmt.Errorf("safenet: session client is required for initialization")
	}
	flowSession.Observe(adapters.LogLevelInfo, a, "initialize-token", "starting SafeNet initialization")

	if err := a.runInitialization(flowSession, params, result); err != nil {
		return nil, err
	}
	flowSession.Observe(adapters.LogLevelInfo, a, "initialize-token", "completed SafeNet initialization")
	if trace := flowSession.TraceLog(); len(trace) != 0 {
		result.APDULog = append(result.APDULog, trace...)
	}
	return result, nil
}

func (a *Adapter) runInitialization(session *adapters.Session, params adapters.InitializeTokenParams, result *adapters.InitializationResult) error {
	session.Observe(adapters.LogLevelDebug, a, "initialize-token", "selecting PIV application")
	if err := session.Client.Select(); err != nil {
		return fmt.Errorf("safenet: select piv applet: %w", err)
	}
	result.Steps = append(result.Steps, "select-piv")

	session.Observe(adapters.LogLevelDebug, a, "initialize-token", "enumerating token structure")
	structure, err := a.determineTokenStructure(session)
	if err != nil {
		return err
	}
	result.Steps = append(result.Steps, "enumerate-structure")
	result.Notes = append(result.Notes, fmt.Sprintf("enumerated %d generation tags and %d mirror tags", len(structure.generationTags), len(structure.mirrorTags)))
	session.Observe(adapters.LogLevelInfo, a, "initialize-token", "enumerated %d generation tags and %d mirror tags", len(structure.generationTags), len(structure.mirrorTags))

	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("safenet: authenticate management key: %w", err)
	}
	result.ManagementAuthenticated = true
	result.Steps = append(result.Steps, "authenticate-management")

	if params.ProvisionIdentity {
		session.Observe(adapters.LogLevelInfo, a, "initialize-token", "provisioning CHUID identity objects")
		if err := a.provisionIdentity(session, params, result); err != nil {
			return err
		}
		result.Steps = append(result.Steps, "provision-identity")
	}

	if params.ClearContainers {
		session.Observe(adapters.LogLevelInfo, a, "initialize-token", "clearing SafeNet generation and mirror containers")
		if err := a.clearContainers(session, structure, result); err != nil {
			return err
		}
		result.Steps = append(result.Steps, "clear-containers")
	}

	return nil
}

type safeNetTokenStructure struct {
	generationTags []uint
	mirrorTags     []uint
}

func (a *Adapter) determineTokenStructure(session *adapters.Session) (safeNetTokenStructure, error) {
	session.Observe(adapters.LogLevelDebug, a, "determine-structure", "selecting SafeNet admin applet")
	if err := selectAdminApplet(session.Client); err != nil {
		return safeNetTokenStructure{}, err
	}
	session.Observe(adapters.LogLevelDebug, a, "determine-structure", "reading SafeNet admin version and status")
	if err := readVersion(session.Client); err != nil {
		return safeNetTokenStructure{}, err
	}
	if err := readStatus(session.Client); err != nil {
		return safeNetTokenStructure{}, err
	}
	if err := readInitializationCredentialMetadata(session.Client); err != nil {
		return safeNetTokenStructure{}, err
	}
	session.Observe(adapters.LogLevelDebug, a, "determine-structure", "re-selecting PIV application after admin metadata reads")
	if err := session.Client.Select(); err != nil {
		return safeNetTokenStructure{}, fmt.Errorf("safenet: re-select piv applet: %w", err)
	}

	generationTags, err := readTagList(session.Client, 0x35)
	if err != nil {
		return safeNetTokenStructure{}, err
	}
	for _, tag := range generationTags {
		session.Observe(adapters.LogLevelDebug, a, "determine-structure", "reading generation metadata tag %06X", tag)
		if err := readMetadataTag(session.Client, tag); err != nil {
			return safeNetTokenStructure{}, err
		}
	}

	mirrorTags, err := readTagList(session.Client, 0x34)
	if err != nil {
		return safeNetTokenStructure{}, err
	}
	for _, tag := range mirrorTags {
		session.Observe(adapters.LogLevelDebug, a, "determine-structure", "reading mirror metadata tag %06X", tag)
		if err := readMetadataTag(session.Client, tag); err != nil {
			return safeNetTokenStructure{}, err
		}
	}

	return safeNetTokenStructure{generationTags: generationTags, mirrorTags: mirrorTags}, nil
}

func (a *Adapter) clearContainers(session *adapters.Session, structure safeNetTokenStructure, result *adapters.InitializationResult) error {
	return a.clearContainersInternal(session, structure, func(tag uint, suffix uint) {
		if result != nil {
			result.ContainersCleared = append(result.ContainersCleared, fmt.Sprintf("%06X/%02X", tag, suffix))
		}
	})
}

func (a *Adapter) clearContainersInternal(session *adapters.Session, structure safeNetTokenStructure, record func(tag uint, suffix uint)) error {
	generationSupported := make(map[uint]struct{}, len(structure.generationTags))
	for _, tag := range structure.generationTags {
		generationSupported[tag] = struct{}{}
	}
	mirrorSupported := make(map[uint]struct{}, len(structure.mirrorTags))
	for _, tag := range structure.mirrorTags {
		mirrorSupported[tag] = struct{}{}
	}

	for _, tag := range safeNetResetMirrorTags {
		if _, ok := mirrorSupported[tag]; !ok {
			continue
		}
		session.Observe(adapters.LogLevelDebug, a, "clear-containers", "clearing mirror object %06X/53", tag)
		if err := clearSafeNetObject(session.Client, tag, iso7816.EncodeTLV(0x53, nil)); err != nil {
			return fmt.Errorf("safenet: clear mirror object %X: %w", tag, err)
		}
		if record != nil {
			record(tag, 0x53)
		}
	}

	for _, tag := range safeNetResetGenerationTags {
		if _, ok := generationSupported[tag]; !ok {
			continue
		}
		session.Observe(adapters.LogLevelDebug, a, "clear-containers", "clearing generation object %06X/7F48", tag)
		if err := clearSafeNetObject(session.Client, tag, iso7816.EncodeTLV(0x7F48, nil)); err != nil {
			return fmt.Errorf("safenet: clear generation object %X 7F48: %w", tag, err)
		}
		if record != nil {
			record(tag, 0x7F48)
		}
		session.Observe(adapters.LogLevelDebug, a, "clear-containers", "clearing generation object %06X/7F49", tag)
		if err := clearSafeNetObject(session.Client, tag, iso7816.EncodeTLV(0x7F49, nil)); err != nil {
			return fmt.Errorf("safenet: clear generation object %X 7F49: %w", tag, err)
		}
		if record != nil {
			record(tag, 0x7F49)
		}
	}

	return nil
}

func (a *Adapter) provisionIdentity(session *adapters.Session, params adapters.InitializeTokenParams, result *adapters.InitializationResult) error {
	session.Observe(adapters.LogLevelDebug, a, "provision-identity", "reading CHUID metadata alias %06X", safeNetCHUIDAlias)
	if err := readMetadataTag(session.Client, safeNetCHUIDAlias); err != nil {
		return err
	}
	chuid, err := buildSafeNetCHUID(session.ReaderName, params.InitializedAt)
	if err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "provision-identity", "writing CHUID object")
	if err := session.Client.PutData(safeNetCHUIDAlias, chuid); err != nil {
		return fmt.Errorf("safenet: write chuid: %w", err)
	}
	session.Observe(adapters.LogLevelDebug, a, "provision-identity", "reading back CHUID object")
	if _, err := session.Client.GetData(safeNetCHUIDAlias); err != nil {
		return fmt.Errorf("safenet: read back chuid: %w", err)
	}
	result.ObjectsWritten = append(result.ObjectsWritten, "CHUID")
	result.Notes = append(result.Notes, fmt.Sprintf("CHUID expiry %s", chuidExpiryDate(params.InitializedAt)))
	return nil
}

func buildSafeNetCHUID(readerName string, initializedAt time.Time) ([]byte, error) {
	seedTime := initializedAt.UTC()
	if seedTime.IsZero() {
		seedTime = time.Now().UTC()
	}
	seed := sha256.Sum256([]byte(strings.ToLower(readerName) + ":" + seedTime.Format(time.RFC3339)))
	guid := seed[:16]

	data := make([]byte, 0, 64)
	data = append(data, iso7816.EncodeTLV(0x30, safeNetInitializationFASCN)...)
	data = append(data, iso7816.EncodeTLV(0x34, guid)...)
	data = append(data, iso7816.EncodeTLV(0x35, []byte(chuidExpiryDate(seedTime)))...)
	data = append(data, iso7816.EncodeTLV(0x3E, nil)...)
	data = append(data, iso7816.EncodeTLV(0xFE, nil)...)
	return iso7816.EncodeTLV(0x53, data), nil
}

func chuidExpiryDate(initializedAt time.Time) string {
	base := initializedAt.UTC()
	if base.IsZero() {
		base = time.Now().UTC()
	}
	return base.AddDate(10, 0, 0).Format("20060102")
}

func readInitializationCredentialMetadata(client *piv.Client) error {
	for _, tag := range []uint{0xFF8180, 0xFF8181, 0xFF840B} {
		if err := readMetadataTag(client, tag); err != nil {
			return err
		}
	}
	return nil
}

func readStatus(client *piv.Client) error {
	resp, err := client.Execute(&iso7816.Command{Cla: 0x81, Ins: 0xCB, P1: 0xDF, P2: 0x39, Le: 0x04})
	if err != nil {
		return fmt.Errorf("read SafeNet status: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("read SafeNet status: %w", err)
	}
	return nil
}

func readTagList(client *piv.Client, selector byte) ([]uint, error) {
	resp, err := client.Execute(&iso7816.Command{Cla: 0x81, Ins: 0xCB, P1: 0xDF, P2: selector, Le: 256})
	if err != nil {
		return nil, fmt.Errorf("read SafeNet tag list DF%02X: %w", selector, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("read SafeNet tag list DF%02X: %w", selector, err)
	}

	data := resp.Data
	if len(data)%3 != 0 {
		return nil, fmt.Errorf("read SafeNet tag list DF%02X: unexpected response length %d", selector, len(data))
	}

	tags := make([]uint, 0, len(data)/3)
	for index := 0; index < len(data); index += 3 {
		tag := uint(data[index])<<16 | uint(data[index+1])<<8 | uint(data[index+2])
		tags = append(tags, tag)
	}
	return tags, nil
}
