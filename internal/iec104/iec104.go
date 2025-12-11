package iec104

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
)

// PacketToProcess encapsula un paquete y su contexto de filtrado para los workers.
type PacketToProcess struct {
	Payload       []byte
	LocalIP       string
	SourceIP      string
	DestinationIP string
	TypeFilter    string
	PointFilter   map[int]struct{}
	RawOutput     bool
}

const (
	StartByte = 0x68 // Exportado para uso en otros paquetes

	// Tipos de ASDU (Type Identification)
	TypeIDSpNa        = 1  // M_SP_NA_1 - Single-point information
	TypeIDMvf         = 13 // M_ME_NC_1 - Measured value, short floating point number
	TypeIDMvfWithTime = 36 // M_ME_TF_1 - Measured value, short floating point number with time tag CP56Time2a
	TypeIDSiq         = 30 // M_SP_TB_1 - Single-point information with time tag CP56Time2a
	TypeIDDiq         = 31 // M_DP_TB_1 - Double-point information with time tag CP56Time2a
	TypeIDStTb        = 32 // M_ST_TB_1 - Step position information with time tag CP56Time2a
	TypeIDSingleCmd   = 45 // C_SC_NA_1 - Single command
	TypeIDDoubleCmd   = 46 // C_DC_NA_1 - Double command
)

// TypeInfo y typeInfoMap para la descripción detallada de las tramas.
type TypeInfo struct {
	Name        string
	Description string
}

var typeInfoMap = map[byte]TypeInfo{
	// Medidos / Eventos
	TypeIDSpNa:        {"M_SP_NA_1", "Single-point information"},
	TypeIDMvf:         {"M_ME_NC_1", "Measured value, short floating point number"},
	TypeIDMvfWithTime: {"M_ME_TF_1", "Measured value, short floating point number with time tag CP56Time2a"},
	TypeIDSiq:         {"M_SP_TB_1", "Single-point information with time tag CP56Time2a"},
	TypeIDDiq:         {"M_DP_TB_1", "Double-point information with time tag CP56Time2a"},
	TypeIDStTb:        {"M_ST_TB_1", "Step position information with time tag CP56Time2a"},

	// Comandos
	TypeIDSingleCmd: {"C_SC_NA_1", "Single command"},
	TypeIDDoubleCmd: {"C_DC_NA_1", "Double command"},

	// U-Frames (informativos)
	250: {"U-FRAME TESTFR (Activation)", "Test Frame Activation"},
	251: {"U-FRAME TESTFR (Confirm)", "Test Frame Confirmation"},
	252: {"U-FRAME STARTDT (Activation)", "Start Data Transfer Activation"},
	253: {"U-FRAME STARTDT (Confirm)", "Start Data Transfer Confirmation"},
	254: {"U-FRAME STOPDT (Activation)", "Stop Data Transfer Activation"},
	255: {"U-FRAME STOPDT (Confirm)", "Stop Data Transfer Confirmation"},
}

// Mapa con descripciones para la Causa de la Transmisión (COT).
var cotInfoMap = map[uint16]string{
	1:  "periodic, cyclic",
	2:  "background scan",
	3:  "spontaneous",
	4:  "initialized",
	5:  "interrogation or interrogated",
	6:  "activation",
	7:  "activation confirmation",
	8:  "deactivation",
	9:  "deactivation confirmation",
	10: "activation termination",
	20: "interrogated by general interrogation",
}

// ProcessPacketWorker determina la dirección del paquete.
func ProcessPacketWorker(ch <-chan PacketToProcess) {
	for p := range ch {
		direction := "Rx"
		if p.SourceIP == p.LocalIP {
			direction = "Tx"
		}
		output := parseAPDU(p.Payload, p.TypeFilter, p.PointFilter, direction, p.SourceIP, p.DestinationIP)
		if output != "" {
			timestamp := time.Now().Format("15:04:05.000")
			if p.RawOutput {
				fmt.Printf("\n%s\n%s", timestamp, hexDump(p.Payload))
			} else {
				fmt.Printf("\n%s\n", timestamp)
			}
			fmt.Print(output)
		}
	}
}

// parseAPDU ahora recibe y utiliza la información de red.
func parseAPDU(data []byte, typeFilter string, pointFilter map[int]struct{}, direction, srcIP, dstIP string) string {
	if len(data) < 6 {
		return ""
	}
	flowInfo := fmt.Sprintf("[%s] %s -> %s", direction, srcIP, dstIP)
	control1 := data[2]
	control3 := data[4]
	control4 := data[5]

	switch {
	case (control1 & 0x01) == 0:
		return parseIFrame(data, typeFilter, pointFilter, flowInfo)
	case (control1 & 0x03) == 0x01:
		return parseSFrame(control3, control4, typeFilter, flowInfo)
	case (control1 & 0x03) == 0x03:
		return parseUFrame(control1, typeFilter, flowInfo)
	}
	return ""
}

// parseIFrame con la lógica de parseo de puntos refactorizada para ser más robusta.
func parseIFrame(data []byte, typeFilter string, pointFilter map[int]struct{}, flowInfo string) string {
	if len(data) < 12 {
		return ""
	}
	sendSeqNum := int(binary.LittleEndian.Uint16(data[2:4]) >> 1)
	recvSeqNum := int(binary.LittleEndian.Uint16(data[4:6]) >> 1)
	asdu := data[6:]
	if len(asdu) < 6 {
		return ""
	}

	typeID := asdu[0]

	// Nota: este filtro "rango 13..36" permite que pasen tipos medidos comunes; si se usa "control",
	// siempre deja pasar. (Se mantiene la lógica original.)
	if !applyFilter("control", 0, typeFilter, nil) && (typeID < TypeIDMvf || typeID > TypeIDMvfWithTime) {
		if typeFilter == "control" {
			// no-op
		} else {
			return ""
		}
	}

	info, ok := typeInfoMap[typeID]
	if !ok {
		info = TypeInfo{Name: "UNKNOWN", Description: "Tipo de dato no identificado"}
	}

	cot := binary.LittleEndian.Uint16(asdu[2:4])
	casdu := binary.LittleEndian.Uint16(asdu[4:6])
	cotDesc, ok := cotInfoMap[cot]
	if !ok {
		cotDesc = "Unknown"
	}

	header := fmt.Sprintf("%s \n I-FRAME (%s \n ID [%d] \n %s) \n N(S)=%d N(R)=%d\tCause: %d (%s) \n Common Addr: %d\n",
		flowInfo, info.Name, typeID, info.Description, sendSeqNum, recvSeqNum, cot, cotDesc, casdu)

	var asduOutput strings.Builder
	numObjects := int(asdu[1] & 0x7F)
	isSequence := (asdu[1] & 0x80) != 0
	cursor := 6 // Cursor de bytes para el payload del ASDU

	var sequenceAddress uint32
	if isSequence {
		if len(asdu) < cursor+3 {
			return ""
		}
		var tempAddrBytes [4]byte
		copy(tempAddrBytes[0:3], asdu[cursor:cursor+3])
		sequenceAddress = binary.LittleEndian.Uint32(tempAddrBytes[:])
		cursor += 3
	}

	for i := 0; i < numObjects; i++ {
		var addr uint32
		if !isSequence {
			if len(asdu) < cursor+3 {
				break
			}
			var tempAddrBytes [4]byte
			copy(tempAddrBytes[0:3], asdu[cursor:cursor+3])
			addr = binary.LittleEndian.Uint32(tempAddrBytes[:])
			cursor += 3
		} else {
			addr = sequenceAddress + uint32(i)
		}

		var pointOutput string

		switch typeID {
		// --- Nuevos: Single point sin tiempo ---
		case TypeIDSpNa:
			const dataSize = 1 // SIQ (1)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("digital", int(addr), typeFilter, pointFilter) {
				siq := asdu[cursor]
				spi := siq & 0x01
				pointOutput = fmt.Sprintf("\tSINGLE\tAddr: %-6d\tVal: %d\tSIQ: 0x%02X\n", addr, spi, siq)
			}
			cursor += dataSize

		// --- Medidos: float corto (M_ME_NC_1) ---
		case TypeIDMvf:
			const dataSize = 5 // Value(4) + QDS(1)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("analog", int(addr), typeFilter, pointFilter) {
				value := math.Float32frombits(binary.LittleEndian.Uint32(asdu[cursor : cursor+4]))
				qds := asdu[cursor+4]
				pointOutput = fmt.Sprintf("\tANALOG\tAddr: %-6d\tVal: %-10.6f\tQDS: 0x%02X\n", addr, value, qds)
			}
			cursor += dataSize

		case TypeIDMvfWithTime:
			const dataSize = 12 // Value(4) + QDS(1) + Timestamp(7)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("analog", int(addr), typeFilter, pointFilter) {
				valueBits := binary.LittleEndian.Uint32(asdu[cursor : cursor+4])
				value := math.Float32frombits(valueBits)
				qds := asdu[cursor+4]
				ts := parseCP56(asdu[cursor+5 : cursor+12])
				pointOutput = fmt.Sprintf(
					"\tANALOG_T\tAddr: %-6d\tVal: %-10.6f\tQDS: 0x%02X\tTime: %s\n",
					addr, value, qds, ts.Format("15:04:05.000"))
			}
			cursor += dataSize

		case TypeIDSiq:
			const dataSize = 8 // SIQ(1) + Timestamp(7)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("digital", int(addr), typeFilter, pointFilter) {
				spi := asdu[cursor] & 0x01
				ts := parseCP56(asdu[cursor+1 : cursor+8])
				pointOutput = fmt.Sprintf("\tSINGLE\tAddr: %-6d\tVal: %d\tTime: %s\n", addr, spi, ts.Format("15:04:05.000"))
			}
			cursor += dataSize

		case TypeIDDiq:
			const dataSize = 8 // DPI(1) + Timestamp(7)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("double", int(addr), typeFilter, pointFilter) {
				dpi := asdu[cursor] & 0x03
				ts := parseCP56(asdu[cursor+1 : cursor+8])
				pointOutput = fmt.Sprintf("\tDOUBLE\tAddr: %-6d\tVal: %d\tTime: %s\n", addr, dpi, ts.Format("15:04:05.000"))
			}
			cursor += dataSize

		// --- Nuevo: Step position con tiempo (M_ST_TB_1) ---
		case TypeIDStTb:
			const dataSize = 9 // VTI(1) + QDS(1) + Timestamp(7)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("analog", int(addr), typeFilter, pointFilter) {
				vti := asdu[cursor]
				raw := int(vti & 0x7F) // 7 bits (signed -64..+63)
				if raw >= 64 {
					raw = raw - 128
				}
				transient := (vti & 0x80) != 0
				qds := asdu[cursor+1]
				ts := parseCP56(asdu[cursor+2 : cursor+9])
				pointOutput = fmt.Sprintf("\tSTEP_T\tAddr: %-6d\tVTI: %d\tT:%t\tQDS: 0x%02X\tTime: %s\n",
					addr, raw, transient, qds, ts.Format("15:04:05.000"))
			}
			cursor += dataSize

		// --- Nuevos: Comandos (sin tiempo) ---
		case TypeIDSingleCmd:
			const dataSize = 1 // SCO (1)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("control", int(addr), typeFilter, pointFilter) {
				sco := asdu[cursor]
				se := (sco & 0x80) != 0
				qu := int((sco >> 2) & 0x1F)
				scs := int(sco & 0x01)
				pointOutput = fmt.Sprintf("\tCMD_SC\tAddr: %-6d\tS/E:%t\tSCS:%d\tQU:%d\n", addr, se, scs, qu)
			}
			cursor += dataSize

		case TypeIDDoubleCmd:
			const dataSize = 1 // DCO (1)
			if len(asdu) < cursor+dataSize {
				break
			}
			if applyFilter("control", int(addr), typeFilter, pointFilter) {
				dco := asdu[cursor]
				se := (dco & 0x80) != 0
				qu := int((dco >> 2) & 0x1F)
				dcs := int(dco & 0x03)
				pointOutput = fmt.Sprintf("\tCMD_DC\tAddr: %-6d\tS/E:%t\tDCS:%d\tQU:%d\n", addr, se, dcs, qu)
			}
			cursor += dataSize

		default:
			i = numObjects // Tipo desconocido: salimos del bucle
		}

		if pointOutput != "" {
			asduOutput.WriteString(pointOutput)
		}
	}

	if asduOutput.Len() > 0 {
		return header + asduOutput.String()
	}
	return ""
}

func parseSFrame(control3, control4 byte, typeFilter, flowInfo string) string {
	if !applyFilter("control", 0, typeFilter, nil) {
		return ""
	}
	recvSeqNum := int(binary.LittleEndian.Uint16([]byte{control3, control4}) >> 1)
	return fmt.Sprintf("%s \n S-FRAME (Supervisory-frame) \n ACK, N(R)=%d\n", flowInfo, recvSeqNum)
}

func parseUFrame(control1 byte, typeFilter, flowInfo string) string {
	if !applyFilter("control", 0, typeFilter, nil) {
		return ""
	}
	var uTypeID byte
	switch {
	case (control1 & 0b01000000) != 0:
		uTypeID = 250
	case (control1 & 0b10000000) != 0:
		uTypeID = 251
	case (control1 & 0b00000100) != 0:
		uTypeID = 252
	case (control1 & 0b00001000) != 0:
		uTypeID = 253
	case (control1 & 0b00010000) != 0:
		uTypeID = 254
	case (control1 & 0b00100000) != 0:
		uTypeID = 255
	default:
		return fmt.Sprintf("%s \n U-FRAME (Unknown)\n", flowInfo)
	}
	info := typeInfoMap[uTypeID]
	return fmt.Sprintf("%s \n %s \n ID [%d]\n", flowInfo, info.Name, uTypeID)
}

func applyFilter(dataType string, addr int, typeFilter string, pointFilter map[int]struct{}) bool {
	if typeFilter != "" && typeFilter != "all" {
		filters := strings.Split(typeFilter, ",")
		typeMatch := false
		for _, f := range filters {
			if strings.TrimSpace(f) == dataType {
				typeMatch = true
				break
			}
		}
		if !typeMatch {
			return false
		}
	}
	if len(pointFilter) > 0 {
		_, ok := pointFilter[addr]
		return ok
	}
	return true
}

func parseCP56(buf []byte) time.Time {
	if len(buf) < 7 {
		return time.Time{}
	}
	ms := int(binary.LittleEndian.Uint16(buf[0:2]))
	min := int(buf[2] & 0x3F)
	hour := int(buf[3] & 0x1F)
	day := int(buf[4] & 0x1F)
	month := int(buf[5] & 0x0F)
	year := 2000 + int(buf[6]&0x7F)
	return time.Date(year, time.Month(month), day, hour, min, ms/1000, (ms%1000)*1e6, time.UTC)
}

func hexDump(data []byte) string {
	var sb strings.Builder
	sb.WriteString("--- RAW PACKET ---\n")
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]
		hexPart := strings.ToUpper(hex.EncodeToString(line))
		spacedHex := ""
		for j := 0; j < len(hexPart); j += 2 {
			spacedHex += hexPart[j:j+2] + " "
		}
		sb.WriteString(fmt.Sprintf(" %04X: %-48s\n", i, spacedHex))
	}
	return sb.String()
}
