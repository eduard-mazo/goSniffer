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
	Payload     []byte
	TypeFilter  string
	PointFilter map[int]struct{}
	RawOutput   bool
}

// Constantes del protocolo IEC 104
const (
	StartByte = 0x68

	// Tipos de ASDU (Type Identification)
	TypeIDMvf = 13 // Measured value, normalized value
	TypeIDSiq = 30 // Single-point information with time tag
	TypeIDDiq = 31 // Double-point information with time tag
)

// ProcessPacketWorker es la función ejecutada por cada worker.
func ProcessPacketWorker(ch <-chan PacketToProcess) {
	for p := range ch {
		output := parseAPDU(p.Payload, p.TypeFilter, p.PointFilter)
		if output != "" {
			timestamp := time.Now().Format("15:04:05.000")
			fmt.Printf("\n%s\n", timestamp)
			if p.RawOutput {
				fmt.Print(hexDump(p.Payload))
			}
			fmt.Print(output)
		}
	}
}

// parseAPDU es el punto de entrada principal para decodificar una trama.
func parseAPDU(data []byte, typeFilter string, pointFilter map[int]struct{}) string {
	// APDU minimum length is 6 bytes (APCI only)
	if len(data) < 6 {
		return ""
	}

	// APCI (Control Field)
	control1 := data[2]
	// control2 := data[3] // Not directly used for frame type identification
	control3 := data[4]
	control4 := data[5] // CORRECTED: Changed from 'con5]' to 'data[5]'

	// Identify frame type (I, S, U) based on the first control octet
	switch {
	case (control1 & 0x01) == 0: // I-Frame (bit 0 is 0)
		return parseIFrame(data, typeFilter, pointFilter)
	case (control1 & 0x03) == 0x01: // S-Frame (bit 0 is 1, bit 1 is 0)
		return parseSFrame(control3, control4, typeFilter)
	case (control1 & 0x03) == 0x03: // U-Frame (bit 0 is 1, bit 1 is 1)
		return parseUFrame(control1, typeFilter)
	}
	return ""
}

// parseIFrame decodifica tramas de información (que llevan datos ASDU).
func parseIFrame(data []byte, typeFilter string, pointFilter map[int]struct{}) string {
	// If typeFilter is "control", I-frames (data frames) should be skipped.
	if typeFilter == "control" {
		return ""
	}

	// An I-frame with ASDU must have at least 6 bytes for APCI + 6 bytes for minimum ASDU header
	if len(data) < 12 { // 6 (APCI) + 6 (ASDU header: TypeID, NumObjects, Cause(2), CommonAddr(2))
		return ""
	}

	// N(S) and N(R) sequence numbers (bits 1-15 of control fields 1,2 and 3,4 respectively)
	sendSeqNum := int(binary.LittleEndian.Uint16(data[2:4]) >> 1)
	recvSeqNum := int(binary.LittleEndian.Uint16(data[4:6]) >> 1)

	asdu := data[6:]   // ASDU starts after the 6-byte APCI
	if len(asdu) < 6 { // Minimum ASDU header length
		return ""
	}

	typeID := asdu[0]
	numObjects := int(asdu[1] & 0x7F)   // Number of information objects (bits 0-6)
	isSequence := (asdu[1] & 0x80) != 0 // SQ bit (bit 7)

	// Cause of Transmission (COT) and Common Address of ASDU (CA)
	cause := binary.LittleEndian.Uint16(asdu[2:4])
	commonAddr := binary.LittleEndian.Uint16(asdu[4:6])

	var asduOutput strings.Builder
	cursor := 6 // Cursor starts after the 6-byte ASDU header

	// Handle SQ=1 (Sequence of Information Objects)
	var sequenceAddress uint32
	if isSequence {
		// If SQ=1, the address is common to all objects and is read once.
		// It's a 3-byte address.
		if len(asdu) < cursor+3 {
			return "" // Not enough data for sequence address
		}
		// Read 3-byte address into a 4-byte buffer and then convert to uint32
		var tempAddrBytes [4]byte
		copy(tempAddrBytes[0:3], asdu[cursor:cursor+3])
		sequenceAddress = binary.LittleEndian.Uint32(tempAddrBytes[:]) // Use the 4-byte buffer
		cursor += 3
	}

	for i := 0; i < numObjects; i++ {
		var addr uint32
		if !isSequence {
			// If SQ=0, each object has its own 3-byte address.
			if len(asdu) < cursor+3 {
				break // Not enough data for object address, exit loop
			}
			// Read 3-byte address into a 4-byte buffer and then convert to uint32
			var tempAddrBytes [4]byte
			copy(tempAddrBytes[0:3], asdu[cursor:cursor+3])
			addr = binary.LittleEndian.Uint32(tempAddrBytes[:]) // Use the 4-byte buffer
			cursor += 3
		} else {
			addr = sequenceAddress // Use the pre-read sequence address
		}

		var pointOutput string
		currentObjectSize := 0

		switch typeID {
		case TypeIDMvf: // Measured value, normalized value (M_ME_NA_1)
			currentObjectSize = 5 // Value (4 bytes float) + QDS (1 byte)
			if len(asdu) < cursor+currentObjectSize {
				break
			}
			if applyFilter("analog", int(addr), typeFilter, pointFilter) {
				value := math.Float32frombits(binary.LittleEndian.Uint32(asdu[cursor : cursor+4]))
				qds := asdu[cursor+4] // Quality Descriptor
				pointOutput = fmt.Sprintf("\t ANALOG    Addr: %-6d | Val: %-10.6f | QDS: 0x%02X\n", addr, value, qds)
			}
			cursor += currentObjectSize
		case TypeIDSiq: // Single-point information with time tag (M_SP_TB_1)
			currentObjectSize = 8 // SPI (1 byte) + CP56Time2a (7 bytes)
			if len(asdu) < cursor+currentObjectSize {
				break
			}
			if applyFilter("digital", int(addr), typeFilter, pointFilter) {
				spi := asdu[cursor] & 0x01 // Single-point information (SCO: bit 0)
				ts := parseCP56(asdu[cursor+1 : cursor+8])
				pointOutput = fmt.Sprintf("\t DIGITAL   Addr: %-6d | Val: %d | Time: %s\n", addr, spi, ts.Format("15:04:05.000"))
			}
			cursor += currentObjectSize
		case TypeIDDiq: // Double-point information with time tag (M_DP_TB_1)
			currentObjectSize = 8 // DPI (1 byte) + CP56Time2a (7 bytes)
			if len(asdu) < cursor+currentObjectSize {
				break
			}
			if applyFilter("double", int(addr), typeFilter, pointFilter) {
				dpi := (asdu[cursor] >> 6) & 0x03 // Double-point information (bits 6-7)
				ts := parseCP56(asdu[cursor+1 : cursor+8])
				pointOutput = fmt.Sprintf("\t DOUBLE    Addr: %-6d | Val: %d | Time: %s\n", addr, dpi, ts.Format("15:04:05.000"))
			}
			cursor += currentObjectSize
		default:
			// If an unsupported TypeID is encountered, we can't reliably parse further objects.
			// Break the loop and return what's parsed so far.
			return "" // Or, depending on desired behavior, return "" if no known types are parsed.
		}
		if pointOutput != "" {
			asduOutput.WriteString(pointOutput)
		}
	}

	// Only return output if any points were successfully parsed and added.
	if asduOutput.Len() > 0 {
		header := fmt.Sprintf("I-FRAME | N(S)=%d N(R)=%d | CAUSE=%d C_ADDR=%d\n", sendSeqNum, recvSeqNum, cause, commonAddr)
		return header + asduOutput.String()
	}

	return "" // No relevant data parsed
}

// parseSFrame decodifica tramas de supervisión.
func parseSFrame(control3, control4 byte, typeFilter string) string {
	if typeFilter != "" && typeFilter != "all" && typeFilter != "control" {
		return ""
	}
	// N(R) sequence number (bits 1-15 of control fields 3,4)
	recvSeqNum := int(binary.LittleEndian.Uint16([]byte{control3, control4}) >> 1)
	return fmt.Sprintf("S-FRAME | ACK, N(R)=%d\n", recvSeqNum)
}

// parseUFrame decodifica tramas de control no numeradas.
func parseUFrame(control1 byte, typeFilter string) string {
	if typeFilter != "" && typeFilter != "all" && typeFilter != "control" {
		return ""
	}

	var uType string
	// Determine U-frame function based on specific bits in control1
	switch {
	case (control1 & 0b10000000) != 0: // Bit 7 set
		uType = "TESTFR (Confirm)"
	case (control1 & 0b01000000) != 0: // Bit 6 set
		uType = "TESTFR (Activation)"
	case (control1 & 0b00100000) != 0: // Bit 5 set
		uType = "STOPDT (Confirm)"
	case (control1 & 0b00010000) != 0: // Bit 4 set
		uType = "STOPDT (Activation)"
	case (control1 & 0b00001000) != 0: // Bit 3 set
		uType = "STARTDT (Confirm)"
	case (control1 & 0b00000100) != 0: // Bit 2 set
		uType = "STARTDT (Activation)"
	default:
		uType = "Unknown"
	}
	return fmt.Sprintf("U-FRAME | %s\n", uType)
}

// applyFilter verifica si un punto de datos debe ser mostrado según los filtros.
func applyFilter(dataType string, addr int, typeFilter string, pointFilter map[int]struct{}) bool {
	// 1. Filter by data type
	passesTypeFilter := typeFilter == "" || typeFilter == "all" || typeFilter == dataType
	if !passesTypeFilter {
		return false
	}

	// 2. Filter by point number
	if len(pointFilter) > 0 {
		_, ok := pointFilter[addr]
		return ok // Only passes if the point is in the map
	}

	return true // No point filter, or point filter passes
}

// parseCP56 parses a 7-byte CP56Time2a (IEC 60870-5-104 Time) into a Go time.Time.
func parseCP56(buf []byte) time.Time {
	if len(buf) < 7 {
		return time.Time{} // Return zero time if buffer is too short
	}
	// CP56Time2a fields:
	// Octet 1-2: Milliseconds (0-59999) and Invalid (bit 15)
	// Octet 3: Minute (0-59), Res (bits 6-7)
	// Octet 4: Hour (0-23), Summer time (bit 7)
	// Octet 5: Day of week (1-7), Day of month (1-31)
	// Octet 6: Month (1-12)
	// Octet 7: Year (0-99 relative to 2000)

	ms := int(binary.LittleEndian.Uint16(buf[0:2])) // Milliseconds (0-59999)
	min := int(buf[2] & 0x3F)                       // Minute (bits 0-5)
	hour := int(buf[3] & 0x1F)                      // Hour (bits 0-4)
	day := int(buf[4] & 0x1F)                       // Day of month (bits 0-4)
	month := int(buf[5] & 0x0F)                     // Month (bits 0-3)
	year := int(buf[6] & 0x7F)                      // Year (bits 0-6, 0-99)

	// Note: IEC 104 year is relative to 2000.
	// For simplicity, we'll assume local time zone for now.
	return time.Date(2000+year, time.Month(month), day, hour, min, ms/1000, (ms%1000)*1e6, time.Local)
}

// hexDump generates a formatted hexadecimal dump of the provided byte slice.
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
		// Pad with spaces if the line is shorter than 16 bytes for consistent formatting
		sb.WriteString(fmt.Sprintf("  %04X: %-48s\n", i, spacedHex))
	}
	return sb.String()
}
