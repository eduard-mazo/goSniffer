package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

type PacketToProcess struct {
	Payload         []byte
	LocalIP         string
	SourceIP        string
	SourcePort      string
	DestinationIP   string
	DestinationPort string
	RawOutput       bool
	TCPInfo         string
}

const (
	FuncReadCoils            = 1
	FuncReadInputStatus      = 2
	FuncReadHoldingRegisters = 3
	FuncReadInputRegisters   = 4
	FuncWriteSingleCoil      = 5
	FuncWriteSingleRegister  = 6
	FuncWriteMultipleCoils   = 15
	FuncWriteMultipleRegs    = 16
)

var funcCodeMap = map[byte]string{
	1:  "Read Coils",
	2:  "Read Input Status",
	3:  "Read Holding Registers",
	4:  "Read Input Registers",
	5:  "Write Single Coil",
	6:  "Write Single Register",
	15: "Write Multiple Coils",
	16: "Write Multiple Registers",
}

var exceptionMap = map[byte]string{
	1: "Illegal Function",
	2: "Illegal Data Address",
	3: "Illegal Data Value",
	4: "Slave Device Failure",
	5: "Acknowledge",
	6: "Slave Device Busy",
}

var requestCache sync.Map

func ProcessPacketWorker(ch <-chan PacketToProcess) {
	for p := range ch {
		// Determinar Dirección
		direction := "RX"
		if p.SourceIP == p.LocalIP {
			direction = "TX"
		}

		timestamp := time.Now().Format("2006-01-02 15:04:05.000")

		// Construcción del Buffer de Salida
		var sb strings.Builder
		sb.WriteString("------------------------------------------------------------\n")
		sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", timestamp))
		sb.WriteString(fmt.Sprintf("Direction:    %s\n", direction))

		protocol := "ModbusTCP"
		if len(p.Payload) == 0 && p.TCPInfo != "" {
			protocol = "TCP" // Solo control TCP
		}
		sb.WriteString(fmt.Sprintf("Protocol:     %s\n", protocol))
		sb.WriteString(fmt.Sprintf("Source:       %s:%s\n", p.SourceIP, p.SourcePort))
		sb.WriteString(fmt.Sprintf("Destination:  %s:%s\n", p.DestinationIP, p.DestinationPort))

		if p.TCPInfo != "" {
			// Si hay eventos TCP, los mostramos en la cabecera
			sb.WriteString(fmt.Sprintf("TCP Flags:    %s\n", p.TCPInfo))
		}
		sb.WriteString("------------------------------------------------------------\n")

		// Si es un paquete Modbus (tiene payload suficiente)
		if len(p.Payload) >= 7 {
			mbap, pduBytes, err := parseMBAP(p.Payload, &sb)
			if err == nil {
				parsePDU(mbap, pduBytes, &sb)
			}

			// Sección RAW al final
			sb.WriteString("------------------------------------------------------------\n")
			sb.WriteString("RAW:\n")
			sb.WriteString(hexDumpFlat(p.Payload))
			sb.WriteString("\n------------------------------------------------------------\n")
			sb.WriteString("============================================================\n")
		} else if p.TCPInfo != "" {
			// Si es solo TCP event (ACK, RST), cerramos la caja visualmente
			sb.WriteString("(No Data Payload)\n")
			sb.WriteString("------------------------------------------------------------\n")
			sb.WriteString("============================================================\n")
		}

		fmt.Print(sb.String())
	}
}

// Estructura interna para pasar datos del MBAP
type mbapHeader struct {
	TransID  uint16
	ProtoID  uint16
	Length   uint16
	UnitID   byte
	FuncCode byte
}

func parseMBAP(data []byte, sb *strings.Builder) (mbapHeader, []byte, error) {
	if len(data) < 7 {
		return mbapHeader{}, nil, fmt.Errorf("short packet")
	}

	h := mbapHeader{
		TransID: binary.BigEndian.Uint16(data[0:2]),
		ProtoID: binary.BigEndian.Uint16(data[2:4]),
		Length:  binary.BigEndian.Uint16(data[4:6]),
		UnitID:  data[6],
	}

	// Protocol ID 0 = Modbus TCP
	if h.ProtoID != 0 {
		return h, nil, fmt.Errorf("invalid proto id")
	}

	pdu := data[7:]
	if len(pdu) == 0 {
		return h, nil, fmt.Errorf("empty pdu")
	}
	h.FuncCode = pdu[0]

	sb.WriteString("MBAP Header\n")
	sb.WriteString(fmt.Sprintf("   Transaction ID: 0x%04X\n", h.TransID))
	sb.WriteString(fmt.Sprintf("   Protocol ID:    0x%04X\n", h.ProtoID))
	sb.WriteString(fmt.Sprintf("   Length:         %d\n", h.Length))
	sb.WriteString(fmt.Sprintf("   Unit ID:        %d\n", h.UnitID))

	return h, pdu, nil
}

func parsePDU(h mbapHeader, data []byte, sb *strings.Builder) {
	funcCode := h.FuncCode
	isError := false
	funcName := "Unknown"

	if funcCode > 0x80 {
		isError = true
		baseFunc := funcCode - 0x80
		if name, ok := funcCodeMap[baseFunc]; ok {
			funcName = fmt.Sprintf("Error response to %s", name)
		} else {
			funcName = "Error Response"
		}
	} else {
		if name, ok := funcCodeMap[funcCode]; ok {
			funcName = name
		}
	}

	sb.WriteString("PDU\n")
	sb.WriteString(fmt.Sprintf("   Function:             %02d – %s\n", funcCode, funcName))

	if isError {
		if len(data) >= 2 {
			exCode := data[1]
			exDesc := exceptionMap[exCode]
			if exDesc == "" {
				exDesc = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("   Exception Code:       0x%02X (%s)\n", exCode, exDesc))
		}
		return
	}

	if len(data) < 2 {
		return
	}
	payload := data[1:]

	switch funcCode {
	// --- LECTURAS (01, 02, 03, 04) ---
	case FuncReadCoils, FuncReadInputStatus, FuncReadHoldingRegisters, FuncReadInputRegisters:
		// REQUEST
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])

			requestCache.Store(h.TransID, addr)

			sb.WriteString(fmt.Sprintf("   Data Address:         %d (0x%04X)\n", addr, addr))
			sb.WriteString(fmt.Sprintf("   Register Count:       %d\n", qty))

		} else if len(payload) > 1 {
			// RESPONSE
			byteCount := int(payload[0])
			dataBytes := payload[1:]
			sb.WriteString(fmt.Sprintf("   Byte Count:           %d\n", byteCount))

			var startAddr uint16 = 0
			var hasAddr = false
			if val, ok := requestCache.Load(h.TransID); ok {
				startAddr = val.(uint16)
				hasAddr = true
				// requestCache.Delete(h.TransID)
			}

			// Decodificación de Registros (Float/Int)
			if funcCode == FuncReadHoldingRegisters || funcCode == FuncReadInputRegisters {
				sb.WriteString("   Data (Registers):\n")
				// Raw Integers
				for i := 0; i < len(dataBytes)-1; i += 2 {
					if i >= 16 { // Limitar vista si es muy largo
						sb.WriteString("      ... (more raw data hidden) ...\n")
						break
					}
					val := binary.BigEndian.Uint16(dataBytes[i : i+2])
					label := fmt.Sprintf("[%d]", i/2)
					if hasAddr {
						label = fmt.Sprintf("[%d]", startAddr+uint16(i/2))
					}
					sb.WriteString(fmt.Sprintf("      Reg%s: %d (0x%04X)\n", label, val, val))
				}

				// Interpretation Float
				if len(dataBytes) >= 4 {
					sb.WriteString("   Interpretation (Float32 Little-Endian/Word-Swap):\n")
					regIdx := 0
					for i := 0; i <= len(dataBytes)-4; i += 4 {
						b0, b1, b2, b3 := dataBytes[i], dataBytes[i+1], dataBytes[i+2], dataBytes[i+3]
						bits := (uint32(b2) << 24) | (uint32(b3) << 16) | (uint32(b0) << 8) | uint32(b1)
						floatVal := math.Float32frombits(bits)

						label := fmt.Sprintf("[%d-%d]", regIdx, regIdx+1)
						if hasAddr {
							label = fmt.Sprintf("[%d]", startAddr+uint16(regIdx))
						}
						sb.WriteString(fmt.Sprintf("      Addr%s: %.6f\n", label, floatVal))
						regIdx += 2
					}
				}
			} else {
				// Decodificación de Bits
				sb.WriteString("   Data (Bits):\n")
				bitCount := 0
				for _, b := range dataBytes {
					for bitIdx := 0; bitIdx < 8; bitIdx++ {
						val := (b >> bitIdx) & 0x01
						label := fmt.Sprintf("+%02d", bitCount)
						if hasAddr {
							label = fmt.Sprintf("%d", startAddr+uint16(bitCount))
						}
						sb.WriteString(fmt.Sprintf("      Bit [%s]: %d\n", label, val))
						bitCount++
					}
				}
			}
		}

	// --- ESCRITURAS ---
	case FuncWriteSingleCoil, FuncWriteSingleRegister:
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			val := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("   Write Address:        %d (0x%04X)\n", addr, addr))
			sb.WriteString(fmt.Sprintf("   Write Value:          %d (0x%04X)\n", val, val))
		}
	case FuncWriteMultipleCoils, FuncWriteMultipleRegs:
		if len(payload) >= 5 { // Request
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			bytes := payload[4]
			sb.WriteString(fmt.Sprintf("   Write Address:        %d (0x%04X)\n", addr, addr))
			sb.WriteString(fmt.Sprintf("   Quantity:             %d\n", qty))
			sb.WriteString(fmt.Sprintf("   Byte Count:           %d\n", bytes))
		} else if len(payload) == 4 { // Response
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("   Write Address:        %d (0x%04X)\n", addr, addr))
			sb.WriteString(fmt.Sprintf("   Quantity:             %d\n", qty))
		}
	}
}

func hexDumpFlat(data []byte) string {
	hexStr := strings.ToUpper(hex.EncodeToString(data))
	var sb strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		sb.WriteString(hexStr[i : i+2])
		sb.WriteString(" ")
	}
	return sb.String()
}
