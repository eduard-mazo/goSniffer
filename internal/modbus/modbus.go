package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
)

type PacketToProcess struct {
	Payload       []byte
	LocalIP       string
	SourceIP      string
	DestinationIP string
	RawOutput     bool
	TCPInfo       string
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

func ProcessPacketWorker(ch <-chan PacketToProcess) {
	for p := range ch {
		direction := "Rx"
		if p.SourceIP == p.LocalIP {
			direction = "Tx"
		}

		timestamp := time.Now().Format("15:04:05.000")

		// 1. Eventos de Control TCP
		if p.TCPInfo != "" {
			icon := "🔔"
			if strings.Contains(p.TCPInfo, "RST") {
				icon = "🔥"
			} else if strings.Contains(p.TCPInfo, "FIN") {
				icon = "🚫"
			} else if strings.Contains(p.TCPInfo, "SYN") {
				icon = "✨"
			}
			fmt.Printf("\n%s\n[%s] %s -> %s\n %s TCP EVENT: [%s]\n",
				timestamp, direction, p.SourceIP, p.DestinationIP, icon, p.TCPInfo)

			if len(p.Payload) == 0 {
				continue
			}
		}

		// 2. Procesamiento Modbus
		if len(p.Payload) < 7 {
			continue
		}

		output := parseMBAP(p.Payload, direction, p.SourceIP, p.DestinationIP)

		if output != "" {
			if p.RawOutput {
				fmt.Printf("\n%s\n%s", timestamp, hexDump(p.Payload))
			} else if p.TCPInfo == "" {
				fmt.Printf("\n%s\n", timestamp)
			}
			fmt.Print(output)
		}
	}
}

func parseMBAP(data []byte, direction, srcIP, dstIP string) string {
	transID := binary.BigEndian.Uint16(data[0:2])
	protoID := binary.BigEndian.Uint16(data[2:4])
	length := binary.BigEndian.Uint16(data[4:6])
	unitID := data[6]

	if protoID != 0 {
		return ""
	}

	pdu := data[7:]
	if len(pdu) == 0 {
		return ""
	}

	funcCode := pdu[0]
	funcName := "Unknown"
	isError := false

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

	header := fmt.Sprintf("[%s] %s -> %s \n MBAP: TransID: %04X | Unit: %d | Len: %d \n Function: %d (%s)\n",
		direction, srcIP, dstIP, transID, unitID, length, funcCode, funcName)

	details := parsePDU(funcCode, pdu, isError)
	return header + details
}

func parsePDU(funcCode byte, data []byte, isError bool) string {
	if isError {
		if len(data) >= 2 {
			exCode := data[1]
			exDesc, ok := exceptionMap[exCode]
			if !ok {
				exDesc = "Unknown"
			}
			return fmt.Sprintf("  ❌ Exception Code: %02X (%s)\n", exCode, exDesc)
		}
		return "  ❌ Malformed Error PDU\n"
	}

	if len(data) < 2 {
		return ""
	}
	payload := data[1:] // Payload sin Function Code
	var sb strings.Builder

	switch funcCode {
	// --- LECTURAS (01, 02, 03, 04) ---
	case FuncReadCoils, FuncReadInputStatus, FuncReadHoldingRegisters, FuncReadInputRegisters:
		// REQUEST (Siempre son 4 bytes: Addr + Qty)
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("  Request -> Start Addr: %d, Quantity: %d\n", addr, qty))
		} else if len(payload) > 1 {
			// RESPONSE
			byteCount := int(payload[0])
			dataBytes := payload[1:]
			sb.WriteString(fmt.Sprintf("  Response -> Bytes: %d\n", byteCount))

			// -- Lógica para REGISTROS (03, 04) --
			if funcCode == FuncReadHoldingRegisters || funcCode == FuncReadInputRegisters {
				// 1. Mostrar Raw Registers (UInt16)
				sb.WriteString("    Raw Integers:\n")
				count := 0
				for i := 0; i < len(dataBytes)-1; i += 2 {
					if count >= 6 { // Limitamos la vista raw para no saturar si es larga
						sb.WriteString("      ... (viewing interpretation below) ...\n")
						break
					}
					val := binary.BigEndian.Uint16(dataBytes[i : i+2])
					sb.WriteString(fmt.Sprintf("      Reg[%d]: %d (0x%04X)\n", i/2, val, val))
					count++
				}

				// 2. Interpretar como FLOAT32 (CDAB - Word Swap)
				// Requiere al menos 4 bytes. Agrupamos de a 2 registros.
				if len(dataBytes) >= 4 {
					sb.WriteString("    Interpretation (Float32 Little-Endian/Word-Swap):\n")
					regIdx := 0
					for i := 0; i <= len(dataBytes)-4; i += 4 {
						// Formato CDAB:
						// Bytes entrada: [b0, b1, b2, b3] -> Reg1[b0,b1], Reg2[b2,b3]
						// Float esperado: [b2, b3, b0, b1] (Big Endian standard para math.Float32frombits)
						b0 := dataBytes[i]
						b1 := dataBytes[i+1]
						b2 := dataBytes[i+2]
						b3 := dataBytes[i+3]

						// Reconstruimos uint32 intercambiando las palabras de 16 bits
						bits := (uint32(b2) << 24) | (uint32(b3) << 16) | (uint32(b0) << 8) | uint32(b1)
						floatVal := math.Float32frombits(bits)

						// Mostramos solo si el valor no es 0 para limpiar la salida, o siempre si se prefiere
						sb.WriteString(fmt.Sprintf("      Regs[%d-%d]: %10.6f\n", regIdx, regIdx+1, floatVal))
						regIdx += 2
					}
				}
			} else {
				// -- Lógica para BITS (01, 02) --
				// Iterar sobre cada byte y luego sobre cada bit
				sb.WriteString(fmt.Sprintf("    Raw Hex: %X\n", dataBytes))
				sb.WriteString("    Bit Interpretation:\n")

				bitCount := 0
				for _, b := range dataBytes {
					for bitIdx := 0; bitIdx < 8; bitIdx++ {
						// Modbus envía LSB primero para el primer bit
						val := (b >> bitIdx) & 0x01

						// Formato compacto: Offset relativo
						// Nota: No tenemos la dirección inicial absoluta aquí (es stateless),
						// así que mostramos Offset relativo (+0, +1...)
						sb.WriteString(fmt.Sprintf("      [+%02d]: %d\n", bitCount, val))
						bitCount++
					}
				}
			}
		}

	// --- ESCRITURAS (05, 06, 15, 16) ---
	case FuncWriteSingleCoil, FuncWriteSingleRegister:
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			val := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("  Write -> Addr: %d, Value: %d (0x%04X)\n", addr, val, val))
		}
	case FuncWriteMultipleCoils, FuncWriteMultipleRegs:
		if len(payload) >= 5 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			bytes := payload[4]
			sb.WriteString(fmt.Sprintf("  Write Multiple -> Addr: %d, Qty: %d, Bytes: %d\n", addr, qty, bytes))
		} else if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("  Response -> Addr: %d, Qty: %d\n", addr, qty))
		}
	}
	return sb.String()
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
		spaced := ""
		for j := 0; j < len(hexPart); j += 2 {
			spaced += hexPart[j:j+2] + " "
		}
		sb.WriteString(fmt.Sprintf(" %04X: %s\n", i, spaced))
	}
	return sb.String()
}
