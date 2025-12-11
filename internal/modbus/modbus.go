package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type PacketToProcess struct {
	Payload       []byte
	LocalIP       string
	SourceIP      string
	DestinationIP string
	RawOutput     bool
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

func ProcessPacketWorker(ch <-chan PacketToProcess) {
	for p := range ch {
		direction := "Rx"
		if p.SourceIP == p.LocalIP {
			direction = "Tx"
		}

		// Validación básica Header Modbus TCP (7 bytes)
		if len(p.Payload) < 7 {
			continue
		}

		output := parseMBAP(p.Payload, direction, p.SourceIP, p.DestinationIP)

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

func parseMBAP(data []byte, direction, srcIP, dstIP string) string {
	transID := binary.BigEndian.Uint16(data[0:2])
	protoID := binary.BigEndian.Uint16(data[2:4])
	length := binary.BigEndian.Uint16(data[4:6])
	unitID := data[6]

	// Protocol ID en Modbus TCP siempre es 0
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
	if isError && len(data) >= 2 {
		return fmt.Sprintf("  ❌ Exception Code: %02X\n", data[1])
	}

	if len(data) < 2 {
		return ""
	}
	payload := data[1:]

	var sb strings.Builder

	switch funcCode {
	case FuncReadHoldingRegisters, FuncReadInputRegisters:
		// Request: Addr(2) + Qty(2) = 4 bytes
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			qty := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("  Request -> Start Addr: %d, Quantity: %d\n", addr, qty))
		} else if len(payload) > 1 {
			// Response: ByteCount(1) + Data
			byteCount := int(payload[0])
			sb.WriteString(fmt.Sprintf("  Response -> Bytes: %d\n", byteCount))
			values := payload[1:]
			for i := 0; i < len(values)-1; i += 2 {
				val := binary.BigEndian.Uint16(values[i : i+2])
				sb.WriteString(fmt.Sprintf("    Reg[%d]: %d (0x%04X)\n", (i / 2), val, val))
			}
		}

	case FuncWriteSingleRegister:
		if len(payload) == 4 {
			addr := binary.BigEndian.Uint16(payload[0:2])
			val := binary.BigEndian.Uint16(payload[2:4])
			sb.WriteString(fmt.Sprintf("  Write -> Addr: %d, Value: %d\n", addr, val))
		}

		// Se pueden agregar más casos aquí (Coils, MultiWrite, etc)
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
