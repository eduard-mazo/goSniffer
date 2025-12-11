package cmd

import (
	"fmt"
	"iec104sniffer/internal/modbus"
	"log"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var (
	modbusIp     string
	modbusPorts  string
	modbusTarget string
	modbusRaw    bool
)

var modbusCmd = &cobra.Command{
	Use:   "modbus",
	Short: "Sniffer para protocolo Modbus TCP",
	Run: func(cmd *cobra.Command, args []string) {
		if modbusIp == "" {
			log.Fatal("Debe especificar la dirección IP de la interfaz con --ip")
		}

		iface, err := findInterfaceByIP(modbusIp)
		if err != nil {
			log.Fatalf("Error al buscar interfaz: %v", err)
		}
		fmt.Printf("✅ Interfaz: %s (IP: %s)\n", iface, modbusIp)

		if modbusPorts == "" {
			modbusPorts = "502"
		}
		ports := strings.Split(modbusPorts, ",")

		packetChan := make(chan modbus.PacketToProcess, 200)
		var wgWorkers sync.WaitGroup

		// Iniciar workers
		for i := 0; i < 4; i++ {
			wgWorkers.Add(1)
			go func() {
				defer wgWorkers.Done()
				modbus.ProcessPacketWorker(packetChan)
			}()
		}

		var wgListeners sync.WaitGroup
		for _, port := range ports {
			p := strings.TrimSpace(port)
			if p == "" {
				continue
			}
			wgListeners.Add(1)
			go listenModbus(iface, modbusIp, p, modbusTarget, modbusRaw, packetChan, &wgListeners)
		}

		fmt.Printf("🚀 Escuchando Modbus en puertos: %s", modbusPorts)
		if modbusTarget != "" {
			fmt.Printf(" | Filtrando comunicación con: %s", modbusTarget)
		}
		fmt.Println("\nPresione Ctrl+C para detener.")

		wgListeners.Wait()
		close(packetChan)
		wgWorkers.Wait()
	},
}

func listenModbus(iface, localIP, port, targetIP string, raw bool, ch chan<- modbus.PacketToProcess, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error pcap puerto %s: %v", port, err)
		return
	}
	defer handle.Close()

	bpfFilter := fmt.Sprintf("tcp port %s", port)
	if targetIP != "" {
		bpfFilter = fmt.Sprintf("tcp port %s and host %s", port, targetIP)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Printf("Error aplicando filtro BPF '%s': %v", bpfFilter, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ipLayer != nil && tcpLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			if len(tcp.Payload) > 0 {
				payloadCopy := make([]byte, len(tcp.Payload))
				copy(payloadCopy, tcp.Payload)

				ch <- modbus.PacketToProcess{
					Payload:       payloadCopy,
					LocalIP:       localIP,
					SourceIP:      ip.SrcIP.String(),
					DestinationIP: ip.DstIP.String(),
					RawOutput:     raw,
				}
			}
		}
	}
}

func init() {
	sniffCmd.AddCommand(modbusCmd)
	modbusCmd.Flags().StringVar(&modbusIp, "ip", "", "IP de la interfaz local")
	modbusCmd.Flags().StringVar(&modbusPorts, "port", "502", "Puertos TCP separados por coma")
	modbusCmd.Flags().StringVar(&modbusTarget, "target", "", "IP del equipo remoto para filtrar tráfico específico")
	modbusCmd.Flags().BoolVar(&modbusRaw, "raw", false, "Ver Hexadecimal crudo")

	if err := modbusCmd.MarkFlagRequired("ip"); err != nil {
		log.Fatalf("Failed to mark 'ip' flag as required: %v", err)
	}
}
