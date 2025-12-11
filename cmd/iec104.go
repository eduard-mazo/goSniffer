package cmd

import (
	"errors"
	"fmt"
	"iec104sniffer/internal/iec104"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var (
	iecIp     string
	iecPorts  string
	iecTarget string
	iecFilter string
	iecPoints string
	iecRaw    bool
)

var iec104Cmd = &cobra.Command{
	Use:   "iec104",
	Short: "Captura y decodifica tramas IEC 60870-5-104",
	Run: func(cmd *cobra.Command, args []string) {
		if iecIp == "" {
			log.Fatal("Debe especificar la dirección IP de la interfaz con --ip")
		}

		iface, err := findInterfaceByIP(iecIp)
		if err != nil {
			log.Fatalf("Error al buscar la interfaz: %v", err)
		}
		fmt.Printf("✅ Interfaz encontrada: %s para la IP %s\n", iface, iecIp)

		if iecPorts == "" {
			iecPorts = "2404"
		}
		ports := strings.Split(iecPorts, ",")

		pointFilterMap, err := parsePointsString(iecPoints)
		if err != nil {
			log.Fatalf("Error al parsear la lista de puntos: %v", err)
		}

		packetChan := make(chan iec104.PacketToProcess, 200)
		var wgWorkers sync.WaitGroup
		const numWorkers = 4

		for i := 0; i < numWorkers; i++ {
			wgWorkers.Add(1)
			go func() {
				defer wgWorkers.Done()
				iec104.ProcessPacketWorker(packetChan)
			}()
		}

		var wgListeners sync.WaitGroup
		for _, port := range ports {
			p := strings.TrimSpace(port)
			if p == "" {
				continue
			}
			wgListeners.Add(1)
			go listenIEC104(iface, iecIp, p, iecTarget, iecFilter, pointFilterMap, iecRaw, packetChan, &wgListeners)
		}

		fmt.Printf("🚀 Escuchando IEC104 en puertos: %s", iecPorts)
		if iecTarget != "" {
			fmt.Printf(" | Filtrando comunicación con: %s", iecTarget)
		}
		fmt.Println("\nPresione Ctrl+C para detener.")

		wgListeners.Wait()
		close(packetChan)
		wgWorkers.Wait()
	},
}

func listenIEC104(iface, localIP, port, targetIP, filter string, pointMap map[int]struct{}, raw bool, packetChan chan<- iec104.PacketToProcess, wg *sync.WaitGroup) {
	defer wg.Done()

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error al abrir pcap en el puerto %s: %v", port, err)
		return
	}
	defer handle.Close()

	bpfFilter := fmt.Sprintf("tcp port %s", port)
	if targetIP != "" {
		bpfFilter = fmt.Sprintf("tcp port %s and host %s", port, targetIP)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Printf("Error al aplicar filtro BPF '%s': %v", bpfFilter, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		if len(tcp.Payload) > 0 && tcp.Payload[0] == iec104.StartByte {
			payloadCopy := make([]byte, len(tcp.Payload))
			copy(payloadCopy, tcp.Payload)

			packetChan <- iec104.PacketToProcess{
				Payload:       payloadCopy,
				LocalIP:       localIP,
				SourceIP:      ip.SrcIP.String(),
				DestinationIP: ip.DstIP.String(),
				TypeFilter:    filter,
				PointFilter:   pointMap,
				RawOutput:     raw,
			}
		}
	}
}

func findInterfaceByIP(ip string) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.IP.String() == ip {
				return device.Name, nil
			}
		}
	}
	return "", errors.New("ninguna interfaz encontrada con la IP especificada")
}

func parsePointsString(pointsStr string) (map[int]struct{}, error) {
	pointMap := make(map[int]struct{})
	if pointsStr == "" {
		return pointMap, nil
	}
	cleanStr := strings.Trim(pointsStr, "[] \t")
	if cleanStr == "" {
		return pointMap, nil
	}
	parts := strings.Split(cleanStr, ",")
	for _, part := range parts {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("valor de punto no válido '%s'", part)
		}
		pointMap[p] = struct{}{}
	}
	return pointMap, nil
}

func init() {
	sniffCmd.AddCommand(iec104Cmd)

	iec104Cmd.Flags().StringVar(&iecIp, "ip", "", "Dirección IP de la interfaz de red a escuchar")
	iec104Cmd.Flags().StringVar(&iecPorts, "port", "2404", "Puerto o puertos TCP separados por comas")
	iec104Cmd.Flags().StringVar(&iecTarget, "target", "", "IP del equipo remoto para filtrar tráfico específico")
	iec104Cmd.Flags().StringVar(&iecFilter, "filter", "", "Filtro por tipo: analog, digital, double, control")
	iec104Cmd.Flags().StringVar(&iecPoints, "points", "", "Lista de puntos IOA a filtrar ej. [100,101]")
	iec104Cmd.Flags().BoolVar(&iecRaw, "raw", false, "Mostrar la trama completa en formato hexadecimal")

	if err := iec104Cmd.MarkFlagRequired("ip"); err != nil {
		log.Fatalf("Failed to mark 'ip' flag as required: %v", err)
	}
}
