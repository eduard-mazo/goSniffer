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
	ipAddr    string
	portsStr  string
	filter    string
	pointsStr string
	rawOutput bool
)

var iec104Cmd = &cobra.Command{
	Use:   "iec104",
	Short: "Comandos para capturar tráfico de red (IEC104 o Modbus)",
	Run: func(cmd *cobra.Command, args []string) {
		if ipAddr == "" {
			log.Fatal("Debe especificar la dirección IP de la interfaz con --ip")
		}

		iface, err := findInterfaceByIP(ipAddr)
		if err != nil {
			log.Fatalf("Error al buscar la interfaz: %v", err)
		}
		fmt.Printf("✅ Interfaz encontrada: %s para la IP %s\n", iface, ipAddr)

		if portsStr == "" {
			portsStr = "2404"
		}
		ports := strings.Split(portsStr, ",")

		pointFilterMap, err := parsePointsString(pointsStr)
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
			go listenOnPort(iface, ipAddr, p, filter, pointFilterMap, rawOutput, packetChan, &wgListeners)
		}

		fmt.Printf("🚀 Escuchando en %d puerto(s): %s. Presione Ctrl+C para detener.\n\n", len(ports), portsStr)

		wgListeners.Wait()
		close(packetChan)
		wgWorkers.Wait()
	},
}

func listenOnPort(iface, localIP, port, filter string, pointMap map[int]struct{}, raw bool, packetChan chan<- iec104.PacketToProcess, wg *sync.WaitGroup) {
	defer wg.Done()

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error al abrir pcap en el puerto %s: %v", port, err)
		return
	}
	defer handle.Close()

	bpfFilter := fmt.Sprintf("tcp port %s", port)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Printf("Error al aplicar filtro BPF en el puerto %s: %v", port, err)
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
	iec104Cmd.Flags().StringVar(&ipAddr, "ip", "", "Dirección IP de la interfaz de red a escuchar (ej. --ip \"xxx.xxx.xxx.xxx\")")
	iec104Cmd.Flags().StringVar(&portsStr, "port", "2404", "Puerto o puertos TCP a escuchar, separados por comas (ej. --port \"2404,2405\")")
	iec104Cmd.Flags().StringVar(&filter, "filter", "", "Filtrar por tipo: analog, digital, double, control. Se pueden combinar con comas (ej. --filter \"analog,digital\")")
	iec104Cmd.Flags().StringVar(&pointsStr, "points", "", "Filtrar por lista de puntos (ej. --points \"[10020,10021,50010]\")")
	iec104Cmd.Flags().BoolVar(&rawOutput, "raw", false, "Mostrar la trama completa en formato hexadecimal")
	if err := iec104Cmd.MarkFlagRequired("ip"); err != nil {
		log.Fatalf("Failed to mark 'ip' flag as required: %v", err)
	}
}
