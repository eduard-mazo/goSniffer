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

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Captura y decodifica tramas IEC 60870-5-104 de forma avanzada",
	Run: func(cmd *cobra.Command, args []string) {
		if ipAddr == "" {
			log.Fatal("Debe especificar la dirección IP de la interfaz con --ip")
		}

		// 1. Encontrar la interfaz de red a partir de la dirección IP
		iface, err := findInterfaceByIP(ipAddr)
		if err != nil {
			log.Fatalf("Error al buscar la interfaz: %v", err)
		}
		fmt.Printf("✅ Interfaz encontrada: %s para la IP %s\n", iface, ipAddr)

		// 2. Parsear los puertos a monitorear
		if portsStr == "" {
			portsStr = "2404" // Puerto por defecto
		}
		ports := strings.Split(portsStr, ",")

		// 3. Parsear la lista de puntos a filtrar
		pointFilterMap, err := parsePointsString(pointsStr)
		if err != nil {
			log.Fatalf("Error al parsear la lista de puntos: %v", err)
		}

		// 4. Configurar el pool de workers para procesar paquetes
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

		// 5. Iniciar un listener por cada puerto especificado
		var wgListeners sync.WaitGroup
		for _, port := range ports {
			p := strings.TrimSpace(port)
			if p == "" {
				continue
			}

			wgListeners.Add(1)
			go listenOnPort(iface, p, filter, pointFilterMap, rawOutput, packetChan, &wgListeners)
		}

		fmt.Printf("🚀 Escuchando en %d puerto(s): %s. Presione Ctrl+C para detener.\n\n", len(ports), portsStr)

		wgListeners.Wait() // Esperar a que todos los listeners terminen
		close(packetChan)  // Cerrar el canal una vez que no haya más productores
		wgWorkers.Wait()   // Esperar a que los workers terminen de procesar
	},
}

// listenOnPort abre una sesión de pcap en una interfaz y puerto específicos
func listenOnPort(iface, port, filter string, pointMap map[int]struct{}, raw bool, packetChan chan<- iec104.PacketToProcess, wg *sync.WaitGroup) {
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
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 && tcp.Payload[0] == iec104.StartByte {
			payloadCopy := make([]byte, len(tcp.Payload))
			copy(payloadCopy, tcp.Payload)

			// Enviar paquete junto con su contexto al canal de procesamiento
			packetChan <- iec104.PacketToProcess{
				Payload:     payloadCopy,
				TypeFilter:  filter,
				PointFilter: pointMap,
				RawOutput:   raw,
			}
		}
	}
}

// findInterfaceByIP busca el nombre de un dispositivo de red basado en su dirección IPv4.
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

// parsePointsString convierte un string como "[1,2,3]" en un mapa para búsqueda eficiente.
func parsePointsString(pointsStr string) (map[int]struct{}, error) {
	pointMap := make(map[int]struct{})
	if pointsStr == "" {
		return pointMap, nil
	}

	// Limpiar el string de entrada: quitar corchetes y espacios
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
	sniffCmd.Flags().StringVar(&ipAddr, "ip", "", "Dirección IP de la interfaz de red a escuchar (ej. --ip \"xxx.xxx.xxx.xxx\")")
	sniffCmd.Flags().StringVar(&portsStr, "port", "2404", "Puerto o puertos TCP a escuchar, separados por comas (ej. --port \"2404,2405\")")
	sniffCmd.Flags().StringVar(&filter, "filter", "", "Filtrar por tipo: analog | digital | double | control  (ej. --filter \"analog\")")
	sniffCmd.Flags().StringVar(&pointsStr, "points", "", "Filtrar por lista de puntos (ej. --points \"[10020,10021,50010]\")")
	sniffCmd.Flags().BoolVar(&rawOutput, "raw", false, "Mostrar la trama completa en formato hexadecimal")
	sniffCmd.MarkFlagRequired("ip")
}
