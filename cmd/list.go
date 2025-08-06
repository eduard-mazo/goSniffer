package cmd

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list-interfaces",
	Short: "Lista interfaces de red disponibles",
	Run: func(cmd *cobra.Command, args []string) {
		ifs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		for _, i := range ifs {
			fmt.Printf("→ Nombre: %s\n  Descripción: %s\n", i.Name, i.Description)
			for _, addr := range i.Addresses {
				fmt.Printf("  IP: %s\n", addr.IP)
			}
			fmt.Println()
		}
	},
}
