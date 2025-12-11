package cmd

import (
	"github.com/spf13/cobra"
)

// sniffCmd representa el comando padre para las funcionalidades de sniffing
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Long:  `Colección de herramientas para analizar protocolos industriales sobre TCP/IP. Usa los subcomandos 'iec104' o 'modbus' para iniciar.`,
}

func init() {
	rootCmd.AddCommand(sniffCmd)
	// Aquí podrías poner flags persistentes globales si las hubiera
}
