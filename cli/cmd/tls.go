// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/internal/factory"
	opensslProbe "github.com/gojue/ecapture/internal/probe/openssl"
)

var opensslConfig = opensslProbe.NewConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl"},
	Short:   "Used to capture TLS/SSL text content without the need for a CA certificate. (Supports OpenSSL 1.0.x/1.1.x/3.x or newer).",
	Long: `Uses eBPF uprobe/TC to capture process event data and network data. Also supports the pcap-NG format.

ecapture tls -m [text|keylog|pcap] [flags] [pcap filter expression (for pcap mode)]
ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443
ecapture tls -l save.log --pid=3423
ecapture tls --libssl=/lib/x86_64-linux-gnu/libssl.so.1.1
ecapture tls -m keylog --pcapfile save_3_0_5.pcapng --ssl_version="openssl 3.0.5" --libssl=/lib/x86_64-linux-gnu/libssl.so.3
ecapture tls -m pcap --pcapfile save_android.pcapng -i wlan0 --libssl=/apex/com.android.conscrypt/lib64/libssl.so --ssl_version="boringssl 1.1.1" tcp port 443

Docker usage:
docker pull gojue/ecapture
docker run --rm --privileged=true --net=host -v /etc:/etc -v /usr:/usr -v ${PWD}:/output gojue/ecapture tls -m pcap -i wlp3s0 --pcapfile=/output/ecapture.pcapng tcp port 443
`,
	Example: "ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443",
	RunE:    openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.OpensslPath, "libssl", "", "libssl.so file path. For APK-backed Flutter apps, this can also be the APK path; manual SSL_* addresses stay relative to libflutter.so and ecapture adds the APK entry offset automatically.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.CaptureMode, "model", "m", "text", "capture model, such as : text, pcap/pcapng, key/keylog")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.KeylogFile, "keylogfile", "k", "ecapture_openssl_key.log", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.PcapFile, "pcapfile", "w", "save.pcapng", "write the raw packets to file as pcapng format.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.SslVersion, "ssl_version", "", "openssl/boringssl version， e.g: --ssl_version=\"openssl 1.1.1g\" or  --ssl_version=\"boringssl 1.1.1\".")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLWriteAddr, "ssl_write_addr", 0, "manual uprobe address of SSL_write (hex, e.g. 0x1234). For stripped binaries (e.g. Android BoringSSL).")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLReadAddr, "ssl_read_addr", 0, "manual uprobe address of SSL_read (hex, e.g. 0x1234).")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLReadInnerOffset, "ssl_read_inner_offset", 0, "offset of inner memcpy BL instruction from ssl_read_addr (0=auto: 0x6DC for newest Flutter).")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLSetFdAddr, "ssl_set_fd_addr", 0, "manual uprobe address of SSL_set_fd.")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLSetRfdAddr, "ssl_set_rfd_addr", 0, "manual uprobe address of SSL_set_rfd.")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLSetWfdAddr, "ssl_set_wfd_addr", 0, "manual uprobe address of SSL_set_wfd.")
	opensslCmd.PersistentFlags().Uint64Var(&opensslConfig.SSLMasterKeyAddr, "ssl_master_key_addr", 0, "manual uprobe address of master-key hook (SSL_in_init for BoringSSL / SSL_get_wbio for OpenSSL).")
	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "tls" command using the new probe architecture.
func openSSLCommandFunc(command *cobra.Command, args []string) error {
	if opensslConfig.PcapFilter == "" && len(args) != 0 {
		opensslConfig.PcapFilter = strings.Join(args, " ")
	}

	// Set global config to openssl-specific config
	opensslConfig.SetPid(globalConf.Pid)
	opensslConfig.SetUid(globalConf.Uid)
	opensslConfig.SetDebug(globalConf.Debug)
	opensslConfig.SetHex(globalConf.IsHex)
	opensslConfig.SetBTF(globalConf.BtfMode)
	opensslConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	opensslConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypeOpenSSL, opensslConfig)
}
