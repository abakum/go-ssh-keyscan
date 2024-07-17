package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/abakum/pageant"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	Scan        = "scan"
	DefaultPort = "22"
	TO          = time.Second * 2
)

var Ch chan string = make(chan string, 10)

func KeyScanCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	Ch <- fmt.Sprintf("%s %s", knownhosts.Normalize(hostname), string(ssh.MarshalAuthorizedKey(key)))
	return fmt.Errorf(Scan)
}

func dial(hp string, config *ssh.ClientConfig, wg *sync.WaitGroup) (HostKeyAlgorithms []string) {
	defer wg.Done()

	client, err := ssh.Dial("tcp", hp, config)
	if err != nil {
		// log.Println("Failed to dial:", err)
		ss := strings.Split(err.Error(), "server offered: [")
		if len(ss) > 1 {
			ss = strings.Split(ss[1], "]")
			if len(ss) > 1 {
				HostKeyAlgorithms = strings.Fields(ss[0])
			}
		}

		return
	}
	// log.Println("success dial", hp, config)
	defer client.Close()
	return
}

func out(wg *sync.WaitGroup) {
	for s := range Ch {
		fmt.Printf("%s", s)
		wg.Done()
	}
}

func main() {
	log.SetFlags(log.Lshortfile)

	auths := []ssh.AuthMethod{}
	conn, err := pageant.NewConn()
	if err == nil {
		defer conn.Close()
		ag := agent.NewClient(conn)
		auths = []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}
	}

	var wg sync.WaitGroup
	go out(&wg)
	body := func(uhp string) {
		h, p, err := net.SplitHostPort(uhp)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "missing port in address") {
				log.Println("parsing", uhp, err)
				return
			}
			h = uhp
			p = DefaultPort
		}
		ss := strings.Split(h, "@")
		u := Scan
		if len(ss) > 1 {
			u = ss[0]
			h = ss[1]
		}
		// log.Println(u+"@"+h+":"+p, HostKeyAlgorithms)
		wg.Add(1) // dial and print
		HostKeyAlgorithms := dial(h+":"+p, &ssh.ClientConfig{
			User:              u,
			Auth:              auths,
			HostKeyCallback:   KeyScanCallback,
			HostKeyAlgorithms: []string{Scan},
			Timeout:           TO,
			BannerCallback: func(banner string) error {
				wg.Add(1)
				Ch <- fmt.Sprintf("# %s %s", h+":"+p, banner)
				return nil
			},
		}, &wg)
		wg.Add(1)
		Ch <- fmt.Sprintf("# %s@%s:%s %v\n", u, h, p, HostKeyAlgorithms)
		if len(HostKeyAlgorithms) == 0 {
			HostKeyAlgorithms = []string{
				ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01,
				ssh.CertAlgoRSAv01, ssh.CertAlgoDSAv01, ssh.CertAlgoECDSA256v01,
				ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01, ssh.CertAlgoED25519v01,

				ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
				ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
				ssh.KeyAlgoRSA, ssh.KeyAlgoDSA,

				ssh.KeyAlgoED25519,
			}
		}
		CertAlgoRSA := false
		KeyAlgoRSA := false
		for _, HostKeyAlgorithm := range HostKeyAlgorithms {
			switch HostKeyAlgorithm {
			case ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01:
				if CertAlgoRSA {
					continue
				}
				CertAlgoRSA = true
			case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA:
				if KeyAlgoRSA {
					continue
				}
				KeyAlgoRSA = true
			}
			wg.Add(2) // dial and print
			go dial(h+":"+p, &ssh.ClientConfig{
				User:              u,
				Auth:              auths,
				HostKeyCallback:   KeyScanCallback,
				HostKeyAlgorithms: []string{HostKeyAlgorithm},
				Timeout:           TO,
			}, &wg)
		}
	}
	fmt.Fprintln(os.Stderr, "Enter [user@]host[:port]")
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "Read [user@]host[:port] from os.Args")
		for _, uhp := range os.Args[1:] {
			body(strings.TrimSpace(uhp))
		}
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		uhp, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		body(strings.TrimSpace(uhp))
	}
	wg.Wait()
}
