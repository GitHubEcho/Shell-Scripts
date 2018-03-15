package main

import (
	"os"
	"log"
	"fmt"
	"sync"
	"flag"
	"context"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"strings"
	"strconv"
	"regexp"
	"github.com/Devatoria/go-nsenter"
	"github.com/docker/docker/client"
	"github.com/docker/docker/api/types"
)

var URL_API = "/api/networks-utils/containers?NetworkId="

const MAPSIZE = 150

// command-line args
var (
	USERNAME    string
	PASSWORD    string
	DCEMANGERIP string
	OPERATE     string
	LOGPATH     string
)

type netDetail struct {
	Name string
	IPs  []string // under the network ip list
}

type netInfo struct {
	LocalNet   map[string]netDetail // local IP list,get local data from docker command-line.
	SwarmNet   map[string]netDetail // all IP list,get data from DEC-API.
	ArpNet     map[string]netDetail // exist arp table,get data from nsenter command-line.
	MissArpNet map[string]netDetail // the missing network.
}

// receive json data's struct via DEC-API
type EndpointResource struct {
	Name        string
	EndpointID  string
	MacAddress  string
	IPv4Address string
	IPv6Address string
}

type Containers map[string]EndpointResource

func handleError(err error) {
	if err != nil {
		fmt.Println("error:", err)
		panic(err)
	}
}

// get network info from local docker.
func (nt *netInfo) getNet() {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	netList, err := cli.NetworkList(context.Background(), types.NetworkListOptions{})
	if err != nil {
		panic(err)
	}

	nt.LocalNet = make(map[string]netDetail, MAPSIZE)
	nt.SwarmNet = make(map[string]netDetail, MAPSIZE)
	var wg sync.WaitGroup
	for _, network := range netList {
		if network.Driver == "overlay" && network.Name != "ingress" {
			wg.Add(1)
			go func() {
				resp, err := cli.NetworkInspect(context.Background(), network.Name, types.NetworkInspectOptions{})

				var localNetlist []string
				for _, v := range resp.Containers {
					localNetlist = append(localNetlist, strings.Split(v.IPv4Address, "/")[0])
				}

				nt.LocalNet[network.ID] = netDetail{network.Name, localNetlist}
				handleError(err)
				defer wg.Done()
			}()

			wg.Add(1)
			go func() {
				res ,err := urlGet(network.ID, URL_API)
				if err != nil{
					log.Fatalln("curl error",err)
				}

				var cons Containers
				err = json.Unmarshal([]byte(res), &cons)
				handleError(err)

				var swarmNetlist []string
				for _, p := range cons {
					swarmNetlist = append(swarmNetlist, strings.Split(p.IPv4Address, "/")[0])
				}
				nt.SwarmNet[network.ID] = netDetail{network.Name, swarmNetlist}
				defer wg.Done()
			}()
		}
		wg.Wait()
	}
	return
}

// via dce-API and return json string
func urlGet(overlayNetwork, apiUrl string) (string,error) {
	httpClient := &http.Client{}
	req, err := http.NewRequest("GET", "http://"+DCEMANGERIP+apiUrl+overlayNetwork, nil)
	req.SetBasicAuth(USERNAME, PASSWORD)
	resp, err := httpClient.Do(req)

	bodyText, err := ioutil.ReadAll(resp.Body)
	return string(bodyText) ,err
}

// get path form"/run/docker/netns/"
func getFilePath(s string) string {
	files, err := ioutil.ReadDir("/run/docker/netns/")
	for _, f := range files {
		if strings.HasSuffix(f.Name(), s) {
			return f.Name()
		}
	}
	handleError(err)
	return ""
}

func (nt *netInfo) getARPnet() {
	nt.ArpNet= make(map[string]netDetail, MAPSIZE)
	var wg sync.WaitGroup
	for k, v := range nt.LocalNet {
		if len(v.IPs) > 0 {
			wg.Add(1)
			go func() {
				path := "/run/docker/netns/" + getFilePath(k[:10])

				config := &nsenter.Config{
					Mount:   true, // Execute into mount namespace
					Target:  1,    // Enter into PID 1 (init) namespace
					NetFile: path,
					Net:     true,
				}
				//  nsenter --net=/run/docker/netns/1-xt4iy2fkd4 ip neighbor show
				stdout, stderr, err := config.Execute("ip", "neigh", "show")
				if err != nil {
					fmt.Println(stderr)
					panic(err)
				}

				reg := regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
				arpIPlist := reg.FindAllString(stdout, -1)
				nt.ArpNet[k] = netDetail{v.Name,arpIPlist}
				defer wg.Done()
			}()
		} else {
			nt.ArpNet[k] = netDetail{v.Name,[]string{}}
		}
	wg.Wait()
	}
	return
}

// difference set
func diff(a, b []string) []string {
	mb := map[string]bool{}
	for _, x := range b {
		mb[x] = true
	}
	ab := []string{}
	for _, x := range a {
		if _, ok := mb[x]; !ok {
			ab = append(ab, x)
		}
	}
	return ab
}

func (nt *netInfo) missARPtable() {
	var wg sync.WaitGroup
	nt.MissArpNet = make(map[string]netDetail, MAPSIZE)
	for k, v := range nt.LocalNet {
		if len(v.IPs) > 0 {
			wg.Add(1)
			go func() {
				nt.MissArpNet[k] = netDetail{ nt.MissArpNet[k].Name,diff(diff(nt.SwarmNet[k].IPs, nt.LocalNet[k].IPs), nt.ArpNet[k].IPs)}
				if len(nt.MissArpNet[k].IPs) > 0{
					fmt.Printf("Network :%v ==> Missing ARP IP:%v\n", nt.MissArpNet[k].Name,nt.MissArpNet[k].IPs)
				}
				defer wg.Done()
			}()
		}
	}
	wg.Wait()
	return
}

func ipTomac(ip string) string {
	//ipslist := []string{"10.0.21.13","10.0.21.21"}
	ipseqstr := strings.Split(ip, ".")
	ipseqint := make([]int, 4)
	for i := 0; i < 4; i++ {
		ipint, err := strconv.Atoi(ipseqstr[i])
		ipseqint[i] = ipint
		if err != nil {
			fmt.Println(err)
		}
	}
	ip2mac := "02:42:" + fmt.Sprintf("%02x:%02x:%02x:%02x", ipseqint[0], ipseqint[1], ipseqint[2], ipseqint[3])
	return ip2mac
}

// nsenter --net=/run/docker/netns/1-xt4iy2fkd4 ip neigh add 10.0.21.13 lladdr 02:42:0a:00:15:0d dev vxlan1 nud permanent
func (nt *netInfo) addARPtable() {
	var wg sync.WaitGroup
	for k, v := range nt.MissArpNet {
		if len(v.IPs) > 0 {
			wg.Add(1)
			go func() {
				fmt.Printf("==> will add Network :%v ==> Missing ARP IP: %v\n",nt.MissArpNet[k].Name,nt.MissArpNet[k].IPs)
				path := "/run/docker/netns/" + getFilePath(k[:10])
				config := &nsenter.Config{
					Mount:   true, // Execute into mount namespace
					Target:  1, // Enter into PID 1 (init) namespace
					NetFile: path,
					Net:     true,
				}

				for _, ip := range nt.MissArpNet[k].IPs {
					ip2mac := ipTomac(ip)
					fmt.Printf("%v is adding...", ip)
					// ip neighbor add ip lladdr ip2mac dev vxlan1 nud permanent
					stdout, stderr, err := config.Execute("ip", "neigh", "add", ip, "lladdr", ip2mac, "dev", "vxlan1", "nud", "permanent")
					if err != nil {
						fmt.Println(stderr)
						panic(err)
					}

					wg.Add(1)
					go func() {
						logFile, err := os.OpenFile(LOGPATH, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0664)
						defer logFile.Close()
						if err != nil {
							log.Fatalln("open file error !", err)
						}

						arpLog := log.New(logFile, "[info]", log.LstdFlags)
						arpLog.Printf("added Network: %v ==> Missing ARP IP: %v", k, ip)
						fmt.Println(stdout)
					}()
				}
				fmt.Println("==>  this network added sucessefully!  <==")
				fmt.Println()
			}()
		}
	}
	wg.Wait()
}

func main() {
	// command args
	flag.StringVar(&USERNAME, "u", "admin", "dec management node username")
	flag.StringVar(&PASSWORD, "p", "8520.", "dec management node password")
	flag.StringVar(&DCEMANGERIP, "i", "192.168.2.7", "dec management node IP")
	flag.StringVar(&OPERATE, "o", "show", "show|add missing arp_list ")
	flag.StringVar(&LOGPATH, "l", "	flush_arp.log", "record log path")
	flag.Parse()

	var nt netInfo
	nt.getNet()
	nt.getARPnet()


	if OPERATE == "show" {
		nt.missARPtable()
	}
	if OPERATE == "add" {
		nt.missARPtable()
		fmt.Println(nt)
		nt.addARPtable()
	}
}
