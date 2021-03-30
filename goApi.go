package gobyApi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/thedevsaddam/gojsonq"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxScanContent int = 5
)

type (
	GobyApi struct {
		TaskId            string
		CurrentGobyTaskId string
		WaitingIps        []string

		//max five ip scanning
		ScaningIps       []string
		GobyTaskIdAndIPs map[string][]string
		notice           chan int
		ScanStatus       bool
		HostInfo string
		PortScope string
		ctx       context.Context

		//url
		startScanAddr string
		getProgessAddr string
		getAssetSearch string
		getVulnSearch string
		stopScanAddr string
	}

	GobyStartScanReq struct {
		Asset struct {
			Ips           []string `json:"ips"`
			Ports         string   `json:"ports"`
			Vulnerability struct {
				Type string `json:"type"`
			} `json:"vulnerability"`
		} `json:"asset"`
	}

	GobyGetProgess struct {
		Taskid string `json:"taskid"`
	}

	GObyAssetSearch struct {
		Query string `json:"query"`
	}

	AssetDetails struct {
		// map[gobyTaskId][ip:port]protocol
		Assets map[string]map[string]string `json:"assets"`
	}
)

var (
	// todo: sync.Map
	// map[gobyTaskId]map[ip:port]asset
	Asserts map[string]map[string]string
	// map[taskId]{ goTaskId1, goTaskId2...}

	AllAsserts sync.Map
)

func NewGobyApi(ips []string, hostInfo, portScope string, ctx context.Context) *GobyApi {
	g := new(GobyApi)
	g.GobyTaskIdAndIPs = make(map[string][]string, 0)
	g.notice = make(chan int, 0)
	g.TaskId = uuid.New().String()
	if ctx == nil {
		g.ctx = context.Background()
	} else {
		g.ctx = ctx
	}
	if hostInfo == "" {
		g.HostInfo = "http://127.0.0.1:8361/api/v1/"
	} else {
		g.HostInfo = hostInfo + "/api/v1/"
	}

	g.PortScope = portScope

	g.init(ips)
	return g
}

// handle this two format
// 192.168.0.1-65
// 192.168.0.1/24
// 192.168.1.1
// 192.168.1.1#172.12.31.1#...
func (g *GobyApi) init(ips []string) error {
	for _, ip := range ips {
		if g.isIpv4(ip) {
			g.WaitingIps = append(g.WaitingIps, ip)
			continue
		}
		if find := strings.Contains(ip, "#"); find {
			g.WaitingIps = append(g.WaitingIps, strings.Split(ip, "#")...)
		}
		if find := strings.Contains(ip, "-"); find {
			ips, err := g.fromToIp(ip)
			if err != nil {
				log.Fatal(err)
				continue
			}
			g.WaitingIps = append(g.WaitingIps, ips...)
		}
		if find := strings.Contains(ip, "/24"); find {
			ips, err := g.cPart(ip)
			if err != nil {
				log.Fatal(err)
				continue
			}
			g.WaitingIps = append(g.WaitingIps, ips...)
		}
	}

	g.startScanAddr = g.HostInfo + "startScan"
	g.getProgessAddr = g.HostInfo + "getProgress"
	g.getAssetSearch = g.HostInfo + "assetSearch"
	g.getVulnSearch = g.HostInfo + "vulnerabilitySearch"
	g.stopScanAddr = g.HostInfo + "stopScan"


	return nil
}

// input : 192.168.1.2-4
// output : [192.168.1.2, 192.168.1.3, 192.168.1.4]
func (g *GobyApi) fromToIp(ip string) ([]string, error) {
	// ss = [192.168.1.2, 4]
	ips := make([]string, 0)
	ss := strings.Split(ip, "-")

	if len(ss) != 2 {
		return nil, errors.New("Ip format error")
	}

	//s = [192, 168, 1, 2]
	s := strings.Split(ss[0], ".")

	// fromFormat 192.168.1.
	var fromFormat string
	for i := 0; i < len(s)-1; i++ {
		fromFormat += s[i] + "."
	}

	//fromNum = 2
	fromNum, err := strconv.Atoi(s[len(s)-1])
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	toNum, err := strconv.Atoi(ss[1])
	if err != nil {
		return nil, err
	}

	for i := fromNum; i <= toNum; i++ {
		ips = append(ips, fromFormat+strconv.Itoa(i))
	}
	return ips, nil
}

// input : 192.168.1.2/24
// output : 192.168.1.0 192.168.1.1 192.168.1.2 192.168.1.3 192.168.1.4....
//			192.168.1.255
func (g *GobyApi) cPart(ip string) ([]string, error) {
	ipOrigin := strings.Split(ip, "/")
	var fromToString string

	//192.168.1.
	ss := strings.Split(ipOrigin[0], ".")
	for i := 0; i < len(ss)-1; i++ {
		fromToString += ss[i] + "."
	}

	//192.168.1.0-255
	fromToString += "0-255"
	return g.fromToIp(fromToString)
}

func (g *GobyApi) isIpv4(ip string) bool {
	ipReg := `^((0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$`
	match, _ := regexp.MatchString(ipReg, ip)
	if match {
		return true
	}
	return false
}

//开启扫描
// set time wait
func (g *GobyApi) StartScan() {
	fmt.Println("start scan task")
	if err := g.unitScan();err !=nil{
		panic(err)
	}
	go g.tickListen()
	for {
		select {
		case <-g.notice:
			goTasks := make([]string, 0)
			for k, _ := range g.GobyTaskIdAndIPs {
				goTasks = append(goTasks, k)
			}
			if vv, ok := AllAsserts.LoadOrStore(g.TaskId, goTasks); ok {
				fmt.Println(vv)
			}
			fmt.Println("Scan Task Is Over!")
			return
		case <-g.ctx.Done():
			g.stopAllScanTasks()
			fmt.Println("scan timeOut, now all scan tasks quit!")
			return
		//default:
		//	fmt.Println("unknow error")
		//	return
		}
	}
}

func (g *GobyApi) tickListen() {
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			g.checkGobyTaskProgess()
		}
	}
}

func (g *GobyApi) stopAllScanTasks() {
	for taskId, _ := range g.GobyTaskIdAndIPs {
		g.stopGobyTask(taskId)
	}
}

//stopScanAddr
func (g *GobyApi) stopGobyTask(gobyTaskId string) {
	fmt.Printf("gobytaskId = %v, will stop", gobyTaskId)
	req := new(GobyGetProgess)
	req.Taskid = gobyTaskId
	r, err := g.post(g.stopScanAddr, req)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println(string(r))
	fmt.Printf("gobytaskId = %v, stop scuess", gobyTaskId)
}

//curl 127.0.0.1:8361/api/v1/getProgress -d '{"taskid":"taskiduuid"}'
func (g *GobyApi) checkGobyTaskProgess() bool {
	if g.CurrentGobyTaskId == "" {
		return false
	}
	req := new(GobyGetProgess)
	req.Taskid = g.CurrentGobyTaskId
	r, err := g.post(g.getProgessAddr, req)
	if err != nil {
		log.Fatal(err)
		return false
	}

	p := gojsonq.New().FromString(string(r[:])).Find("data.progress").(float64)

	pi := int(p)
	if pi == 100 {
		g.unitScan()
		fmt.Println("progress 100%")
		return true
	}
	fmt.Printf("Current progress is %d\n", pi)
	return false
}

func (g *GobyApi) unitScan() error {
	// all finish
	if g.WaitingIps == nil || len(g.WaitingIps) == 0 {
		fmt.Println("scan task all finished, now out!")
		g.ScanStatus = true
		g.notice <- 1
		return nil
	}

	// pop maxScan ip
	if len(g.WaitingIps) < maxScanContent {
		g.ScaningIps = g.WaitingIps
		g.WaitingIps = nil
	} else {
		g.ScaningIps = g.WaitingIps[:maxScanContent]
		//todo:need test
		g.WaitingIps = g.WaitingIps[maxScanContent:]
	}

	body := GobyStartScanReq{}
	body.Asset.Ips = g.ScaningIps
	body.Asset.Ports = g.PortScope
	body.Asset.Vulnerability.Type = "2"

	b, err := g.post(g.startScanAddr, body)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println(string(b))

	gobyTaskId := gojsonq.New().FromString(string(b[:])).Find("data.taskId").(string)
	fmt.Printf("GobyTaskId = %s\n", gobyTaskId)
	g.CurrentGobyTaskId = gobyTaskId

	g.GobyTaskIdAndIPs[gobyTaskId] = g.ScaningIps
	return nil
}

func (g *GobyApi) post(url string, data interface{}) ([]byte, error) {
	// 超时时间：5秒
	client := &http.Client{Timeout: 5 * time.Second}
	jsonStr, _ := json.Marshal(data)
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer resp.Body.Close()

	result, _ := ioutil.ReadAll(resp.Body)
	return result, nil
}

//func Post(url string, data interface{}) ([]byte, error) {
//	// 超时时间：5秒
//	client := &http.Client{Timeout: 5 * time.Second}
//	jsonStr, _ := json.Marshal(data)
//	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonStr))
//	if err != nil {
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	result, _ := ioutil.ReadAll(resp.Body)
//	return result, nil
//}

//// get all taskId
//func getAssetByGobyTaskId(taskID string) (map[string]string, error){
//	if len(Asserts) == 0{
//		Asserts = make(map[string]map[string]string,0)
//		return getAssetByTaskId(taskID)
//	}
//
//	return getAssetByTaskId(taskID)
//}

//func GetAssetByTaskId(taskID string)(map[string]string, error){
//	vv, ok := AllAsserts.Load(taskID);
//	if !ok{
//		return nil, errors.New("Can't find this TaskId")
//	}
//	gobyTaskIds := make([]string, 0)
//
//	switch vv.(type) {
//	case []string:
//		gobyTaskIds = vv.([]string)
//	default:
//		return nil, errors.New("can't interface to slice string")
//	}
//
//	alls := make(map[string]string, 0)
//
//	for _, v := range gobyTaskIds{
//		m, err := getAssetByGobyTaskId(v)
//		if err != nil{
//			return nil, err
//		}
//		for ek, ev := range m{
//			alls[ek] = ev
//		}
//	}
//	return alls, nil
//}
//
//func GetVulnsByTaskId(taskID string)(map[string]string, error){
//	vv, ok := AllAsserts.Load(taskID);
//	if !ok{
//		return nil, errors.New("Can't find this TaskId")
//	}
//	gobyTaskIds := make([]string, 0)
//
//	switch vv.(type) {
//	case []string:
//		gobyTaskIds = vv.([]string)
//	default:
//		return nil, errors.New("can't interface to slice string")
//	}
//
//	alls := make(map[string]string, 0)
//
//	for _, v := range gobyTaskIds{
//		m, err := getVulnByGobyTaskIdFromHTTP(v)
//		if err != nil{
//			return nil, err
//		}
//		for ek, ev := range m{
//			alls[ek] = ev
//		}
//	}
//	return alls, nil
//}

func (g *GobyApi) getAssetByTaskId(taskID string) (map[string]string, error) {
	rt := make(map[string]string, 0)

	req := new(GObyAssetSearch)
	//"taskid=taskiduuid"
	req.Query = "taskid=" + taskID
	r, err := g.post(g.getAssetSearch, req)
	if err != nil {
		log.Fatal(err)
		return rt, err
	}

	rs := string(r[:])
	p := gojsonq.New().FromString(rs).From("data.ips").Select("protocols")
	list, ok := p.Get().([]interface{})
	if !ok {
		return rt, errors.New("Convert error")
	}

	//
	if len(list) == 0 {
		return nil, errors.New("Can't find this taskId")
	}

	for _, info := range list {
		infoMap, ok := info.(map[string]interface{})["protocols"]
		if !ok {
			return rt, errors.New("Convert error")
		}

		for _, v := range infoMap.(map[string]interface{}) {
			hostinfo := v.(map[string]interface{})["hostinfo"].(string)
			protocol := v.(map[string]interface{})["protocol"].(string)
			et := make(map[string]string, 0)
			et[hostinfo] = protocol

			if Asserts == nil {
				Asserts = make(map[string]map[string]string, 0)
			}

			if _, ok := Asserts[taskID]; !ok {
				Asserts[taskID] = et
			}

			if _, ok := Asserts[taskID][hostinfo]; !ok {
				Asserts[taskID][hostinfo] = protocol
			}
		}
	}
	rt = Asserts[taskID]

	return rt, err
}

//map[vulurl]name
func (g *GobyApi) getVulnByGobyTaskIdFromHTTP(taskID string) (map[string]string, error) {
	req := new(GObyAssetSearch)
	//"taskid=taskiduuid"
	req.Query = "taskid=" + taskID
	r, err := g.post(g.getVulnSearch, req)
	if err != nil {

		return nil, err
	}

	fmt.Println(string(r[:]))
	vulMap := make(map[string]string, 0)
	p := gojsonq.New().FromString(string(r[:])).From("data.list").Select("name", "vulurl")
	list, ok := p.Get().([]interface{})
	if !ok {
		fmt.Println("Convert error")
	}

	if len(list) == 0 {
		return vulMap, nil
	}

	for _, info := range list {
		vulURl := info.(map[string]interface{})["vulurl"].(string)
		vulName := info.(map[string]interface{})["name"].(string)
		//protocol := v.(map[string]interface{})["protocol"].(string)
		vulMap[vulURl] = vulName
	}

	return vulMap, nil
}
func (g *GobyApi) GetAsserts() (map[string]string, error) {
	vv, ok := AllAsserts.Load(g.TaskId)
	if !ok {
		return nil, errors.New("Can't find this TaskId")
	}
	gobyTaskIds := make([]string, 0)

	switch vv.(type) {
	case []string:
		gobyTaskIds = vv.([]string)
	default:
		return nil, errors.New("can't interface to slice string")
	}

	alls := make(map[string]string, 0)

	for _, v := range gobyTaskIds {
		m, err := g.getAssetByTaskId(v)
		if err != nil {
			return nil, err
		}
		for ek, ev := range m {
			alls[ek] = ev
		}
	}
	return alls, nil
}
func (g *GobyApi) GetVulns() (map[string]string, error) {
	vv, ok := AllAsserts.Load(g.TaskId)
	if !ok {
		return nil, errors.New("Can't find this TaskId")
	}
	gobyTaskIds := make([]string, 0)

	switch vv.(type) {
	case []string:
		gobyTaskIds = vv.([]string)
	default:
		return nil, errors.New("can't interface to slice string")
	}

	alls := make(map[string]string, 0)

	for _, v := range gobyTaskIds {
		m, err := g.getVulnByGobyTaskIdFromHTTP(v)
		if err != nil {
			return nil, err
		}
		for ek, ev := range m {
			alls[ek] = ev
		}
	}
	return alls, nil
}
