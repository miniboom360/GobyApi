package tests

import (
	"fmt"
	"goby-scan/handler/gobyApi"
	"context"
	"testing"
	"time"
)

func TestStartScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute * 30)
	defer cancel()
	ips := make([]string, 0)
	ips = append(ips,"172.31.10.10")
	ips = append(ips, "172.31.10.11")
	g := gobyApi.NewGobyApi(ips,ctx)

	g.StartScan()
	//fmt.Printf("g is %#v", g)
	if g.ScanStatus {
		fmt.Println("StartScan is scuess, over!")
	}

	m, err := gobyApi.GetAssetByTaskId(g.TaskId)
	if err !=nil{
		fmt.Println(err)
		return
	}
	fmt.Printf("details = %#v\n", m)

	vuln, err := gobyApi.GetVulnsByTaskId(g.TaskId)
	if err != nil{
		panic(err)
	}
	fmt.Println(vuln)

}


