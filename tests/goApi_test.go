package tests

import (
	"fmt"
	"context"
	gobyApi "github.com/miniboom360/GobyApi"
	"testing"
	"time"
)

func TestStartScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute * 30)
	defer cancel()
	ips := make([]string, 0)
	ips = append(ips,"xxxx.xxx")

	//remote host
	// not http://172.31.13.199:8361/
	g := gobyApi.NewGobyApi(ips,"http://172.31.13.199:8361","1000-6000",ctx)

	//localhost
	//g := gobyApi.NewGobyApi(ips,"","1000-5000",ctx)

	g.StartScan()
	//fmt.Printf("g is %#v", g)
	if g.ScanStatus {
		fmt.Println("StartScan is scuess, over!")
	}

	m, err := g.GetAsserts()
	if err !=nil{
		fmt.Println(err)
		return
	}
	fmt.Printf("details = %#v\n", m)

	vuln, err := g.GetVulns()
	if err != nil{
		panic(err)
	}
	fmt.Println(vuln)

}


