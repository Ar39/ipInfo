package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func GetInfo(c *cli.Context) {
	ip := c.String("ip")
	if strings.HasSuffix(ip, "/24") == true {
		//扫描C段
		for i := 1; i <= 255; i += 1 {
			tmp := strings.LastIndex(ip, ".")
			ipNet := ip[:tmp]
			ipC := ipNet + "." + strconv.Itoa(i)
			//fmt.Println(ipC)
			err := GetInterFace(ipC)
			if err != nil {
				fmt.Println(err)
				continue
			}
		}

	} else {
		err := GetInterFace(ip)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func GetInterFace(ip string) error {
	fmt.Println(ip)
	addr := ip + ":" + strconv.Itoa(135)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Printf("连接失败")
		return err
	}
	defer conn.Close()
	buf := make([]byte, 4096)
	payloadStep1 := "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
	payloadStep2 := "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
	conn.Write([]byte(payloadStep1))
	packV1, err := conn.Read(buf)
	conn.Write([]byte(payloadStep2))
	packV1, err = conn.Read(buf)
	// fmt.Print(pack_v1)
	result := buf[:packV1]
	Inter := string(result)
	Inter = Inter[42:]
	// 数据清洗
	flag := strings.Index(Inter, "\x09\x00\xff\xff\x00\x00")
	end := Inter[:flag-4]
	hostnameOrip := strings.Split(end, "\x00\x00")
	// 删除空格
	fmt.Println(hostnameOrip)
	// fmt.Println(reflect.TypeOf(hostname))
	for _, value := range hostnameOrip {
		fmt.Printf("\t[->] %s\n", value)
	}
	return nil
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "scan",
				Aliases: []string{"c"},
				Usage:   "complete a task on the list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "ip",
						Aliases: []string{"i"},
						Usage:   "get a info of interface",
					},
				},
				Action: func(c *cli.Context) error {
					GetInfo(c)
					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
