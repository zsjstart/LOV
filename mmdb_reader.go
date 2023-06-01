package main

import (
	"fmt"
	"log"
	"net"
        "time"
	"github.com/oschwald/maxminddb-golang"
	"C"
	"unsafe"
	"os"
	"bufio"
	"strings"
)

//export lookup
func lookup(ipstr string) (uintptr) {
	db, err := maxminddb.Open("/home/zhao/Shujie/Routing_traffic/coding/LocalData/GeoIP/GeoLite2-City.mmdb")
	//db, err := maxminddb.Open("./LocalData/GeoIP/GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ip := net.ParseIP(ipstr)

	var record struct {
		Location struct {
			Latitude float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
			
		} `maxminddb:"location"`
		
		
	} // Or any appropriate struct
        loc := []float64{}
	err = db.Lookup(ip, &record)
	
	if err != nil {
		loc = append(loc, 9999.0, 9999.0)
	}
	
	loc = append(loc, record.Location.Latitude, record.Location.Longitude)
	return uintptr(unsafe.Pointer(&loc[0]))
}


func mylookup(ipstr string) {
	defer func() { <-sem }()
	defer wg.Done()
	
	db, err := maxminddb.Open("/home/zhao/Shujie/Routing_traffic/coding/LocalData/GeoIP/GeoLite2-City.mmdb")
	//db, err := maxminddb.Open("./LocalData/GeoIP/GeoLite2-City.mmdb")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ip := net.ParseIP(ipstr)

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		
	} // Or any appropriate struct
        loc := []float64{}
	err = db.Lookup(ip, &record)
	
	if err != nil {
		return
	}
	of.Write(record.Country.ISOCode)
	
}

var sem chan bool
var wg sync.WaitGroup
var of, _ := os.OpenFile("/home/zhao/Shujie/coding/Datasets/online_analysis/all_public_ips_isocodes.dat", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
defer of.Close()

func test() {
	infile, err := os.Open("/home/zhao/Shujie/coding/Datasets/online_analysis/all_public_uniqueips.dat")  
    	if err!=nil {
		panic(err)
    	}
	defer infile.Close()
	
	
	
	sem = make(chan bool, 50)
	scanner := bufio.NewScanner(infile) 
	buf := make([]byte, 0, 64*1024)
        scanner.Buffer(buf, 400*1024*1024)
    	for scanner.Scan() { 
		line := scanner.Text()
		fields := strings.Split(line, ",")
		if len(fields) < 1{ continue }
		ip := fields[0]
		wg.Add(1)
		sem <- true
		
		go mylookup(ip)
        }
	wg.Wait()
}


func main() {
	test()
     

}
