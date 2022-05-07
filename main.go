package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"encoding/binary"
)

func urlToQName(url string) [] byte {
	buffer := make([] byte, 0, 255)
	labels := strings.Split(url, ".")
	for _, s := range labels {
		b := []byte(s)
		buffer = append(buffer, byte(len(b)))
		buffer = append(buffer, b...)
	}
	buffer = append(buffer, 0x00)
	return buffer
}

func createDNSQuery(url string) [] byte {
	buffer := make([] byte, 12, 512)	// 12 bytes is length of the header
	var id uint16 = uint16(os.Getpid())
	fmt.Println("The query ID: ", id)
	
	/* network byte order is big endian, 
	 therefore any integer value wider than 8 bit 
	 should be converted properly */
	 
	// put ID
	binary.BigEndian.PutUint16(buffer[0:2], id)
	
	/*
	var flags uint16 = 0
	flags |= (0x00 << 0)	// 0th bit is query bit: 0/1 - query/response
	flags |= (0x00 << 1)	// the bits 1-4 is opcode value: 0000 - a standard query
	flags |= (0x00 << 5)	// 5th bit - authoritative answer, has meaning for response only
	flags |= (0x00 << 6)	// 6th bit - truncation flags
	flags |= (0x01 << 7)	// 7th bit - recursion desired, we make recursive query
	flags |= (0x00 << 8)	// 8th bit - recursion enabled, has meaning for response only
	flags |= (0x00 << 9)	// the bits 9-11 are reserved for now and should be zero
	flags |= (0x00 << 12)	// the bits 12-15 is response code, used by response
	*/
	
	var flags uint16 = 0
	flags |= (0x00 << 15)	// 15th bit is query bit: 0/1 - query/reply
	flags |= (0x00 << 14)	// the bits 14-11 is opcode value: 0000 - a standard query
	flags |= (0x00 << 10)	// 10th bit - authoritative answer, has meaning for response only
	flags |= (0x00 << 9)	// 9th bit - truncation flags
	flags |= (0x01 << 8)	// 8th bit - recursion desired, we make recursive query
	flags |= (0x00 << 7)	// 7th bit - recursion enabled, has meaning for response only
	flags |= (0x00 << 6)	// the bits 6-4 are reserved for now and should be zero
	flags |= (0x00 << 0)	// the bits 3-0 is response code, used by response	
	
	// put flags
	binary.BigEndian.PutUint16(buffer[2:4], flags)
	
	// put qdcount, the number of entries in the question section
	var qdcount uint16 = 1
	binary.BigEndian.PutUint16(buffer[4:6], qdcount)
	
	// put ancount, the number of resource records in the answer section
	var ancount uint16 = 0
	binary.BigEndian.PutUint16(buffer[6:8], ancount)
	
	// put nscount, the number of name server resource records in the authority records section
	var nscount uint16 = 0
	binary.BigEndian.PutUint16(buffer[8:10], nscount)
	
	// put arcount, the number of resource records in the additional records section
	var arcount uint16 = 0
	binary.BigEndian.PutUint16(buffer[10:12], arcount)

	fmt.Println("The length of the header (bytes): ", len(buffer))
	
	qname := urlToQName(url)
	fmt.Println("The length of the qname (bytes): ", len(qname))	
	
	// build DNS Questions section	
	buffer = append(buffer, qname...)
	offset := len(buffer)
	buffer = append(buffer[0:offset], []byte{0x00, 0x00, 0x00, 0x00}...)
	// put qtype (0x0001 - A records, i.e. host addresses)
	binary.BigEndian.PutUint16(buffer[offset:offset+2], 0x0001)
	offset += 2
	// put qclass (0x0001 - Internet addresses)
	binary.BigEndian.PutUint16(buffer[offset:], 0x0001)
	
	fmt.Println("The length of the query (bytes): ", len(buffer))
	
	return buffer
}

func parseDNSReply(buffer [] byte) {
	id := binary.BigEndian.Uint16(buffer[0:])
	flags := binary.BigEndian.Uint16(buffer[2:])
	
	fmt.Println("The reply ID: ", id)
	fmt.Printf("flags: %04x\n", flags)
	if flags & 0x8000 == 0 {
		fmt.Println("It is not a reply!")
		return
	}
	
	if flags & 0x0080 != 0 {
		fmt.Println("Recursion available")
	}
	
	if flags & 0x0020 != 0 {
		fmt.Println("Answer authenticated")
	}
	
	// rcode
	fmt.Print("rcode: ")
	switch flags & 0x000F {
		case 0:
			fmt.Println("no errors")
		case 1:
			fmt.Println("format error")
		case 2:
			fmt.Println("server error")
		case 3:
			fmt.Println("name error")
		case 4:
			fmt.Println("not implemented (not available)")
		case 5:
			fmt.Println("refused")
		default:
			fmt.Println("Invalid RCODE!")
	}

	fmt.Println("QDCOUNT: ", binary.BigEndian.Uint16(buffer[4:]))
	fmt.Println("ANCOUNT: ", binary.BigEndian.Uint16(buffer[6:]))
	fmt.Println("NSCOUNT: ", binary.BigEndian.Uint16(buffer[8:]))
	fmt.Println("ARCOUNT: ", binary.BigEndian.Uint16(buffer[10:]))
	
	ancount := binary.BigEndian.Uint16(buffer[6:])
	var offset uint16 = 12
	for i := 0; i < int(ancount); i++ {
		n := parseDNSAnswer(buffer[offset:])
		fmt.Println("\nn = ", n)
		offset += n
	}
}

func parseDNSAnswer(buffer [] byte) uint16 {
	var name string
	var offset uint16 = 0
	var i byte = 0
	var n byte = buffer[i]
	for n != 0 {
		i += 1
		name += string(buffer[i:i+n])
		name += "."
		i += n
		n = buffer[i]
	}
	
	offset = uint16(i) + 1
	
	fmt.Println("Queried name: ", name)
	
	rtype := binary.BigEndian.Uint16(buffer[offset:])
	offset += 2
	class := binary.BigEndian.Uint16(buffer[offset:])
	offset += 2
	ttl := binary.BigEndian.Uint32(buffer[offset:])
	offset += 4
	rdlength := binary.BigEndian.Uint16(buffer[offset:])
	offset += 2
	
	fmt.Printf("class: %04x, ttl: %d, data length: %d, type: ", class, ttl, rdlength)
	if rtype == 0x0001 {
		fmt.Println("A-record")		
		var hostIP [4]byte
		for i = 0; i < 4; i++ {
			hostIP[i] = buffer[offset + uint16(i)]
		}
		fmt.Printf("Host IP: %d.%d.%d.%d\n", uint16(hostIP[0]), uint16(hostIP[1]), uint16(hostIP[2]), uint16(hostIP[3]))
		offset += 4
	} else if rtype == 0x0005 {
		fmt.Println("CNAME")
	} else if rtype == 0x000f {
		fmt.Println("mailserver")
	}
	
	// offset += rdlength
	
	return offset
}

func main() {
	args := os.Args
	if len(args) == 1 {
		fmt.Println("Provide an URL(s) to resolve, please")
		return
	}
	
	url := args[1]
	fmt.Println("Asking DNS server about: ", url)
	queryBuffer := createDNSQuery(url)

	fmt.Println("The length of queryBuffer (bytes) = ", len(queryBuffer))
	fmt.Println("The buffer content:")
	for i := 0; i < len(queryBuffer); i++ {
		fmt.Printf("%02x ", queryBuffer[i])
	}

	s, err := net.ResolveUDPAddr("udp4", "8.8.8.8:53")
	if err != nil {
		fmt.Println("ResolveUDPAddr failed. ", err)
		return
	}

	c, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		fmt.Println("DialUDP failed. ", err)
		return
	}
	
	fmt.Printf("Remote server is %s\n", c.RemoteAddr().String())
	defer c.Close()
	
	fmt.Println("Sending packet: ")
	for i := 0; i < len(queryBuffer); i++ {
		fmt.Printf("%02x ", queryBuffer[i])
	}

	_, err = c.Write(queryBuffer)
	if err != nil {
		fmt.Println("Write failed. ", err)
		return
	}
	
	buffer := make([]byte, 512)
	n, _, err := c.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Read failed. ", err)
		return
	}
	
	fmt.Printf("\nReceived %d bytes", n)
	reply := buffer[0:n]
	fmt.Printf("\nReceived data (%d bytes): ", len(reply))
	for i := 0; i < len(reply); i++ {
		fmt.Printf("%02x ", reply[i])
	}
	
	fmt.Println("\n-------- RESPONSE(s) --------\n")
	parseDNSReply(reply)
}
