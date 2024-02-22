package utils

import (
	"fmt"
	"net"
)

func Uint32ToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(num >> 24)
	ip[1] = byte(num >> 16)
	ip[2] = byte(num >> 8)
	ip[3] = byte(num)
	return ip
}

func Byte16ToIPV6(num [16]byte) net.IP {
	ip := net.IP(num[:])
	return ip
}

func inet_ntop(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
