package main

import (. "syscall"
         "encoding/binary"
        "fmt"
        "unsafe"
        . "sync/atomic"
        "errors"
        "net"
)        

var nextSeqNr uint32

type NetlinkAuditRequest struct {
    Header NlMsghdr
    Data   RtGenmsg
}

var (
    ErrWrongSockType = errors.New("Wrong socket type")
    ErrShortResponse = errors.New("Got short response from netlink")
)
// A Route is a subnet associated with the interface to reach it.
type Route struct {
    *net.IPNet
    Iface *net.Interface
    Default bool
}


type IfInfomsg_two struct {
    IfInfomsg
}
/*
func (msg *IfInfomsg_two) ToWireFormat() []byte {
    native := nativeEndian()
    length := SizeofIfInfomsg
    b := make([]byte, length)
    b[0] = msg.Family
    b[1] = 0
    native.PutUint16(b[2:4], msg.Type)
    native.PutUint32(b[4:8], uint32(msg.Index))
    native.PutUint32(b[8:12], msg.Flags)
    native.PutUint32(b[12:16], msg.Change)
    return b
}
*/


func (rr *NetlinkRequest) ToWireFormat() []byte {
    native := nativeEndian()
    length := rr.Len
    dataBytes := make([][]byte, len(rr.Data))
    for i, data := range rr.Data {
        dataBytes[i] = data.ToWireFormat()
        length += uint32(len(dataBytes[i]))
    }
    b := make([]byte, length)
    native.PutUint32(b[0:4], length)
    native.PutUint16(b[4:6], rr.Type)
    native.PutUint16(b[6:8], rr.Flags)
    native.PutUint32(b[8:12], rr.Seq)
    native.PutUint32(b[12:16], rr.Pid)
    next := 16
    for _, data := range dataBytes {
        copy(b[next:], data)
        next += len(data)
    }
    return b
}

func nativeEndian() binary.ByteOrder {
    var x uint32 = 0x01020304
    if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
        return binary.BigEndian
    }
    return binary.LittleEndian
}

/*
func newNetlinkAuditRequest(proto, seq, family int) []byte {
    rr := &NetlinkAuditRequest{}
    rr.Header.Len = uint32(NLMSG_HDRLEN + SizeofRtGenmsg)
    rr.Header.Type = uint16(proto)
    rr.Header.Flags = NLM_F_ACK | NLM_F_REQUEST
    rr.Header.Seq = uint32(seq)
    rr.Data.Family = uint8(family)
    return rr.toWireFormat()
}
*/


type NetlinkRequest struct {
    NlMsghdr
    Data []NetlinkRequestData
}



func (s *NetlinkSocket) Close() {
    Close(s.fd)
}

type NetlinkRequestData interface {
    Len() int
    ToWireFormat() []byte
}

type NetlinkSocket struct {
    fd int
    lsa SockaddrNetlink
}

func getNetlinkSocket() (*NetlinkSocket, error) {
    fd, err := Socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT)
    if err != nil {
        //return nil, err
        fmt.Println("statement 1")
    }
    s := &NetlinkSocket{
        fd: fd,
    }
    s.lsa.Family = AF_NETLINK
    if err := Bind(fd, &s.lsa); err != nil {
        Close(fd)
        return nil, err
    }
    return s, nil
}

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
    if err := Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
        fmt.Println("statement error 1")
        return err
    }
    fmt.Println("statement 2")
    return nil
}

func (s *NetlinkSocket) Receive() ([]NetlinkMessage, error) {
    rb := make([]byte, Getpagesize())
    nr, _, err := Recvfrom(s.fd, rb, 0)
    if err != nil {
        fmt.Println("statement error 2")
        return nil, err
    }
    if nr < NLMSG_HDRLEN {
        fmt.Println("statement error 3")
        return nil, ErrShortResponse
    }
    rb = rb[:nr]
    fmt.Println("statement 3")
    return ParseNetlinkMessage(rb)
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
    lsa, err := Getsockname(s.fd)
    if err != nil {
        fmt.Println("statement 4")
        return 0, err
    }
    switch v := lsa.(type) {
    case *SockaddrNetlink:
        fmt.Println("statement 5")
        return v.Pid, nil
    }
    return 0, ErrWrongSockType
}


func (s *NetlinkSocket) HandleAck(seq uint32) error {
    native := nativeEndian()
    pid, err := s.GetPid()
    if err != nil {
        fmt.Println("statement error 4")
        return err
    }
    done:
        for {
            msgs, err := s.Receive()
            if err != nil {
                return err
            }   
            for _, m := range msgs {
                if m.Header.Seq != seq {
                    fmt.Println("Wrong Seq, expected ")
                }
                if m.Header.Pid != pid {
                    fmt.Println("Wrong pid , expected")
                }
                if m.Header.Type == NLMSG_DONE {
                    //fmt.Println("working")
                    fmt.Println("statement 6")
                    break done
                }
                if m.Header.Type == NLMSG_ERROR {
                    error := int32(native.Uint32(m.Data[0:4]))
                    if error == 0 {
                        break done
                    }
                    fmt.Println(EINVAL)
                    return Errno(-error)
                }
            }
        }
    return nil
}

func newNetlinkRequest(proto, flags int) *NetlinkRequest {
    return &NetlinkRequest{
        NlMsghdr: NlMsghdr{
            Len: uint32(NLMSG_HDRLEN),
            Type: uint16(proto),
            Flags: NLM_F_REQUEST | uint16(flags),
            Seq: AddUint32(&nextSeqNr, 1),
        },
    }
}

func main() {
    socket, _ := getNetlinkSocket()
    defer socket.Close()

    RequestData := newNetlinkRequest(AF_NETLINK, NETLINK_AUDIT)
    //socketFamily := NetlinkSocket{AF_NETLINK, socket}
    socket.Send(RequestData)
    socket.HandleAck(RequestData.NlMsghdr.Seq)
}