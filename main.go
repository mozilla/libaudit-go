package main

import . "syscall"
import . "encoding/binary"
import "fmt"
import . "unsafe"

type NetlinkAuditRequest struct {
    Header NlMsghdr
    Data   RtGenmsg
}

func (msg *IfInfomsg) ToWireFormat() []byte {
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

func nativeEndian() ByteOrder {
    var x uint32 = 0x01020304
    if *(*byte)(Pointer(&x)) == 0x01 {
        return BigEndian
    }
    return LittleEndian
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

type IfInfomsg struct {
    IfInfomsg
}

type NetlinkRequest struct {
    NlMsghdr
    Data []NetlinkRequestData
}

func (msg *IfInfomsg) Len() int {
    return SizeofIfInfomsg
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
        return nil, err
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
        return err
    }
    return nil
}

func (s *NetlinkSocket) Receive() ([]NetlinkMessage, error) {
    rb := make([]byte, Getpagesize())
    nr, _, err := Recvfrom(s.fd, rb, 0)
    if err != nil {
        return nil, err
    }
    if nr < NLMSG_HDRLEN {
        return nil, ErrShortResponse
    }
    rb = rb[:nr]
    return ParseNetlinkMessage(rb)
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
    lsa, err := Getsockname(s.fd)
    if err != nil {
        return 0, err
    }
    switch v := lsa.(type) {
    case *SockaddrNetlink:
        return v.Pid, nil
    }
    return 0, ErrWrongSockType
}


func (s *NetlinkSocket) HandleAck(seq uint32) error {
    native := nativeEndian()
    pid, err := s.GetPid()
    if err != nil {
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
                    return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
                }
                if m.Header.Pid != pid {
                    return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, pid)
                }
                if m.Header.Type == NLMSG_DONE {
                    break done
                }
                if m.Header.Type == NLMSG_ERROR {
                    error := int32(native.Uint32(m.Data[0:4]))
                    if error == 0 {
                        break done
                    }
                    return Errno(-error)
                }
            }
        }
    return nil
}

func main() {
    
}