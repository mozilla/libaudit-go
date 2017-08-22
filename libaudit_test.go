package libaudit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestWireFormat(t *testing.T) {
	rr := NetlinkMessage{}
	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + 4)
	rr.Header.Type = syscall.AF_NETLINK
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = 2
	data := make([]byte, 4)
	hostEndian.PutUint32(data, 12)
	rr.Data = append(rr.Data[:], data[:]...)
	var result = []byte{20, 0, 0, 0, 16, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0}
	var expected = rr.ToWireFormat()
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ToWireFormat(): expected %v, found %v", result, expected)
	}

	// we currently are avoiding testing repacking byte stream into struct
	// as we don't have a single correct way to repack (kernel side allows a lot of cases which needs to be managed on our side)
	// re, err := parseAuditNetlinkMessage(result)
	// if err != nil {
	// 	t.Errorf("parseAuditNetlinkMessage failed: %v", err)
	// }

	// if !reflect.DeepEqual(rr, re[0]) {
	// 	t.Errorf("parseAuditNetlinkMessage: expected %v , found %v", rr, re[0])
	// }
}

func TestNetlinkConnection(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("skipping netlink support test: not root user")
	}
	s, err := NewNetlinkConnection()
	if err != nil {
		t.Errorf("NewNetlinkConnection failed %v", err)
	}
	defer s.Close()
	wb := newNetlinkAuditRequest(uint16(AUDIT_GET), syscall.AF_NETLINK, 0)
	if err = s.Send(wb); err != nil {
		t.Errorf("TestNetlinkConnection: sending failed %v", err)
	}
	_, err = auditGetReply(s, wb.Header.Seq, true)
	if err != nil {
		t.Errorf("TestNetlinkConnection: test failed %v", err)
	}
}

func TestSetters(t *testing.T) {
	var (
		s             *NetlinkConnection
		err           error
		actualStatus  = 1
		actualPID     = os.Getpid()
		actualRate    = 500
		actualBackLog = 500
	)
	if os.Getuid() != 0 {
		testSettersEmulated(t)
		t.Skipf("skipping netlink socket based tests: not root user")
	}
	s, err = NewNetlinkConnection()
	defer s.Close()
	err = AuditSetEnabled(s, true)
	if err != nil {
		t.Errorf("AuditSetEnabled failed %v", err)
	}
	auditstatus, err := AuditIsEnabled(s)
	if err != nil {
		t.Errorf("AuditIsEnabled failed %v", err)
	}
	if !auditstatus {
		t.Errorf("AuditIsEnabled returned false")
	}
	err = AuditSetRateLimit(s, actualRate)
	if err != nil {
		t.Errorf("AuditSetRateLimit failed %v", err)
	}
	err = AuditSetBacklogLimit(s, actualBackLog)
	if err != nil {
		t.Errorf("AuditSetBacklogLimit failed %v", err)
	}

	err = AuditSetPID(s, actualPID)
	if err != nil {
		t.Errorf("AuditSetPID failed %v", err)
	}
	// now we run `auditctl -s` and match the returned status, rate limit,
	// backlog limit and pid from the kernel with the passed args. we rely on the format `auditctl`
	// emits its output for parsing the values. If `auditctl` changes the format, the collection
	// will need to rewritten.(specifically at https://fedorahosted.org/audit/browser/trunk/src/auditctl-listing.c audit_print_reply)

	cmd := exec.Command("auditctl", "-s")
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput

	if err := cmd.Run(); err != nil {
		t.Skipf("auditctl execution failed %v, skipping test", err)
	}
	var (
		enabled      string
		rateLimit    string
		backLogLimit string
		pid          string
		result       string
	)
	result = cmdOutput.String()
	resultStr := strings.Split(result, "\n")
	strip := strings.Split(resultStr[0], " ")
	enabled = strip[1]
	strip = strings.Split(resultStr[2], " ")
	pid = strip[1]
	strip = strings.Split(resultStr[3], " ")
	rateLimit = strip[1]
	strip = strings.Split(resultStr[4], " ")
	backLogLimit = strip[1]

	if enabled != fmt.Sprintf("%d", actualStatus) {
		t.Errorf("expected status %v, found status %v", actualStatus, enabled)
	}
	if backLogLimit != fmt.Sprintf("%d", actualBackLog) {
		t.Errorf("expected back_log_limit %v, found back_log_limit %v", actualBackLog, backLogLimit)
	}
	if pid != fmt.Sprintf("%d", actualPID) {
		t.Errorf("expected pid %v, found pid %v", actualPID, pid)
	}
	if rateLimit != fmt.Sprintf("%d", actualRate) {
		t.Errorf("expected rate %v, found rate %v", actualRate, rateLimit)
	}

}
