package libaudit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
)

type FieldType int

const (
	TypeUID FieldType = iota
	TypeGID
	TypeSyscall
	TypeArch
	TypeExit
	TypePerm
	TypeEscaped
	TypeMode
	TypeSockaddr
	TypePromisc
	TypeCapability
	TypeSuccess
	TypeA0
	TypeA1
	TypeA2
	TypeA3
	TypeSignal
	TypeList
	TypeTTYData
	TypeSession
	TypeCapBitmap
	TypeNFProto
	TypeICMP
	TypeProtocol
	TypeAddr
	TypePersonality
	TypeOFlag
	TypeSeccomp
	TypeMmap
	TypeMacLabel
	TypeProctile
	TypeUnclassified
	TypeModeShort
)

var FieldLookupMap = map[string]FieldType{
	"auid":           TypeUID,
	"uid":            TypeUID,
	"euid":           TypeUID,
	"suid":           TypeUID,
	"fsuid":          TypeUID,
	"ouid":           TypeUID,
	"oauid":          TypeUID,
	"iuid":           TypeUID,
	"id":             TypeUID,
	"inode_uid":      TypeUID,
	"sauid":          TypeUID,
	"obj_uid":        TypeUID,
	"obj_gid":        TypeGID,
	"gid":            TypeGID,
	"egid":           TypeGID,
	"sgid":           TypeGID,
	"fsgid":          TypeGID,
	"ogid":           TypeGID,
	"igid":           TypeGID,
	"inode_gid":      TypeGID,
	"new_gid":        TypeGID,
	"syscall":        TypeSyscall,
	"arch":           TypeArch,
	"exit":           TypeExit,
	"path":           TypeEscaped,
	"comm":           TypeEscaped,
	"exe":            TypeEscaped,
	"file":           TypeEscaped,
	"name":           TypeEscaped,
	"watch":          TypeEscaped,
	"cwd":            TypeEscaped,
	"cmd":            TypeEscaped,
	"acct":           TypeEscaped,
	"dir":            TypeEscaped,
	"key":            TypeEscaped,
	"vm":             TypeEscaped,
	"old-disk":       TypeEscaped,
	"new-disk":       TypeEscaped,
	"old-fs":         TypeEscaped,
	"new-fs":         TypeEscaped,
	"device":         TypeEscaped,
	"cgroup":         TypeEscaped,
	"perm":           TypePerm,
	"perm_mask":      TypePerm,
	"mode":           TypeMode,
	"saddr":          TypeSockaddr,
	"prom":           TypePromisc,
	"old_prom":       TypePromisc,
	"capability":     TypeCapability,
	"res":            TypeSuccess,
	"result":         TypeSuccess,
	"a0":             TypeA0,
	"a1":             TypeA1,
	"a2":             TypeA2,
	"a3":             TypeA3,
	"sig":            TypeSignal,
	"list":           TypeList,
	"data":           TypeTTYData,
	"ses":            TypeSession,
	"cap_pi":         TypeCapBitmap,
	"cap_pe":         TypeCapBitmap,
	"cap_pp":         TypeCapBitmap,
	"cap_fi":         TypeCapBitmap,
	"cap_fp":         TypeCapBitmap,
	"fp":             TypeCapBitmap,
	"fi":             TypeCapBitmap,
	"fe":             TypeCapBitmap,
	"old_pp":         TypeCapBitmap,
	"old_pi":         TypeCapBitmap,
	"old_pe":         TypeCapBitmap,
	"new_pp":         TypeCapBitmap,
	"new_pi":         TypeCapBitmap,
	"new_pe":         TypeCapBitmap,
	"family":         TypeNFProto,
	"icmptype":       TypeICMP,
	"proto":          TypeProtocol,
	"addr":           TypeAddr,
	"apparmor":       TypeEscaped,
	"operation":      TypeEscaped,
	"denied_mask":    TypeEscaped,
	"info":           TypeEscaped,
	"profile":        TypeEscaped,
	"requested_mask": TypeEscaped,
	"per":            TypePersonality,
	"code":           TypeSeccomp,
	"old-rng":        TypeEscaped,
	"new-rng":        TypeEscaped,
	"oflag":          TypeOFlag,
	"ocomm":          TypeEscaped,
	"flags":          TypeMmap,
	"sigev_signo":    TypeEscaped,
	"subj":           TypeMacLabel,
	"obj":            TypeMacLabel,
	"scontext":       TypeMacLabel,
	"tcontext":       TypeMacLabel,
	"vm-ctx":         TypeMacLabel,
	"img-ctx":        TypeMacLabel,
	"proctitle":      TypeProctile,
	"grp":            TypeEscaped,
	"new_group":      TypeEscaped,
}

func InterpretField(fieldName string, fieldValue string, msgType auditConstant, r record) (string, error) {
	// auparse_interpret_field() -> nvlist_interp_cur_val(const rnode *r) -> interpret(r) -> type = auparse_interp_adjust_type(r->type, id.name, id.val);
	// 	out = auparse_do_interpretation(type, &id);
	var ftype FieldType
	var result string
	var err error

	if msgType == AUDIT_EXECVE && strings.HasPrefix(fieldName, "a") && fieldName != "argc" && strings.Index(fieldName, "_len") == -1 {
		ftype = TypeEscaped
	} else if msgType == AUDIT_AVC && fieldName == "saddr" {
		ftype = TypeUnclassified
	} else if msgType == AUDIT_USER_TTY && fieldName == "msg" {
		ftype = TypeEscaped
	} else if msgType == AUDIT_NETFILTER_PKT && fieldName == "saddr" {
		ftype = TypeAddr
	} else if fieldName == "acct" {
		if strings.HasPrefix(fieldValue, `"`) {
			ftype = TypeEscaped
		} else if _, err := strconv.ParseInt(fieldValue, 16, -1); err != nil {
			ftype = TypeEscaped
		} else {
			ftype = TypeUnclassified
		}
	} else if msgType == AUDIT_MQ_OPEN && fieldName == "mode" {
		ftype = TypeModeShort
	} else if msgType == AUDIT_CRYPTO_KEY_USER && fieldName == "fp" {
		ftype = TypeUnclassified
	} else if fieldName == "id" && (msgType == AUDIT_ADD_GROUP || msgType == AUDIT_GRP_MGMT ||
		msgType == AUDIT_DEL_GROUP) {
		ftype = TypeGID
	} else {
		if _, ok := FieldLookupMap[fieldName]; ok {
			ftype = FieldLookupMap[fieldName]
		} else {
			ftype = TypeUnclassified
		}
	}

	switch ftype {
	case TypeUID:
		result, err = printUID(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "UID interpretation failed")
		}
	case TypeGID:
		// printGID is currently only a stub
		result, err = printGID(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "GID interpretation failed")
		}

	case TypeSyscall:
		result, err = printSyscall(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "syscall interpretation failed")
		}
	case TypeArch:
		return printArch()
	case TypeExit:
		result, err = printExit(fieldValue) // peek on exit codes (stderror)
		if err != nil {
			return "", errors.Wrap(err, "exit interpretation failed")
		}
	case TypePerm:
		result, err = printPerm(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "perm interpretation failed")
		}
	case TypeEscaped:
		result, err = printEscaped(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "interpretation failed")
		}
	case TypeMode:
		result, err = printMode(fieldValue, 8)
		if err != nil {
			return "", errors.Wrap(err, "mode interpretation failed")
		}
	case TypeModeShort:
		result, err = printModeShort(fieldValue, 8)
		if err != nil {
			return "", errors.Wrap(err, "short mode interpretation failed")
		}
	case TypeSockaddr:
		result, err = printSockAddr(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "sockaddr interpretation failed")
		}
	case TypePromisc:
		result, err = printPromiscuous(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "promsc interpretation failed")
		}
	case TypeCapability:
		result, err = printCapabilities(fieldValue, 10)
		if err != nil {
			return "", errors.Wrap(err, "capability interpretation failed")
		}
	case TypeSuccess:
		result, err = printSuccess(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "success interpretation failed")
		}
	case TypeA0:
		result, err = printA0(fieldValue, r.syscallNum)
		if err != nil {
			return "", errors.Wrap(err, "a0 interpretation failed")
		}
	case TypeA1:
		result, err = printA1(fieldValue, r.syscallNum, r.a0)
		if err != nil {
			return "", errors.Wrap(err, "a1 interpretation failed")
		}
	case TypeA2:
		result, err = printA2(fieldValue, r.syscallNum, r.a1)
		if err != nil {
			return "", errors.Wrap(err, "a2 interpretation failed")
		}
	case TypeA3:
		result, err = printA3(fieldValue, r.syscallNum)
		if err != nil {
			return "", errors.Wrap(err, "a3 interpretation failed")
		}
	case TypeSignal:
		result, err = printSignals(fieldValue, 10)
		if err != nil {
			return "", errors.Wrap(err, "signal interpretation failed")
		}
	case TypeList:
		result, err = printList(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "list interpretation failed")
		}
	case TypeTTYData:
		// discuss priority
		// result, err = printTTYData(fieldValue)
		// if err != nil {
		// 	return "", errors.Wrap(err, "tty interpretation failed")
		// }
	case TypeSession:
		result, err = printSession(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "session interpretation failed")
		}
	case TypeCapBitmap:
		// discuss priority
		// result, err = printCapBitMap(fieldValue)
		// if err != nil {
		// 	return "", errors.Wrap(err, "cap bitmap interpretation failed")
		// }
	case TypeNFProto:
		result, err = printNFProto(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "session interpretation failed")
		}
	case TypeICMP:
		result, err = printICMP(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "ICMP type interpretation failed")
		}
	case TypeProtocol:
		// discuss priority
		// getprotobynumber
		// result, err = printProtocol(fieldValue)
		// if err != nil {
		// 	return "", errors.Wrap(err, "ICMP type interpretation failed")
		// }
	case TypeAddr:
		result, err = printAddr(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "Addr interpretation failed")
		}
	case TypePersonality:
		result, err = printPersonality(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "personality interpretation failed")
		}
	case TypeOFlag:
		result, err = printOpenFlags(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "Addr interpretation failed")
		}
	case TypeSeccomp:
		result, err = printSeccompCode(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "seccomp code interpretation failed")
		}
	case TypeMmap:
		result, err = printMmap(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "mmap interpretation failed")
		}
	case TypeProctile:
		//printing proctitle is same as printing escaped
		result, err = printEscaped(fieldValue)
		if err != nil {
			return "", errors.Wrap(err, "proctitle interpretation failed")
		}
	case TypeMacLabel:
		fallthrough
	case TypeUnclassified:
		fallthrough
	default:
		result = fieldValue
	}

	return result, nil
}

func printUID(fieldValue string) (string, error) {

	name, err := user.LookupId(fieldValue)
	if err != nil {
		return fmt.Sprintf("unknown(%s)", fieldValue), nil
	}
	return name.Username, nil
}

// No standard function until Go 1.7
func printGID(fieldValue string) (string, error) {
	return fieldValue, nil
}

func printSyscall(fieldValue string) (string, error) {
	//NOTE: considering only x64 machines
	name, err := AuditSyscallToName(fieldValue)
	if err != nil {
		return "", errors.Wrap(err, "syscall parsing failed")
	}
	return name, nil
}

func printArch() (string, error) {
	return runtime.GOARCH, nil
}

func printExit(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "exit parsing failed")
	}
	// c version of this method tries to retrieve string description of the error code
	// ignoring the same approach as the codes can vary
	if ival == 0 {
		return "success", nil
	}
	return fieldValue, nil
}

func printPerm(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "perm parsing failed")
	}
	var perm string
	if ival == 0 {
		ival = 0x0F
	}
	if ival&AUDIT_PERM_READ > 0 {
		perm += "read"
	}
	if ival&AUDIT_PERM_WRITE > 0 {
		if len(perm) > 0 {
			perm += ",write"
		} else {
			perm += "write"
		}
	}
	if ival&AUDIT_PERM_EXEC > 0 {
		if len(perm) > 0 {
			perm += ",exec"
		} else {
			perm += "exec"
		}
	}
	if ival&AUDIT_PERM_ATTR > 0 {
		if len(perm) > 0 {
			perm += ",attr"
		} else {
			perm += "attr"
		}
	}
	return perm, nil
}

func printMode(fieldValue string, base int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, base, 64)
	if err != nil {
		return "", errors.Wrap(err, "mode parsing failed")
	}
	var name string
	firstIFMTbit := syscall.S_IFMT & ^(syscall.S_IFMT - 1)
	if syscall.S_IFMT&ival == syscall.S_IFSOCK {
		name = "socket"
	} else if syscall.S_IFMT&ival == syscall.S_IFBLK {
		name = "block"
	} else if syscall.S_IFMT&ival == syscall.S_IFREG {
		name = "file"
	} else if syscall.S_IFMT&ival == syscall.S_IFDIR {
		name = "dir"
	} else if syscall.S_IFMT&ival == syscall.S_IFCHR {
		name = "character"
	} else if syscall.S_IFMT&ival == syscall.S_IFIFO {
		name = "fifo"
	} else if syscall.S_IFMT&ival == syscall.S_IFLNK {
		name = "link"
	} else {
		name += fmt.Sprintf("%03o", (int(ival)&syscall.S_IFMT)/firstIFMTbit)
	}
	// check on special bits
	if ival&syscall.S_ISUID > 0 {
		name += ",suid"
	}
	if ival&syscall.S_ISGID > 0 {
		name += ",sgid"
	}
	if ival&syscall.S_ISVTX > 0 {
		name += ",sticky"
	}
	// the read, write, execute flags in octal
	name += fmt.Sprintf("%03o", ((syscall.S_IRWXU | syscall.S_IRWXG | syscall.S_IRWXO) & int(ival)))
	return name, nil
}

func printModeShort(fieldValue string, base int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, base, 64)
	if err != nil {
		return "", errors.Wrap(err, "short mode parsing failed")
	}
	return printModeShortInt(ival)
}

func printModeShortInt(ival int64) (string, error) {
	var name string
	// check on special bits
	if ival&syscall.S_ISUID > 0 {
		name += "suid"
	}
	if ival&syscall.S_ISGID > 0 {
		if len(name) > 0 {
			name += ","
		}
		name += "sgid"
	}
	if ival&syscall.S_ISVTX > 0 {
		if len(name) > 0 {
			name += ","
		}
		name += "sticky"
	}
	name += fmt.Sprintf("0%03o", ((syscall.S_IRWXU | syscall.S_IRWXG | syscall.S_IRWXO) & int(ival)))

	return name, nil
}

func printSockAddr(fieldValue string) (string, error) {
	// representations of c struct to unpack bytestream into
	type sockaddr struct {
		Sa_family uint16   `struc:"uint16,little"`   // address family, AF_xxx
		Sa_data   [14]byte `struc:"[14]byte,little"` // 14 bytes of protocol address
	}

	type sockaddr_un struct {
		Sun_family uint16    `struc:"uint16,little"`    /* AF_UNIX */
		Sun_path   [108]byte `struc:"[108]byte,little"` /* pathname */
	}

	type sockaddr_nl struct {
		Sun_family uint16 `struc:"uint16,little"` /* AF_NETLINK */
		Nl_pad     uint16 `struc:"uint16,little"` /* Zero. */
		Nl_pid     int32  `struc:"int32,little"`  /* Port ID. */
		Nl_groups  uint32 `struc:"uint32,little"` /* Multicast groups mask. */
	}

	type sockaddr_ll struct {
		Sll_family   uint16  `struc:"uint16,little"`  /* Always AF_PACKET */
		Sll_protocol uint16  `struc:"uint16,little"`  /* Physical-layer protocol */
		Sll_ifindex  int32   `struc:"int32,little"`   /* Interface number */
		Sll_hatype   uint16  `struc:"uint16,little"`  /* ARP hardware type */
		Sll_pkttype  byte    `struc:"byte,little"`    /* Packet type */
		Sll_halen    byte    `struc:"byte,little"`    /* Length of address */
		Sll_addr     [8]byte `struc:"[8]byte,little"` /* Physical-layer address */
	}

	type sockaddr_in struct {
		Sin_family uint16  `struc:"uint16,little"` // e.g. AF_INET, AF_INET6
		Sin_port   uint16  `struc:"uint16,big"`    // port in network byte order
		In_addr    [4]byte `struc:"[4]byte,big"`   // address in network byte order
		Sin_zero   [8]byte `struc:"[8]byte,little"`
	}

	type sockaddr_in6 struct {
		Sin6_family   uint16   `struc:"uint16,little"` // address family, AF_INET6
		Sin6_port     uint16   `struc:"uint16,big"`    // port in network byte order
		Sin6_flowinfo uint32   `struc:"uint32,little"` // IPv6 flow information
		Sin6_addr     [16]byte `struc:"[16]byte,big"`  // IPv6 address
		Sin6_scope_id uint32   `struc:"uint32,little"` // Scope ID
	}

	var famLookup = map[int]string{
		syscall.AF_LOCAL:      "local",
		syscall.AF_INET:       "inet",
		syscall.AF_AX25:       "ax25",
		syscall.AF_IPX:        "ipx",
		syscall.AF_APPLETALK:  "appletalk",
		syscall.AF_NETROM:     "netrom",
		syscall.AF_BRIDGE:     "bridge",
		syscall.AF_ATMPVC:     "atmpvc",
		syscall.AF_X25:        "x25",
		syscall.AF_INET6:      "inet6",
		syscall.AF_ROSE:       "rose",
		syscall.AF_DECnet:     "decnet",
		syscall.AF_NETBEUI:    "netbeui",
		syscall.AF_SECURITY:   "security",
		syscall.AF_KEY:        "key",
		syscall.AF_NETLINK:    "netlink",
		syscall.AF_PACKET:     "packet",
		syscall.AF_ASH:        "ash",
		syscall.AF_ECONET:     "econet",
		syscall.AF_ATMSVC:     "atmsvc",
		syscall.AF_RDS:        "rds",
		syscall.AF_SNA:        "sna",
		syscall.AF_IRDA:       "irda",
		syscall.AF_PPPOX:      "pppox",
		syscall.AF_WANPIPE:    "wanpipe",
		syscall.AF_LLC:        "llc",
		syscall.AF_CAN:        "can",
		syscall.AF_TIPC:       "tipc",
		syscall.AF_BLUETOOTH:  "bluetooth",
		syscall.AF_IUCV:       "iucv",
		syscall.AF_RXRPC:      "rxrpc",
		syscall.AF_ISDN:       "isdn",
		syscall.AF_PHONET:     "phonet",
		syscall.AF_IEEE802154: "ieee802154",
		37: "caif",
		38: "alg",
		39: "nfc",
		40: "vsock",
	}
	var name string
	var s sockaddr

	bytestr, err := hex.DecodeString(fieldValue)
	if err != nil {
		return fieldValue, errors.Wrap(err, "sockaddr parsing failed")
	}

	// family := int(bytestr[0]) + 256*int(bytestr[1])
	buf := bytes.NewBuffer(bytestr)
	err = struc.Unpack(buf, &s)

	if err != nil {
		return fieldValue, errors.Wrap(err, "sockaddr decoding failed")
	}
	family := int(s.Sa_family)

	if _, ok := famLookup[int(family)]; !ok {
		return fmt.Sprintf("unknown family (%d)", family), nil
	}

	errstring := fmt.Sprintf("%s (error resolving addr)", famLookup[family])

	switch family {

	case syscall.AF_LOCAL:
		var p sockaddr_un
		nbuf := bytes.NewBuffer(bytestr)

		err = struc.Unpack(nbuf, &p)
		if err != nil {
			return fieldValue, errors.Wrap(err, errstring)
		}
		name = fmt.Sprintf("%s %s", famLookup[family], string(p.Sun_path[:]))
		return name, nil

	case syscall.AF_INET:
		var ip4 sockaddr_in

		nbuf := bytes.NewBuffer(bytestr)
		err = struc.Unpack(nbuf, &ip4)
		if err != nil {
			return fieldValue, errors.Wrap(err, errstring)
		}
		addrBytes := ip4.In_addr[:]
		var x net.IP = addrBytes
		name = fmt.Sprintf("%s host:%s serv:%d", famLookup[family], x.String(), ip4.Sin_port)
		return name, nil
	case syscall.AF_INET6:
		var ip6 sockaddr_in6
		nbuf := bytes.NewBuffer(bytestr)
		err = struc.Unpack(nbuf, &ip6)
		if err != nil {
			return fieldValue, errors.Wrap(err, errstring)
		}
		addrBytes := ip6.Sin6_addr[:]
		var x net.IP = addrBytes
		name = fmt.Sprintf("%s host:%s serv:%d", famLookup[family], x.String(), ip6.Sin6_port)
		return name, nil

	case syscall.AF_NETLINK:
		var n sockaddr_nl

		nbuf := bytes.NewBuffer(bytestr)
		err = struc.Unpack(nbuf, &n)
		if err != nil {
			return fieldValue, errors.Wrap(err, errstring)
		}
		name = fmt.Sprintf("%s pid:%d", famLookup[family], n.Nl_pid)
		return name, nil

	case syscall.AF_PACKET:
		var l sockaddr_ll

		nbuf := bytes.NewBuffer(bytestr)
		err = struc.Unpack(nbuf, &l)
		if err != nil {
			return fieldValue, errors.Wrap(err, errstring)
		}
		// decide on kind of info to return
		// name = fmt.Sprintf("%s pid:%u", famLookup[family], l.)
		return famLookup[family], nil

	}
	return famLookup[family], nil
}

// not needed
func printFlags(fieldValue string) (string, error) {
	return fieldValue, nil
}

func printEscaped(fieldValue string) (string, error) {
	if strings.HasPrefix(fieldValue, `"`) {
		newStr := strings.Trim(fieldValue, `"`)
		return newStr, nil
	} else if strings.HasPrefix(fieldValue, "00") {
		newStr := unescape(fieldValue[2:])
		if newStr == "" {
			return fieldValue, nil
		}
	}
	newStr := unescape(fieldValue)
	if newStr == "" {
		return fieldValue, nil
	}

	return newStr, nil
}

func unescape(fieldvalue string) string {
	if strings.HasPrefix(fieldvalue, "(") {
		return fieldvalue
	}
	if len(fieldvalue) < 2 {
		return ""
	}
	var str []byte
	// try to chop 2 characters at a time and convert them from hexadecimal to decimal
	str, err := hex.DecodeString(fieldvalue)
	if err != nil {
		return fieldvalue
	}
	// for i := 0; i < len(fieldvalue)-1; i += 2 {
	// 	ival, err := strconv.ParseInt(fieldvalue[i:i+2], 16, -1)
	// 	if err != nil {
	// 		return str
	// 	}
	// 	str += fmt.Sprintf("%d", ival)
	// }
	return string(str)
}

func printPromiscuous(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "promiscuous parsing failed")
	}
	if ival == 0 {
		return "no", nil
	}
	return "yes", nil
}

func printCapabilities(fieldValue string, base int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, base, 64)
	if err != nil {
		return "", errors.Wrap(err, "capability parsing failed")
	}
	var capLookup = map[int]string{
		0:  "chown",
		1:  "dac_override",
		2:  "dac_read_search",
		3:  "fowner",
		4:  "fsetid",
		5:  "kill",
		6:  "setgid",
		7:  "setuid",
		8:  "setpcap",
		9:  "linux_immutable",
		10: "net_bind_service",
		11: "net_broadcast",
		12: "net_admin",
		13: "net_raw",
		14: "ipc_lock",
		15: "ipc_owner",
		16: "sys_module",
		17: "sys_rawio",
		18: "sys_chroot",
		19: "sys_ptrace",
		20: "sys_pacct",
		21: "sys_admin",
		22: "sys_boot",
		23: "sys_nice",
		24: "sys_resource",
		25: "sys_time",
		26: "sys_tty_config",
		27: "mknod",
		28: "lease",
		29: "audit_write",
		30: "audit_control",
		31: "setfcap",
		32: "mac_override",
		33: "mac_admin",
		34: "syslog",
		35: "wake_alarm",
		36: "block_suspend",
		37: "audit_read",
	}
	cap, ok := capLookup[int(ival)]
	if ok {
		return cap, nil
	}
	if base == 16 {
		return fmt.Sprintf("unknown capability(0x%d)", ival), nil
	}
	return fmt.Sprintf("unknown capability(%d)", ival), nil
}

func printSuccess(fieldValue string) (string, error) {

	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		// following as per auparse interpret
		return fieldValue, nil
	}
	const (
		sUnset  = -1
		sFailed = iota
		sSuccess
	)

	switch int(ival) {
	case sSuccess:
		return "yes", nil
	case sFailed:
		return "no", nil
	default:
		return "unset", nil
	}

}

func printA0(fieldValue string, sysNum string) (string, error) {
	//NOTE: considering only x64 machines
	// need to fetch syscall number on this as well ? design decision ?
	name, err := AuditSyscallToName(sysNum)
	if err != nil {
		return "", errors.Wrap(err, "syscall parsing failed")
	}
	if strings.HasPrefix(name, "r") {
		if name == "rt_sigaction" {
			return printSignals(fieldValue, 16)
		} else if name == "renameat" {
			return printDirFd(fieldValue)
		} else if name == "readlinkat" {
			return printDirFd(fieldValue)
		}
	} else if strings.HasPrefix(name, "c") {
		if name == "clone" {
			return printCloneFlags(fieldValue)
		} else if name == "clock_settime" {
			return printClockID(fieldValue)
		}
	} else if strings.HasPrefix(name, "p") {
		if name == "personality" {
			return printPersonality(fieldValue)
		} else if name == "ptrace" {
			return printPtrace(fieldValue)
		} else if name == "prctl" {
			return printPrctlOpt(fieldValue)
		}
	} else if strings.HasPrefix(name, "m") {
		if name == "mkdirat" {
			return printDirFd(fieldValue)
		} else if name == "mknodat" {
			return printDirFd(fieldValue)
		}
	} else if strings.HasPrefix(name, "f") {
		if name == "fchownat" {
			return printDirFd(fieldValue)
		} else if name == "futimesat" {
			return printDirFd(fieldValue)
		} else if name == "fchmodat" {
			return printDirFd(fieldValue)
		} else if name == "faccessat" {
			return printDirFd(fieldValue)
		} else if name == "ftimensat" {
			return printDirFd(fieldValue)
		}
	} else if strings.HasPrefix(name, "u") {
		if name == "unshare" {
			return printCloneFlags(fieldValue)
		} else if name == "unlinkat" {
			return printDirFd(fieldValue)
		} else if name == "utimesat" {
			return printDirFd(fieldValue)
		} else if name == "etrlimit" {
			return printRLimit(fieldValue)
		}
	} else if strings.HasPrefix(name, "s") {
		if name == "setuid" {
			return printUID(fieldValue)
		} else if name == "setreuid" {
			return printUID(fieldValue)
		} else if name == "setresuid" {
			return printUID(fieldValue)
		} else if name == "setfsuid" {
			return printUID(fieldValue)
		} else if name == "setgid" {
			return printGID(fieldValue)
		} else if name == "setregid" {
			return printGID(fieldValue)
		} else if name == "setresgid" {
			return printGID(fieldValue)
		} else if name == "socket" {
			return printSocketDomain(fieldValue)
		} else if name == "setfsgid" {
			return printGID(fieldValue)
		} else if name == "socketcall" {
			return printSocketCall(fieldValue, 16)
		}
	} else if name == "linkat" {
		return printDirFd(fieldValue)
	} else if name == "newfsstat" {
		return printDirFd(fieldValue)
	} else if name == "openat" {
		return printDirFd(fieldValue)
	} else if name == "ipccall" {
		return printIpcCall(fieldValue, 16)
	}

	return fmt.Sprintf("0x%s", fieldValue), nil
}

func printSignals(fieldValue string, base int) (string, error) {
	var sigMap = map[int]string{
		0:  "SIG0",
		1:  "SIGHUP",
		2:  "SIGINT",
		3:  "SIGQUIT",
		4:  "SIGILL",
		5:  "SIGTRAP",
		6:  "SIGABRT",
		7:  "SIGBUS",
		8:  "SIGFPE",
		9:  "SIGKILL",
		10: "SIGUSR1",
		11: "SIGSEGV",
		12: "SIGUSR2",
		13: "SIGPIPE",
		14: "SIGALRM",
		15: "SIGTERM",
		16: "SIGSTKFLT",
		17: "SIGCHLD",
		18: "SIGCONT",
		19: "SIGSTOP",
		20: "SIGTSTP",
		21: "SIGTTIN",
		22: "SIGTTOU",
		23: "SIGURG",
		24: "SIGXCPU",
		25: "SIGXFSZ",
		26: "SIGVTALRM",
		27: "SIGPROF",
		28: "SIGWINCH",
		29: "SIGIO",
		30: "IGPWR",
		31: "SIGSYS",
	}

	ival, err := strconv.ParseInt(fieldValue, base, 64)
	if err != nil {
		return "", errors.Wrap(err, "signal parsing failed")
	}
	if ival < 31 {
		return sigMap[int(ival)], nil
	}
	if base == 16 {
		return fmt.Sprintf("unknown signal (0x%s)", fieldValue), nil
	}
	return fmt.Sprintf("unknown signal (%s)", fieldValue), nil
}

func printDirFd(fieldValue string) (string, error) {
	if fieldValue == "-100" {
		return "AT_FDWD", nil
	}
	return fmt.Sprintf("0x%s", fieldValue), nil
}

func printCloneFlags(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "clone flags parsing failed")
	}

	var cloneLookUp = map[int]string{
		0x00000100: "CLONE_VM",
		0x00000200: "CLONE_FS",
		0x00000400: "CLONE_FILES",
		0x00000800: "CLONE_SIGHAND",
		0x00002000: "CLONE_PTRACE",
		0x00004000: "CLONE_VFORK",
		0x00008000: "CLONE_PARENT",
		0x00010000: "CLONE_THREAD",
		0x00020000: "CLONE_NEWNS",
		0x00040000: "CLONE_SYSVSEM",
		0x00080000: "CLONE_SETTLS",
		0x00100000: "CLONE_PARENT_SETTID",
		0x00200000: "CLONE_CHILD_CLEARTID",
		0x00400000: "CLONE_DETACHED",
		0x00800000: "CLONE_UNTRACED",
		0x01000000: "CLONE_CHILD_SETTID",
		0x02000000: "CLONE_STOPPED",
		0x04000000: "CLONE_NEWUTS",
		0x08000000: "CLONE_NEWIPC",
		0x10000000: "CLONE_NEWUSER",
		0x20000000: "CLONE_NEWPID",
		0x40000000: "CLONE_NEWNET",
		0x80000000: "CLONE_IO",
	}

	var name string
	for key, val := range cloneLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}
	var cloneSignal = ival & 0xFF
	var signalLookup = map[int]string{
		0:  "SIG0",
		1:  "SIGHUP",
		2:  "SIGINT",
		3:  "SIGQUIT",
		4:  "SIGILL",
		5:  "SIGTRAP",
		6:  "SIGABRT",
		7:  "SIGBUS",
		8:  "SIGFPE",
		9:  "SIGKILL",
		10: "SIGUSR1",
		11: "SIGSEGV",
		12: "SIGUSR2",
		13: "SIGPIPE",
		14: "SIGALRM",
		15: "SIGTERM",
		16: "SIGSTKFLT",
		17: "SIGCHLD",
		18: "SIGCONT",
		19: "SIGSTOP",
		20: "SIGTSTP",
		21: "SIGTTIN",
		22: "SIGTTOU",
		23: "SIGURG",
		24: "SIGXCPU",
		25: "SIGXFSZ",
		26: "SIGVTALRM",
		27: "SIGPROF",
		28: "SIGWINCH",
		29: "SIGIO",
		30: "IGPWR",
		31: "SIGSYS",
	}
	if cloneSignal > 0 && cloneSignal < 32 {
		if len(name) > 0 {
			name += "|"
		}
		name += signalLookup[int(cloneSignal)]
	}
	if len(name) == 0 {
		return fmt.Sprintf("0x%d", ival), nil
	}
	return name, nil
}

func printClockID(fieldValue string) (string, error) {
	var clockMap = map[int]string{
		0:  "CLOCK_REALTIME",
		1:  "CLOCK_MONOTONIC",
		2:  "CLOCK_PROCESS_CPUTIME_ID",
		3:  "CLOCK_THREAD_CPUTIME_ID",
		4:  "CLOCK_MONOTONIC_RAW",
		5:  "CLOCK_REALTIME_COARSE",
		6:  "CLOCK_MONOTONIC_COARSE",
		7:  "CLOCK_BOOTTIME",
		8:  "CLOCK_REALTIME_ALARM",
		9:  "CLOCK_BOOTTIME_ALARM",
		10: "CLOCK_SGI_CYCLE",
		11: "CLOCK_TAI",
	}
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "clock ID parsing failed")
	}
	if ival < 7 {
		return clockMap[int(ival)], nil
	}
	return fmt.Sprintf("unknown clk_id (0x%s)", fieldValue), nil
}

// skipping personality interpretation
// auparse specific table persontab.h
func printPersonality(fieldValue string) (string, error) {
	return fieldValue, nil
}

func printPtrace(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "ptrace parsing failed")
	}
	var ptraceLookup = map[int]string{
		0:      "PTRACE_TRACEME",
		1:      "PTRACE_PEEKTEXT",
		2:      "PTRACE_PEEKDATA",
		3:      "PTRACE_PEEKUSER",
		4:      "PTRACE_POKETEXT",
		5:      "PTRACE_POKEDATA",
		6:      "PTRACE_POKEUSER",
		7:      "PTRACE_CONT",
		8:      "PTRACE_KILL",
		9:      "PTRACE_SINGLESTEP",
		12:     "PTRACE_GETREGS",
		13:     "PTRACE_SETREGS",
		14:     "PTRACE_GETFPREGS",
		15:     "PTRACE_SETFPREGS",
		16:     "PTRACE_ATTACH",
		17:     "PTRACE_DETACH",
		18:     "PTRACE_GETFPXREGS",
		19:     "PTRACE_SETFPXREGS",
		24:     "PTRACE_SYSCALL",
		0x4200: "PTRACE_SETOPTIONS",
		0x4201: "PTRACE_GETEVENTMSG",
		0x4202: "PTRACE_GETSIGINFO",
		0x4203: "PTRACE_SETSIGINFO",
		0x4204: "PTRACE_GETREGSET",
		0x4205: "PTRACE_SETREGSET",
		0x4206: "PTRACE_SEIZE",
		0x4207: "PTRACE_INTERRUPT",
		0x4208: "PTRACE_LISTEN",
		0x4209: "PTRACE_PEEKSIGINFO",
		0x420a: "PTRACE_GETSIGMASK",
		0x420b: "PTRACE_SETSIGMASK",
	}
	if _, ok := ptraceLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown ptrace (0x%s)", fieldValue), nil
	}
	return ptraceLookup[int(ival)], nil
}

func printPrctlOpt(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "prctl parsing failed")
	}
	var prctlLookup = map[int]string{
		1:  "PR_SET_PDEATHSIG",
		2:  "PR_GET_PDEATHSIG",
		3:  "PR_GET_DUMPABLE",
		4:  "PR_SET_DUMPABLE",
		5:  "PR_GET_UNALIGN",
		6:  "PR_SET_UNALIGN",
		7:  "PR_GET_KEEPCAPS",
		8:  "PR_SET_KEEPCAPS",
		9:  "PR_GET_FPEMU",
		10: "PR_SET_FPEMU",
		11: "PR_GET_FPEXC",
		12: "PR_SET_FPEXC",
		13: "PR_GET_TIMING",
		14: "PR_SET_TIMING",
		15: "PR_SET_NAME",
		16: "PR_GET_NAME",
		19: "PR_GET_ENDIAN",
		20: "PR_SET_ENDIAN",
		21: "PR_GET_SECCOMP",
		22: "PR_SET_SECCOMP",
		23: "PR_CAPBSET_READ",
		24: "PR_CAPBSET_DROP",
		25: "PR_GET_TSC",
		26: "PR_SET_TSC",
		27: "PR_GET_SECUREBITS",
		28: "PR_SET_SECUREBITS",
		29: "PR_SET_TIMERSLACK",
		30: "PR_GET_TIMERSLACK",
		31: "PR_TASK_PERF_EVENTS_DISABLE",
		32: "PR_TASK_PERF_EVENTS_ENABLE",
		33: "PR_MCE_KILL",
		34: "PR_MCE_KILL_GET",
		35: "PR_SET_MM",
		36: "PR_SET_CHILD_SUBREAPER",
		37: "PR_GET_CHILD_SUBREAPER",
		38: "PR_SET_NO_NEW_PRIVS",
		39: "PR_GET_NO_NEW_PRIVS",
		40: "PR_GET_TID_ADDRESS",
		41: "PR_SET_THP_DISABLE",
		42: "PR_GET_THP_DISABLE",
		43: "PR_MPX_ENABLE_MANAGEMENT",
		44: "PR_MPX_DISABLE_MANAGEMENT",
		45: "PR_SET_FP_MODE",
		46: "PR_GET_FP_MODE",
	}
	if _, ok := prctlLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown prctl option (0x%s)", fieldValue), nil
	}
	return prctlLookup[int(ival)], nil
}

func printSocketDomain(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "socket domain parsing failed")
	}
	var famLookup = map[int]string{
		syscall.AF_LOCAL:      "local",
		syscall.AF_INET:       "inet",
		syscall.AF_AX25:       "ax25",
		syscall.AF_IPX:        "ipx",
		syscall.AF_APPLETALK:  "appletalk",
		syscall.AF_NETROM:     "netrom",
		syscall.AF_BRIDGE:     "bridge",
		syscall.AF_ATMPVC:     "atmpvc",
		syscall.AF_X25:        "x25",
		syscall.AF_INET6:      "inet6",
		syscall.AF_ROSE:       "rose",
		syscall.AF_DECnet:     "decnet",
		syscall.AF_NETBEUI:    "netbeui",
		syscall.AF_SECURITY:   "security",
		syscall.AF_KEY:        "key",
		syscall.AF_NETLINK:    "netlink",
		syscall.AF_PACKET:     "packet",
		syscall.AF_ASH:        "ash",
		syscall.AF_ECONET:     "econet",
		syscall.AF_ATMSVC:     "atmsvc",
		syscall.AF_RDS:        "rds",
		syscall.AF_SNA:        "sna",
		syscall.AF_IRDA:       "irda",
		syscall.AF_PPPOX:      "pppox",
		syscall.AF_WANPIPE:    "wanpipe",
		syscall.AF_LLC:        "llc",
		syscall.AF_CAN:        "can",
		syscall.AF_TIPC:       "tipc",
		syscall.AF_BLUETOOTH:  "bluetooth",
		syscall.AF_IUCV:       "iucv",
		syscall.AF_RXRPC:      "rxrpc",
		syscall.AF_ISDN:       "isdn",
		syscall.AF_PHONET:     "phonet",
		syscall.AF_IEEE802154: "ieee802154",
		37: "caif",
		38: "alg",
		39: "nfc",
		40: "vsock",
	}

	if _, ok := famLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown family (0x%s)", fieldValue), nil
	}
	return famLookup[int(ival)], nil

}

func printSocketCall(fieldValue string, base int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "socketcall parsing failed")
	}
	var sockLookup = map[int]string{
		syscall.SYS_SOCKET:      "socket",
		syscall.SYS_BIND:        "bind",
		syscall.SYS_CONNECT:     "connect",
		syscall.SYS_LISTEN:      "listen",
		syscall.SYS_ACCEPT:      "accept",
		syscall.SYS_GETSOCKNAME: "getsockname",
		syscall.SYS_GETPEERNAME: "getpeername",
		syscall.SYS_SOCKETPAIR:  "socketpair",
		9:                      "send",
		10:                     "recv",
		syscall.SYS_SENDTO:     "sendto",
		syscall.SYS_RECVFROM:   "recvfrom",
		syscall.SYS_SHUTDOWN:   "shutdown",
		syscall.SYS_SETSOCKOPT: "setsockopt",
		syscall.SYS_GETSOCKOPT: "getsockopt",
		syscall.SYS_SENDMSG:    "sendmsg",
		syscall.SYS_RECVMSG:    "recvmsg",
		syscall.SYS_ACCEPT4:    "accept4",
		19:                     "recvmmsg",
		20:                     "sendmmsg",
	}
	if _, ok := sockLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown socketcall (0x%s)", fieldValue), nil
	}
	return sockLookup[int(ival)], nil
}

func printRLimit(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "rlimit parsing failed")
	}
	var rlimitLookup = map[int]string{
		0:  "RLIMIT_CPU",
		1:  "RLIMIT_FSIZE",
		2:  "RLIMIT_DATA",
		3:  "RLIMIT_STACK",
		4:  "RLIMIT_CORE",
		5:  "RLIMIT_RSS",
		6:  "RLIMIT_NPROC",
		7:  "RLIMIT_NOFILE",
		8:  "RLIMIT_MEMLOCK",
		9:  "RLIMIT_AS",
		10: "RLIMIT_LOCKS",
		11: "RLIMIT_SIGPENDING",
		12: "RLIMIT_MSGQUEUE",
		13: "RLIMIT_NICE",
		14: "RLIMIT_RTPRIO",
		15: "RLIMIT_RTTIME",
	}
	if _, ok := rlimitLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown rlimit (0x%s)", fieldValue), nil
	}
	return rlimitLookup[int(ival)], nil
}

func printIpcCall(fieldValue string, base int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "ipccall parsing failed")
	}
	var ipccallLookup = map[int]string{
		syscall.SYS_SEMOP:  "semop",
		syscall.SYS_SEMGET: "semget",
		syscall.SYS_SEMCTL: "semctl",
		4:                  "semtimedop",
		syscall.SYS_MSGSND: "msgsnd",
		syscall.SYS_MSGRCV: "msgrcv",
		syscall.SYS_MSGGET: "msgget",
		syscall.SYS_MSGCTL: "msgctl",
		syscall.SYS_SHMAT:  "shmat",
		syscall.SYS_SHMDT:  "shmdt",
		syscall.SYS_SHMGET: "shmget",
		syscall.SYS_SHMCTL: "shmctl",
	}
	if _, ok := ipccallLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown ipccall (%s)", fieldValue), nil
	}
	return ipccallLookup[int(ival)], nil
}

func printA1(fieldValue, sysNum string, a0 int) (string, error) {
	//NOTE: considering only x64 machines
	// need to fetch syscall number on this as well ? design decision ?
	name, err := AuditSyscallToName(sysNum)
	if err != nil {
		return "", errors.Wrap(err, "syscall parsing failed")
	}
	if strings.HasPrefix(name, "f") {
		if name == "fchmod" {
			return printModeShort(fieldValue, 16)
		} else if name == "fcntl" {
			return printFcntlCmd(fieldValue)
		}
	}
	if strings.HasPrefix(name, "c") {
		if name == "chmod" {
			return printModeShort(fieldValue, 16)
		} else if k := strings.Index(name, "chown"); k != -1 {
			return printUID(fieldValue)
		} else if name == "creat" {
			return printModeShort(fieldValue, 16)
		}
	}
	if name[1:] == "etsocketopt" {
		return printSockOptLevel(fieldValue)
	} else if strings.HasPrefix(name, "s") {
		if name == "setreuid" {
			return printUID(fieldValue)
		} else if name == "setresuid" {
			return printUID(fieldValue)
		} else if name == "setregid" {
			return printGID(fieldValue)
		} else if name == "setresgid" {
			return printGID(fieldValue)
		} else if name == "socket" {
			return printSocketType(fieldValue)
		} else if name == "setns" {
			return printCloneFlags(fieldValue)
		} else if name == "sched_setscheduler" {
			return printSched(fieldValue)
		}
	} else if strings.HasPrefix(name, "m") {
		if name == "mkdir" {
			return printModeShort(fieldValue, 16)
		} else if name == "mknod" {
			return printMode(fieldValue, 16)
		} else if name == "mq_open" {
			return printOpenFlags(fieldValue)
		}
	} else if name == "open" {
		return printOpenFlags(fieldValue)
	} else if name == "access" {
		return printAccess(fieldValue)
	} else if name == "epoll_ctl" {
		return printEpollCtl(fieldValue)
	} else if name == "kill" {
		return printSignals(fieldValue, 16)
	} else if name == "prctl" {
		if a0 == syscall.PR_CAPBSET_READ || a0 == syscall.PR_CAPBSET_DROP {
			return printCapabilities(fieldValue, 16)
		} else if a0 == syscall.PR_SET_PDEATHSIG {
			return printSignals(fieldValue, 16)
		}
	} else if name == "tkill" {
		return printSignals(fieldValue, 16)
	} else if name == "umount2" {
		return printUmount(fieldValue)
	} else if name == "ioctl" {
		return printIoctlReq(fieldValue)
	}
	return fmt.Sprintf("0x%s", fieldValue), nil
}

func printFcntlCmd(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "fcntl command parsing failed")
	}
	var fcntlLookup = map[int]string{
		0:    "F_DUPFD",
		1:    "F_GETFD",
		2:    "F_SETFD",
		3:    "F_GETFL",
		4:    "F_SETFL",
		5:    "F_GETLK",
		6:    "F_SETLK",
		7:    "F_SETLKW",
		8:    "F_SETOWN",
		9:    "F_GETOWN",
		10:   "F_SETSIG",
		11:   "F_GETSIG",
		12:   "F_GETLK64",
		13:   "F_SETLK64",
		14:   "F_SETLKW64",
		15:   "F_SETOWN_EX",
		16:   "F_GETOWN_EX",
		17:   "F_GETOWNER_UIDS",
		1024: "F_SETLEASE",
		1025: "F_GETLEASE",
		1026: "F_NOTIFY",
		1029: "F_CANCELLK",
		1030: "F_DUPFD_CLOEXEC",
		1031: "F_SETPIPE_SZ",
		1032: "F_GETPIPE_SZ",
		1033: "F_ADD_SEALS",
		1034: "F_GET_SEALS",
	}
	if _, ok := fcntlLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown fcntl command(%d)", ival), nil
	}
	return fcntlLookup[int(ival)], nil
}

func printSocketType(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "socket type parsing failed")
	}
	var socketLookup = map[int]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}
	if _, ok := socketLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown socket type(%d)", ival), nil
	}
	return socketLookup[int(ival)], nil
}

func printSched(fieldValue string) (string, error) {
	const schedResetOnFork int64 = 0x40000000
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "sched parsing failed")
	}
	var schedLookup = map[int]string{
		0: "SCHED_OTHER",
		1: "SCHED_FIFO",
		2: "SCHED_RR",
		3: "SCHED_BATCH",
		5: "SCHED_IDLE",
		6: "SCHED_DEADLINE",
	}
	if _, ok := schedLookup[int(ival)&0x0F]; !ok {
		return fmt.Sprintf("unknown scheduler policy (0x%s)", fieldValue), nil
	}
	if ival&schedResetOnFork > 0 {
		return schedLookup[int(ival)] + "|SCHED_RESET_ON_FORK", nil
	}
	return schedLookup[int(ival)], nil
}

// not currently used (so skipped for now)
// useful for debugging rather than forensics
// actual policy is to filter either on open or write or both
// and emit msg that this happened so if its opened in r,rw, etc.
// all endup looking the same i.e READ or WRITE
// auparse specific table is open-flagtab.h
func printOpenFlags(fieldValue string) (string, error) {
	// look at table of values from /usr/include/asm-generic/fcntl.h
	return fieldValue, nil
}

// policy is to only log success or denial but not read the actual value
// ie make a rule on the arguments but dont read it and just trust that right rule is reported
// auparse specific table is accesstab.h
func printAccess(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "access parsing failed")
	}
	if ival&0x0F == 0 {
		return "F_OK", nil
	}
	var accessLookUp = map[int]string{
		1: "X_OK",
		2: "W_OK",
		4: "R_OK",
	}
	var name string
	for key, val := range accessLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return name, nil
}

func printEpollCtl(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "epoll parsing failed")
	}
	var epollLookup = map[int]string{
		1: "EPOLL_CTL_ADD",
		2: "EPOLL_CTL_DEL",
		3: "EPOLL_CTL_MOD",
	}
	if _, ok := epollLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown epoll_ctl operation (%d)", ival), nil
	}
	return epollLookup[int(ival)], nil
}

// not used currently
// auparse specific table is umounttab.h
func printUmount(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "umount parsing failed")
	}
	var umountLookUp = map[int]string{
		0x00000001: "MNT_FORCE",
		0x00000002: "MNT_DETACH",
		0x00000004: "MNT_EXPIRE",
		0x00000008: "UMOUNT_NOFOLLOW",
		0x80000001: "UMOUNT_UNUSED",
	}
	var name string
	for key, val := range umountLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return name, nil
}

func printIoctlReq(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "ioctl req parsing failed")
	}
	var ioctlLookup = map[int]string{
		0x4B3A:     "KDSETMODE",
		0x4B3B:     "KDGETMODE",
		0x5309:     "CDROMEJECT",
		0x530F:     "CDROMEJECT_SW",
		0x5311:     "CDROM_GET_UPC",
		0x5316:     "CDROMSEEK",
		0x5401:     "TCGETS",
		0x5402:     "TCSETS",
		0x5403:     "TCSETSW",
		0x5404:     "TCSETSF",
		0x5409:     "TCSBRK",
		0x540B:     "TCFLSH",
		0x540E:     "TIOCSCTTY",
		0x540F:     "TIOCGPGRP",
		0x5410:     "TIOCSPGRP",
		0x5413:     "TIOCGWINSZ",
		0x5414:     "TIOCSWINSZ",
		0x541B:     "TIOCINQ",
		0x5421:     "FIONBIO",
		0x8901:     "FIOSETOWN",
		0x8903:     "FIOGETOWN",
		0x8910:     "SIOCGIFNAME",
		0x8927:     "SIOCGIFHWADDR",
		0x8933:     "SIOCGIFINDEX",
		0x89a2:     "SIOCBRADDIF",
		0x40045431: "TIOCSPTLCK",
		0x80045430: "TIOCGPTN",
		0x80045431: "TIOCSPTLCK",
		0xC01C64A3: "DRM_IOCTL_MODE_CURSOR",
		0xC01864B0: "DRM_IOCTL_MODE_PAGE_FLIP",
		0xC01864B1: "DRM_IOCTL_MODE_DIRTYFB"}

	if _, ok := ioctlLookup[int(ival)]; !ok {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return ioctlLookup[int(ival)], nil
}

// discuss priority + def designs ?
func printSockOptLevel(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "sock opt parsing failed")
	}
	if ival == syscall.SOL_SOCKET {
		return "SOL_SOCKET", nil
	}
	var sockOptLookup = map[int]string{
		0:   "SOL_IP",
		6:   "SOL_TCP",
		17:  "SOL_UDP",
		41:  "SOL_IPV6",
		58:  "SOL_ICMPV6",
		132: "SOL_SCTP",
		136: "SOL_UDPLITE",
		255: "SOL_RAW",
		256: "SOL_IPX",
		257: "SOL_AX25",
		258: "SOL_ATALK",
		259: "SOL_NETROM",
		260: "SOL_ROSE",
		261: "SOL_DECNET",
		263: "SOL_PACKET",
		264: "SOL_ATM",
		265: "SOL_AAL",
		266: "SOL_IRDA",
		267: "SOL_NETBEUI",
		268: "SOL_LLC",
		269: "SOL_DCCP",
		270: "SOL_NETLINK",
		271: "SOL_TIPC",
		272: "SOL_RXRPC",
		273: "SOL_PPPOL2TP",
		274: "SOL_BLUETOOTH",
		275: "SOL_PNPIPE",
		276: "SOL_RDS",
		277: "SOL_IUCV",
		278: "SOL_CAIF",
		279: "SOL_ALG",
		280: "SOL_NFC",
	}
	// pure go implementation of getprotobynumber
	// if not find by getprotobynumber use map
	if _, ok := sockOptLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown sockopt level (0x%s)", fieldValue), nil
	}
	return sockOptLookup[int(ival)], nil
}

// pure go implementation of getprotobynumber
func printSocketProto(fieldValue string) (string, error) {
	// ival, err := strconv.ParseInt(fieldValue, 16, 64)
	// if err != nil {
	// 	return "", errors.Wrap(err, "sock proto parsing failed")
	// }
	//protocol = getprotobynumber(ival)
	// if not found
	// return fmt.Sprintf("unknown proto(%s)", fieldValue), nil
	return fieldValue, nil
}

func printA2(fieldValue, sysNum string, a1 int) (string, error) {
	//NOTE: considering only x64 machines
	// need to fetch syscall number on this as well ? design decision ?
	name, err := AuditSyscallToName(sysNum)
	if err != nil {
		return "", errors.Wrap(err, "syscall parsing failed")
	}
	if name == "fcntl" {
		ival, err := strconv.ParseInt(fieldValue, 16, 64)
		if err != nil {
			return "", errors.Wrap(err, "fcntl parsing failed")
		}
		switch a1 {
		case syscall.F_SETOWN:
			return printUID(fieldValue)
		case syscall.F_SETFD:
			if ival == syscall.FD_CLOEXEC {
				return "FD_CLOSEXEC", nil
			}
		case syscall.F_SETFL:
		case syscall.F_SETLEASE:
		case syscall.F_GETLEASE:
		case syscall.F_NOTIFY:
		}
	} else if name[1:] == "esockopt" {
		if a1 == syscall.IPPROTO_IP {
			return printIPOptName(fieldValue)
		} else if a1 == syscall.SOL_SOCKET {
			return printSockOptName(fieldValue) // add machine ?
		} else if a1 == syscall.IPPROTO_UDP {
			return printUDPOptName(fieldValue)
		} else if a1 == syscall.IPPROTO_IPV6 {
			return printIP6OptName(fieldValue)
		} else if a1 == syscall.SOL_PACKET {
			return printPktOptName(fieldValue)
		}
		return fmt.Sprintf("0x%s", fieldValue), nil
	} else if strings.HasPrefix(name, "o") {
		if name == "openat" {
			return printOpenFlags(fieldValue)
		}
		if name == "open" && (a1&syscall.O_CREAT > 0) {
			return printModeShort(fieldValue, 16)
		}
	} else if strings.HasPrefix(name, "f") {
		if name == "fchmodat" {
			return printModeShort(fieldValue, 16)
		} else if name == "faccessat" {
			return printAccess(fieldValue)
		}
	} else if strings.HasPrefix(name, "s") {
		if name == "setresuid" {
			return printUID(fieldValue)
		} else if name == "setresgid" {
			return printGID(fieldValue)
		} else if name == "socket" {
			return printSocketProto(fieldValue)
		} else if name == "sendmsg" {
			return printRecv(fieldValue)
		} else if name == "shmget" {
			return printSHMFlags(fieldValue)
		}
	} else if strings.HasPrefix(name, "m") {
		if name == "mmap" {
			return printProt(fieldValue, 1)
		} else if name == "mkdirat" {
			return printModeShort(fieldValue, 16)
		} else if name == "mknodat" {
			return printModeShort(fieldValue, 16)
		} else if name == "mprotect" {
			return printProt(fieldValue, 0)
		} else if name == "mqopen" && a1&syscall.O_CREAT > 0 {
			return printModeShort(fieldValue, 16)
		}
	} else if strings.HasPrefix(name, "r") {
		if name == "recvmsg" {
			return printRecv(fieldValue)
		} else if name == "readlinkat" {
			return printDirFd(fieldValue)
		}
	} else if strings.HasPrefix(name, "l") {
		if name == "linkat" {
			return printDirFd(fieldValue)
		} else if name == "lseek" {
			return printSeek(fieldValue)
		}
	} else if name == "chown" {
		return printGID(fieldValue)
	} else if name == "tgkill" {
		return printSignals(fieldValue, 16)
	}
	return fmt.Sprintf("0x%s", fieldValue), nil
}

func printIPOptName(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "ip opt parsing failed")
	}
	var ipOptLookup = map[int]string{
		1:  "IP_TOS",
		2:  "IP_TTL",
		3:  "IP_HDRINCL",
		4:  "IP_OPTIONS",
		5:  "IP_ROUTER_ALERT",
		6:  "IP_RECVOPTS",
		7:  "IP_RETOPTS",
		8:  "IP_PKTINFO",
		9:  "IP_PKTOPTIONS",
		10: "IP_MTU_DISCOVER",
		11: "IP_RECVERR",
		12: "IP_RECVTTL",
		14: "IP_MTU",
		15: "IP_FREEBIND",
		16: "IP_IPSEC_POLICY",
		17: "IP_XFRM_POLICY",
		18: "IP_PASSSEC",
		19: "IP_TRANSPARENT",
		20: "IP_ORIGDSTADDR",
		21: "IP_MINTTL",
		22: "IP_NODEFRAG",
		23: "IP_CHECKSUM",
		32: "IP_MULTICAST_IF",
		33: "IP_MULTICAST_TTL",
		34: "IP_MULTICAST_LOOP",
		35: "IP_ADD_MEMBERSHIP",
		36: "IP_DROP_MEMBERSHIP",
		37: "IP_UNBLOCK_SOURCE",
		38: "IP_BLOCK_SOURCE",
		39: "IP_ADD_SOURCE_MEMBERSHIP",
		40: "IP_DROP_SOURCE_MEMBERSHIP",
		41: "IP_MSFILTER",
		42: "MCAST_JOIN_GROUP",
		43: "MCAST_BLOCK_SOURCE",
		44: "MCAST_UNBLOCK_SOURCE",
		45: "MCAST_LEAVE_GROUP",
		46: "MCAST_JOIN_SOURCE_GROUP",
		47: "MCAST_LEAVE_SOURCE_GROUP",
		48: "MCAST_MSFILTER",
		49: "IP_MULTICAST_ALL",
		50: "IP_UNICAST_IF",
		64: "IPT_SO_SET_REPLACE",
		65: "IPT_SO_SET_ADD_COUNTERS",
		66: "IPT_SO_GET_REVISION_TARGET",
	}
	if _, ok := ipOptLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown ipopt name (0x%s)", fieldValue), nil
	}
	return ipOptLookup[int(ival)], nil
}

func printIP6OptName(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "ip6 opt parsing failed")
	}
	var ip6OptLookup = map[int]string{
		1:  "IPV6_ADDRFORM",
		2:  "IPV6_2292PKTINFO",
		3:  "IPV6_2292HOPOPTS",
		4:  "IPV6_2292DSTOPTS",
		5:  "IPV6_2292RTHDR",
		6:  "IPV6_2292PKTOPTIONS",
		7:  "IPV6_CHECKSUM",
		8:  "IPV6_2292HOPLIMIT",
		9:  "IPV6_NEXTHOP",
		10: "IPV6_AUTHHDR",
		11: "IPV6_FLOWINFO",
		16: "IPV6_UNICAST_HOPS",
		17: "IPV6_MULTICAST_IF",
		18: "IPV6_MULTICAST_HOPS",
		19: "IPV6_MULTICAST_LOOP",
		20: "IPV6_ADD_MEMBERSHIP",
		21: "IPV6_DROP_MEMBERSHIP",
		22: "IPV6_ROUTER_ALERT",
		23: "IPV6_MTU_DISCOVER",
		24: "IPV6_MTU",
		25: "IPV6_RECVERR",
		26: "IPV6_V6ONLY",
		27: "IPV6_JOIN_ANYCAST",
		28: "IPV6_LEAVE_ANYCAST",
		32: "IPV6_FLOWLABEL_MGR",
		33: "IPV6_FLOWINFO_SEND",
		34: "IPV6_IPSEC_POLICY",
		35: "IPV6_XFRM_POLICY",
		42: "MCAST_JOIN_GROUP",
		43: "MCAST_BLOCK_SOURCE",
		44: "MCAST_UNBLOCK_SOURCE",
		45: "MCAST_LEAVE_GROUP",
		46: "MCAST_JOIN_SOURCE_GROUP",
		47: "MCAST_LEAVE_SOURCE_GROUP",
		48: "MCAST_MSFILTER",
		49: "IPV6_RECVPKTINFO",
		50: "IPV6_PKTINFO",
		51: "IPV6_RECVHOPLIMIT",
		52: "IPV6_HOPLIMIT",
		53: "IPV6_RECVHOPOPTS",
		54: "IPV6_HOPOPTS",
		55: "IPV6_RTHDRDSTOPTS",
		56: "IPV6_RECVRTHDR",
		57: "IPV6_RTHDR",
		58: "IPV6_RECVDSTOPTS",
		59: "IPV6_DSTOPTS",
		60: "IPV6_RECVPATHMTU",
		61: "IPV6_PATHMTU",
		62: "IPV6_DONTFRAG",
		63: "IPV6_USE_MIN_MTU",
		64: "IP6T_SO_SET_REPLACE",
		65: "IP6T_SO_SET_ADD_COUNTERS",
		66: "IPV6_RECVTCLASS",
		67: "IPV6_TCLASS",
		68: "IP6T_SO_GET_REVISION_MATCH",
		69: "IP6T_SO_GET_REVISION_TARGET",
		72: "IPV6_ADDR_PREFERENCES",
		73: "IPV6_MINHOPCOUNT",
		74: "IPV6_ORIGDSTADDR",
		75: "IPV6_TRANSPARENT",
		76: "IPV6_UNICAST_IF",
		80: "IP6T_SO_ORIGINAL_DST",
	}
	if _, ok := ip6OptLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown ip6opt name (0x%s)", fieldValue), nil
	}
	return ip6OptLookup[int(ival)], nil
}

func printTCPOptName(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "tcp opt parsing failed")
	}
	var tcpOptLookup = map[int]string{
		1:  "TCP_NODELAY",
		2:  "TCP_MAXSEG",
		3:  "TCP_CORK",
		4:  "TCP_KEEPIDLE",
		5:  "TCP_KEEPINTVL",
		6:  "TCP_KEEPCNT",
		7:  "TCP_SYNCNT",
		8:  "TCP_LINGER2",
		9:  "TCP_DEFER_ACCEPT",
		10: "TCP_WINDOW_CLAMP",
		11: "TCP_INFO",
		12: "TCP_QUICKACK",
		13: "TCP_CONGESTION",
		14: "TCP_MD5SIG",
		15: "TCP_COOKIE_TRANSACTIONS",
		16: "TCP_THIN_LINEAR_TIMEOUTS",
		17: "TCP_THIN_DUPACK",
		18: "TCP_USER_TIMEOUT",
		19: "TCP_REPAIR",
		20: "TCP_REPAIR_QUEUE",
		21: "TCP_QUEUE_SEQ",
		22: "TCP_REPAIR_OPTIONS",
		23: "TCP_FASTOPEN",
		24: "TCP_TIMESTAMP",
		25: "TCP_NOTSENT_LOWAT",
	}
	if _, ok := tcpOptLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown tcpopt name (0x%s)", fieldValue), nil
	}
	return tcpOptLookup[int(ival)], nil
}

func printUDPOptName(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "udp opt parsing failed")
	}
	if ival == 1 {
		return "UDP_CORK", nil
	} else if ival == 100 {
		return "UDP_ENCAP", nil
	}

	return fmt.Sprintf("unknown udpopt name (0x%s)", fieldValue), nil
}

func printPktOptName(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "pkt opt parsing failed")
	}
	var pktOptLookup = map[int]string{
		1:  "PACKET_ADD_MEMBERSHIP",
		2:  "PACKET_DROP_MEMBERSHIP",
		3:  "PACKET_RECV_OUTPUT",
		5:  "PACKET_RX_RING",
		6:  "PACKET_STATISTICS",
		7:  "PACKET_COPY_THRESH",
		8:  "PACKET_AUXDATA",
		9:  "PACKET_ORIGDEV",
		10: "PACKET_VERSION",
		11: "PACKET_HDRLEN",
		12: "PACKET_RESERVE",
		13: "PACKET_TX_RING",
		14: "PACKET_LOSS",
		15: "PACKET_VNET_HDR",
		16: "PACKET_TX_TIMESTAMP",
		17: "PACKET_TIMESTAMP",
		18: "PACKET_FANOUT",
		19: "PACKET_TX_HAS_OFF",
		20: "PACKET_QDISC_BYPASS",
	}
	if _, ok := pktOptLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown pktopt name (0x%s)", fieldValue), nil
	}
	return pktOptLookup[int(ival)], nil
}

// tables (question, ) what are the actual values from table ( are they in binary?)
func printSHMFlags(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "shm parsing failed")
	}
	var ipccmdLookUp = map[int]string{
		00001000: "IPC_CREAT",
		00002000: "IPC_EXCL",
		00004000: "IPC_NOWAIT",
	}
	var name string
	var partial = ival & 00003000
	for key, val := range ipccmdLookUp {
		if key&int(partial) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}
	partial = ival & 00014000
	var shmLookUp = map[int]string{
		00001000: "SHM_DEST",
		00002000: "SHM_LOCKED",
		00004000: "SHM_HUGETLB",
		00010000: "SHM_NORESERVE",
	}
	for key, val := range shmLookUp {
		if key&int(partial) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}
	partial = ival & 000777
	tmode, err := printModeShortInt(partial)
	if err != nil {
		return "", errors.Wrap(err, "shm parsing failed")
	}
	if len(name) > 0 {
		name += "|"
	}
	name += tmode

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}

	return name, nil
}

func printProt(fieldValue string, isMmap int) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "prot parsing failed")
	}
	if ival&0x07 == 0 {
		return "PROT_NONE", nil
	}
	var protLookUp = map[int]string{
		1: "PROT_READ",
		2: "PROT_WRITE",
		4: "PROT_EXEC",
		8: "PROT_SEM",
	}

	var name string
	for key, val := range protLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			// skip last key if isMmap == 0
			if isMmap == 0 && val == "PROT_SEM" {
				continue
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}

	return name, nil
}

func printSockOptName(fieldValue string) (string, error) {
	// Note: Considering only x64 machines
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "sock optname parsing failed")
	}
	/*
		// PPC machine arch
			if ((machine == MACH_PPC64 || machine == MACH_PPC) &&
					opt >= 16 && opt <= 21)
				opt+=100;
	*/
	var sockOptNameLookup = map[int]string{
		1:  "SO_DEBUG",
		2:  "SO_REUSEADDR",
		3:  "SO_TYPE",
		4:  "SO_ERROR",
		5:  "SO_DONTROUTE",
		6:  "SO_BROADCAST",
		7:  "SO_SNDBUF",
		8:  "SO_RCVBUF",
		9:  "SO_KEEPALIVE",
		10: "SO_OOBINLINE",
		11: "SO_NO_CHECK",
		12: "SO_PRIORITY",
		13: "SO_LINGER",
		14: "SO_BSDCOMPAT",
		15: "SO_REUSEPORT",
		16: "SO_PASSCRED",
		17: "SO_PEERCRED",
		18: "SO_RCVLOWAT",
		19: "SO_SNDLOWAT",
		20: "SO_RCVTIMEO",
		21: "SO_SNDTIMEO",
		22: "SO_SECURITY_AUTHENTICATION",
		23: "SO_SECURITY_ENCRYPTION_TRANSPORT",
		24: "SO_SECURITY_ENCRYPTION_NETWORK",
		25: "SO_BINDTODEVICE",
		26: "SO_ATTACH_FILTER",
		27: "SO_DETACH_FILTER",
		28: "SO_PEERNAME",
		29: "SO_TIMESTAMP",
		30: "SO_ACCEPTCONN",
		31: "SO_PEERSEC",
		32: "SO_SNDBUFFORCE",
		33: "SO_RCVBUFFORCE",
		34: "SO_PASSSEC",
		35: "SO_TIMESTAMPNS",
		36: "SO_MARK",
		37: "SO_TIMESTAMPING",
		38: "SO_PROTOCOL",
		39: "SO_DOMAIN",
		40: "SO_RXQ_OVFL",
		41: "SO_WIFI_STATUS",
		42: "SO_PEEK_OFF",
		43: "SO_NOFCS",
		44: "SO_LOCK_FILTER",
		45: "SO_SELECT_ERR_QUEUE",
		46: "SO_BUSY_POLL",
		47: "SO_MAX_PACING_RATE",
		48: "SO_BPF_EXTENSIONS",
		49: "SO_INCOMING_CPU",
		50: "SO_ATTACH_BPF",

		// PPC has these different
		116: "SO_RCVLOWAT",
		117: "SO_SNDLOWAT",
		118: "SO_RCVTIMEO",
		119: "SO_SNDTIMEO",
		120: "SO_PASSCRED",
		121: "SO_PEERCRED",
	}
	if _, ok := sockOptNameLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown sockopt name (0x%s)", fieldValue), nil
	}
	return sockOptNameLookup[int(ival)], nil
}

func printRecv(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "recv parsing failed")
	}
	var recvLookUp = map[int]string{
		0x00000001: "MSG_OOB",
		0x00000002: "MSG_PEEK",
		0x00000004: "MSG_DONTROUTE",
		0x00000008: "MSG_CTRUNC",
		0x00000010: "MSG_PROXY",
		0x00000020: "MSG_TRUNC",
		0x00000040: "MSG_DONTWAIT",
		0x00000080: "MSG_EOR",
		0x00000100: "MSG_WAITALL",
		0x00000200: "MSG_FIN",
		0x00000400: "MSG_SYN",
		0x00000800: "MSG_CONFIRM",
		0x00001000: "MSG_RST",
		0x00002000: "MSG_ERRQUEUE",
		0x00004000: "MSG_NOSIGNAL",
		0x00008000: "MSG_MORE",
		0x00010000: "MSG_WAITFORONE",
		0x00020000: "MSG_SENDPAGE_NOTLAST",
		0x20000000: "MSG_FASTOPEN",
		0x40000000: "MSG_CMSG_CLOEXEC",
		0x80000000: "MSG_CMSG_COMPAT",
	}
	var name string
	for key, val := range recvLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return name, nil
}

func printSeek(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "seek parsing failed")
	}
	var whence = int(ival) & 0xFF
	var seekLookup = map[int]string{
		0: "SEEK_SET",
		1: "SEEK_CUR",
		2: "SEEK_END",
		3: "SEEK_DATA",
		4: "SEEK_HOLE",
	}
	if _, ok := seekLookup[whence]; !ok {
		return fmt.Sprintf("unknown whence(0x%s)", fieldValue), nil
	}
	return seekLookup[whence], nil
}

func printA3(fieldValue, sysNum string) (string, error) {
	//NOTE: considering only x64 machines
	// need to fetch syscall number on this as well ? design decision ?
	name, err := AuditSyscallToName(sysNum)
	if err != nil {
		return "", errors.Wrap(err, "syscall parsing failed")
	}
	if strings.HasPrefix(name, "m") {
		if name == "mmap" {
			return printMmap(fieldValue)
		} else if name == "mount" {
			return printMount(fieldValue)
		}
	} else if strings.HasPrefix(name, "r") {
		if name == "recv" {
			return printRecv(fieldValue)
		} else if name == "recvfrom" {
			return printRecv(fieldValue)
		} else if name == "recvmsg" {
			return printRecv(fieldValue)
		}
	} else if strings.HasPrefix(name, "s") {
		if name == "send" {
			return printRecv(fieldValue)
		} else if name == "sendto" {
			return printRecv(fieldValue)
		} else if name == "sendmmsg" {
			return printRecv(fieldValue)
		}
	}
	return fmt.Sprintf("0x%s", fieldValue), nil
}

func printMmap(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "mmap parsing failed")
	}
	var mmapLookUp = map[int]string{
		0x00001: "MAP_SHARED",
		0x00002: "MAP_PRIVATE",
		0x00010: "MAP_FIXED",
		0x00020: "MAP_ANONYMOUS",
		0x00040: "MAP_32BIT",
		0x00100: "MAP_GROWSDOWN",
		0x00800: "MAP_DENYWRITE",
		0x01000: "MAP_EXECUTABLE",
		0x02000: "MAP_LOCKED",
		0x04000: "MAP_NORESERVE",
		0x08000: "MAP_POPULATE",
		0x10000: "MAP_NONBLOCK",
		0x20000: "MAP_STACK",
		0x40000: "MAP_HUGETLB",
	}
	var name string
	if ival&0x0F == 0 {
		name += "MAP_FILE"
	}
	for key, val := range mmapLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return name, nil
}

func printMount(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "mount parsing failed")
	}
	var mountLookUp = map[int]string{
		syscall.MS_RDONLY:      "MS_RDONLY",
		syscall.MS_NOSUID:      "MS_NOSUID",
		syscall.MS_NODEV:       "MS_NODEV",
		syscall.MS_NOEXEC:      "MS_NOEXEC",
		syscall.MS_SYNCHRONOUS: "MS_SYNCHRONOUS",
		syscall.MS_REMOUNT:     "MS_REMOUNT",
		syscall.MS_MANDLOCK:    "MS_MANDLOCK",
		syscall.MS_DIRSYNC:     "MS_DIRSYNC",
		syscall.MS_NOATIME:     "MS_NOATIME",
		syscall.MS_NODIRATIME:  "MS_NODIRATIME",
		syscall.MS_BIND:        "MS_BIND",
		syscall.MS_MOVE:        "MS_MOVE",
		syscall.MS_REC:         "MS_REC",
		syscall.MS_SILENT:      "MS_SILENT",
		syscall.MS_POSIXACL:    "MS_POSIXACL",
		syscall.MS_UNBINDABLE:  "MS_UNBINDABLE",
		syscall.MS_PRIVATE:     "MS_PRIVATE",
		syscall.MS_SLAVE:       "MS_SLAVE",
		syscall.MS_SHARED:      "MS_SHARED",
		syscall.MS_RELATIME:    "MS_RELATIME",
		syscall.MS_KERNMOUNT:   "MS_KERNMOUNT",
		syscall.MS_I_VERSION:   "MS_I_VERSION",
		1 << 24:                "MS_STRICTATIME",
		1 << 27:                "MS_SNAP_STABLE",
		1 << 28:                "MS_NOSEC",
		1 << 29:                "MS_BORN",
		syscall.MS_ACTIVE:      "MS_ACTIVE",
		syscall.MS_NOUSER:      "MS_NOUSER",
	}
	var name string
	for key, val := range mountLookUp {
		if key&int(ival) > 0 {
			if len(name) > 0 {
				name += "|"
			}
			name += val
		}
	}

	if len(name) == 0 {
		return fmt.Sprintf("0x%s", fieldValue), nil
	}
	return name, nil
}

func printSession(fieldValue string) (string, error) {
	if fieldValue == "4294967295" {
		return "unset", nil
	}
	return fieldValue, nil
}

func printNFProto(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "netfilter protocol parsing failed")
	}
	var nfProtoLookup = map[int]string{
		0:  "unspecified",
		1:  "inet",
		2:  "ipv4",
		3:  "arp",
		7:  "bridge",
		10: "ipv6",
		12: "decnet",
	}
	if _, ok := nfProtoLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown netfilter protocol (%s)", fieldValue), nil
	}
	return nfProtoLookup[int(ival)], nil
}

func printICMP(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "icmp type parsing failed")
	}
	var icmpLookup = map[int]string{
		0:  "echo-reply",
		3:  "destination-unreachable",
		4:  "source-quench",
		5:  "redirect",
		8:  "echo",
		11: "time-exceeded",
		12: "parameter-problem",
		13: "timestamp-request",
		14: "timestamp-reply",
		15: "info-request",
		16: "info-reply",
		17: "address-mask-request",
		18: "address-mask-reply",
	}
	if _, ok := icmpLookup[int(ival)]; !ok {
		return fmt.Sprintf("unknown icmp type (%s)", fieldValue), nil
	}
	return icmpLookup[int(ival)], nil
}

func printAddr(fieldValue string) (string, error) {
	return fieldValue, nil
}

func printSeccompCode(fieldValue string) (string, error) {
	if strings.HasPrefix(fieldValue, "0x") {
		fieldValue = fieldValue[2:]
	}
	ival, err := strconv.ParseInt(fieldValue, 16, 64)
	if err != nil {
		return "", errors.Wrap(err, "seccomp code parsing failed")
	}
	var SECCOMPRETACTION = 0x7fff0000
	var seccompCodeLookUp = map[int]string{
		0x00000000: "kill",
		0x00030000: "trap",
		0x00050000: "errno",
		0x7ff00000: "trace",
		0x7fff0000: "allow",
	}
	if _, ok := seccompCodeLookUp[int(ival)&SECCOMPRETACTION]; !ok {
		return fmt.Sprintf("unknown seccomp code (%s)", fieldValue), nil
	}
	return seccompCodeLookUp[int(ival)&SECCOMPRETACTION], nil
}

func printList(fieldValue string) (string, error) {
	ival, err := strconv.ParseInt(fieldValue, 10, 64)
	if err != nil {
		return "", errors.Wrap(err, "list parsing failed")
	}
	var listLookUp = map[int]string{
		AUDIT_FILTER_TASK:    "task",
		AUDIT_FILTER_ENTRY:   "entry",
		AUDIT_FILTER_EXIT:    "exit",
		AUDIT_FILTER_USER:    "user",
		AUDIT_FILTER_EXCLUDE: "exclude",
	}
	if _, ok := listLookUp[int(ival)]; !ok {
		return fmt.Sprintf("unknown list (%s)", fieldValue), nil
	}
	return listLookUp[int(ival)], nil
}
