package libaudit

import "testing"

var jsonRules = `
{
    "file_rules": [
        {
            "path": "/etc/libaudit.conf",
            "key": "audit",
            "permission": "wa"
        },
        {
            "path": "/etc/rsyslog.conf",
            "key": "syslog",
            "permission": "wa"
        }
    ],
    "syscall_rules": [
        {
            "key": "bypass",
            "fields": [
                {
                    "name": "arch",
                    "value": 64,
                    "op": "eq"
                }
            ],
            "syscalls": [
                "personality"
            ],
            "actions": [
                "always",
                "exit"
            ]
        },
        {
            "fields": [
                {
                    "name": "path",
                    "value": "/bin/ls",
                    "op": "eq"
                },
                {
                    "name": "perm",
                    "value": "x",
                    "op": "eq"
                }
            ],
            "actions": [
                "exit",
                "never"
            ]
        },
        {
            "key": "exec",
            "fields": [
                {
                    "name": "arch",
                    "value": 64,
                    "op": "eq"
                }
            ],
            "syscalls": [
                "execve"
            ],
            "actions": [
                "exit",
                "always"
            ]
        },
        {
            "syscalls": [
                "clone",
                "fork",
                "vfork"
            ],
            "actions": [
                "entry",
                "always"
            ]
        },
        {
            "key": "rename",
            "fields": [
                {
                    "name": "arch",
                    "value": 64,
                    "op": "eq"
                },
                {
                    "name": "auid",
                    "value": 1000,
                    "op": "gt_or_eq"
                }
            ],
            "syscalls": [
                "rename",
                "renameat"
            ],
            "actions": [
                "always",
                "exit"
            ]
        }
    ]
}
`
var expectedRules = []string{
	"-w /etc/libaudit.conf -p wa -k audit",
	"-w /etc/rsyslog.conf -p wa -k syslog",
	"-a always,exit-F arch=b64 -S personality -F key=bypass",
	"-a never,exit -F path=/bin/ls -F perm=x",
	"-a always,exit-F arch=b64 -S execve -F key=exec",
	"-a always,exit -S clone,fork,vfork",
	"-a always,exit-F arch=b64 -S rename,renameat -F auid>=1000 -F key=rename",
}

func TestSetRules(t *testing.T) {
	s, err := NewNetlinkConnection()
	if err != nil {
		t.Errorf("failed to avail netlink connection %v", err)
	}
	err = DeleteAllRules(s)
	if err != nil {
		t.Errorf("rule deletion failed %v", err)
	}

	err = SetRules(s, []byte(jsonRules))
	if err != nil {
		t.Errorf("rule setting failed %v", err)
	}
	s.Close()

	// open up a new connection before listing rules
	// for using the same connection we'll need to empty
	// the queued messages from kernel (that are a response to rule addition)
	x, err := NewNetlinkConnection()
	if err != nil {
		t.Errorf("failed to avail netlink connection %v", err)
	}

	actualRules, err := ListAllRules(x)
	if err != nil {
		t.Errorf("rule listing failed %v", err)
	}
	if !(len(actualRules) == len(expectedRules)) {
		t.Errorf("numbers of expected rules mismatch")
	}
	for i := range actualRules {
		if actualRules[i] != expectedRules[i] {
			t.Errorf("expected rule %v, actual rule %v", expectedRules[i], actualRules[i])
		}
	}
	x.Close()
}
