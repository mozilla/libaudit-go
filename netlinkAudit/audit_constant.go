package netlinkAudit

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8960
	AUDIT_GET                = 1000
	AUDIT_SET                = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST               = 1002
	AUDIT_LIST_RULES         = 1013
	AUDIT_ADD_RULE           = 1011 /* Add syscall filtering rule */
	AUDIT_FIRST_USER_MSG     = 1100 /* Userspace messages mostly uninteresting to kernel */
	AUDIT_MAX_FIELDS         = 64
	AUDIT_BITMASK_SIZE       = 64
	//Rule Flags
	AUDIT_FILTER_ENTRY = 0x02 /* Apply rule at syscall entry */

	/*Audit Message Types */
	AUDIT_SYSCALL       = 1300 /* Syscall event */
	AUDIT_PATH          = 1302 /* Filename path information */
	AUDIT_CWD           = 1307 /* Current working directory */

	/* Rule fields */
	/* These are useful when checking the
	 * task structure at task creation time
	 * (AUDIT_PER_TASK).  */
	AUDIT_LOGINUID_SET          = 24
	/* Status symbols */
	/* Mask values */
	AUDIT_STATUS_ENABLED       = 0x0001
	AUDIT_STATUS_PID           = 0x0004
)
