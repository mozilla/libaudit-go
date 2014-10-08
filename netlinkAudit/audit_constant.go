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
	AUDIT_GET_FEATURE        = 1019
	AUDIT_STATUS_ENABLED     = 0x0001
	//Rule Flags
	AUDIT_FILTER_USER  = 0x00 /* Apply rule to user-generated messages */
	AUDIT_FILTER_TASK  = 0x01 /* Apply rule at task creation (not syscall) */
	AUDIT_FILTER_ENTRY = 0x02 /* Apply rule at syscall entry */
	AUDIT_FILTER_WATCH = 0x03 /* Apply rule to file system watches */
	AUDIT_FILTER_EXIT  = 0x04 /* Apply rule at syscall exit */
	AUDIT_FILTER_TYPE  = 0x05 /* Apply rule at audit_log_start */

	/* Rule actions */
	AUDIT_NEVER    = 0 /* Do not build context if rule matches */
	AUDIT_POSSIBLE = 1 /* Build context if rule matches  */
	AUDIT_ALWAYS   = 2 /* Generate audit record if rule matches */

	/* Rule fields */
	/* These are useful when checking the
	 * task structure at task creation time
	 * (AUDIT_PER_TASK).  */
	AUDIT_PID                   = 0
	AUDIT_UID                   = 1
	AUDIT_EUID                  = 2
	AUDIT_SUID                  = 3
	AUDIT_FSUID                 = 4
	AUDIT_GID                   = 5
	AUDIT_EGID                  = 6
	AUDIT_SGID                  = 7
	AUDIT_FSGID                 = 8
	AUDIT_LOGINUID              = 9
	AUDIT_PERS                  = 10
	AUDIT_ARCH                  = 11
	AUDIT_MSGTYPE               = 12
	AUDIT_SUBJ_USER             = 13 /* security label user */
	AUDIT_SUBJ_ROLE             = 14 /* security label role */
	AUDIT_SUBJ_TYPE             = 15 /* security label type */
	AUDIT_SUBJ_SEN              = 16 /* security label sensitivity label */
	AUDIT_SUBJ_CLR              = 17 /* security label clearance label */
	AUDIT_PPID                  = 18
	AUDIT_OBJ_USER              = 19
	AUDIT_OBJ_ROLE              = 20
	AUDIT_OBJ_TYPE              = 21
	AUDIT_OBJ_LEV_LOW           = 22
	AUDIT_OBJ_LEV_HIGH          = 23
	AUDIT_LOGINUID_SET          = 24
	AUDIT_BIT_MASK              = 0x08000000
	AUDIT_LESS_THAN             = 0x10000000
	AUDIT_GREATER_THAN          = 0x20000000
	AUDIT_NOT_EQUAL             = 0x30000000
	AUDIT_EQUAL                 = 0x40000000
	AUDIT_BIT_TEST              = (AUDIT_BIT_MASK | AUDIT_EQUAL)
	AUDIT_LESS_THAN_OR_EQUAL    = (AUDIT_LESS_THAN | AUDIT_EQUAL)
	AUDIT_GREATER_THAN_OR_EQUAL = (AUDIT_GREATER_THAN | AUDIT_EQUAL)
	AUDIT_OPERATORS             = (AUDIT_EQUAL | AUDIT_NOT_EQUAL | AUDIT_BIT_MASK)
)
