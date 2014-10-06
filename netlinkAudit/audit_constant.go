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
)
