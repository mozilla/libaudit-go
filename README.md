#Linux Audit Heka Plugin (GO)

This project aims deliver the same functionality as Linux Audit (auditd, audispd) + audisp-cef/json but in native Go as a plugin to Heka. 

This means it will listen for events from the kernel via the Netlink protocol, parse the messages, convert them (to JSON using MozDef's native format), and pass them over to Heka. 

###[Project Wiki](https://wiki.mozilla.org/Security/Mentorships/MWoS/2014/Linux_Audit_heka_plugin_%28Go%29)

Feedback
-----------------
Open an issue [https://github.com/owtf/js-lib-sniper/issues](https://github.com/owtf/js-lib-sniper/issues) to report a bug or request a new feature. Other comments and suggestions can be directly emailed to the authors.

