# Privilege Escalation on Linux
For authorized users on Linux, ***privilege escalation allows elevated access to complete a specific task or make system configuration modifications***. For example, system administrators may need access **to troubleshoot a technical problem**, **add a user**, **make configuration changes to an application**, or **install a program**.

On Linux, this is typically done via the sudo (Super User DO) command that enables condition-based privilege elevation for user accounts. To use sudo privilege elevation, you simply precede the command with sudo, which will then execute the command as a super-user.


> One common method for authorized users to elevate privileges is via the setuid or setgid, a special permission bit set on an executable that will run with elevated privileges such as root when executed.

## Problem with Linux privilege escalation.

Privilege escalation is also one of the most common techniques attackers use to discover and exfiltrate sensitive data from Linux.

On Linux systems, privilege escalation is a technique by which an attacker gains initial access to a limited or full interactive shell of a basic user or system account with limited privileges. They perform ***enumeration*** to discover the path to elevate access to the root user, the default super-user account on all Linux- based systems. Once they gain root user access, they have ultimate control of an entire Linux system.

Let’s say an attacker successfully compromises a user’s credential and gains access to their account. That password may enable certain privileges. For example, it may unlock data stored locally on a web server, web application, or content management system.

But the attacker is always hungry for more. They’re looking for more sensitive data they can resell for profit. They’re looking for access to business-critical applications so they can deploy ransomware, shutdown services, and demand financial payment.

## To be successful, an attacker engages in a variety of strategies to escalate privileges on Linux systems:


- ***Vertical privilege escalation***, sometimes referred to as privilege elevation, is when an attacker compromises a user account that has limited shell permissions on a system. They then look for ways to increase their privileges using the same account. For example, they might add the compromised account to sudoers file so they can execute commands as the super-user account or use the special permission bit set by setuid and setgid to execute an executable as a privileged user.

- ***Horizontal privilege escalation***, the more common method, is when an attacker gains access to another user on the system with higher privileges than the initial one used to gain their initial shell. With higher level privileges, an attacker can move freely around the network without detection.


## Basics of Linux privilege escalation

Before we explain how to prevent unwanted privilege escalation, it’s important to have a basic understanding of how access controls work on Linux systems. User account management is one of the critical steps to hardening and securing Linux systems. Unmanaged user accounts leave a door open for attackers to exploit. Unused user accounts or accounts with easily cracked or guessable passwords are the most targeted by attackers.

> A big difference between Windows and Linux is that Windows was originally planned as a single-user system with administrator privileges. In contrast, Linux was designed as a multi-user operating system. With many users accessing the same system, you can see why managing directory and file access is critical.

## How privileges are created and delegated in Linux systems 

One of the most important files on the Linux system is the ***passwd file***, located at /etc/passwd. This file lists all the users known to the system which could also be included in directory services.

If we look inside the passwd file using the “cat” command ie 
>cat /etc/passwd

we get lines representing users on the Linux system.

Each field is separated using the colon “:” character in which the fields represent the following passwd file format:

1. Username
2. Password Placeholder (x indicates encrypted password is stored in the /etc/shadow file)
3. User ID (UID)
4. Group ID (GID)
5. Personal Information (separated by comma’s) – can contain full name, department, etc.
6. Home Directory
7. Shell – absolute path to the command shell used (if /sbin/nologon then logon isn’t permitted, and the connection gets closed)

