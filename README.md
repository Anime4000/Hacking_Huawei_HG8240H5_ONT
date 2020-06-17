
# Hacking Huawei HG8240 Series ONT/ONU
Huawei HG8240 Series ONT was a mass produce for country deploy Fiber Internet.
This repo was inspired by [@logon84](https://github.com/logon84/Hacking_Huawei_HG8012H_ONT)

# Step & Guide to access CLI
After I moving from ADSL2+ (8192/512k) internet to Fiber Internet (300/50m), I found my connection latency are horrible, in my country,  ISP **hard limit** WAN speed for unfair competitive, this guide ***try*** to remove **hard limit**, thus will solve **bufferbloat** issue that cause `ping` spike.

The ONT will receive some command from OLT for **hard limit** *I woner what is command OLT send to this ONT*
```
1981-01-01 00:01:43 [Critical][Config-Log] Terminal:OLT(-),Result:Success,Type:Set,Msg:Me[11] Inst[257] Att[5] Val[0]
1981-01-01 00:01:43 [Critical][Config-Log] Terminal:OLT(-),Result:Success,Type:Set,Msg:Me[11] Inst[258] Att[5] Val[0]
1981-01-01 00:01:43 [Critical][Config-Log] Terminal:OLT(-),Result:Success,Type:Set,Msg:Me[11] Inst[259] Att[5] Val[0]
1981-01-01 00:01:43 [Critical][Config-Log] Terminal:OLT(-),Result:Success,Type:Set,Msg:Me[11] Inst[260] Att[5] Val[0]
```

![ONT Top](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/ont_front_mozjpeg.jpg)
So I got another extra ONT from a friend, in this particular modem I have is **HG8240H5** for me experiment with, without risking main ONT.

# Issue #1
Back of ONT have some info about default IP address and login info for access Web GUI,
![ONT Bottom](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/ont_back_mozjpeg.jpg)

My Kali PC have 3 LAN port, `eth0` used for Internet.

However, this particular ONT using `192.168.1.1` will conflict with my `eth0`, so I need to disconnect my `eth0` temporary, connect ONT to `eth2` and set network profile:
![ONT Bottom](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/static%20ip.png)

# Issue #2
Inside Web GUI, configuration pretty basic. I want to access advanced configuration! It should be some configuration port, or Telnet/SSH!

## Scan Port
I trying to find any available open port using `nmap` tools, what I found:
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/nmap_1_scan.png)
Port `21` `22` `23` was filtered by device firewall. there is no way to gain access these port, time to move next part!

## WebGUI
Login to Web GUI via `https:\\192.168.1.1:80` *yes, HTTPS works with port 80, pretty weird...*
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/WebGUI_001.png)
For this model, I use `tmadmin` for username, `Adm@XXXX` for password, where `XXXX` is last HEX digit of **mac address**

You can try several default login, just google it!

If you received **First Time Setup** or **Service Provisioning**, simply `Exit` or `Skip`

## Download configuration
Hopefully by downloading configuration, I can craft and edit to enable extra feature, allowing me to access SSH for advanced configuration.
![---](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/WebGUI_003.png)
This model, no need to use `aescrypt2_huawei` to decrypt configuration file:
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/WebGUI_004.png)

---
Hours of hours examine and found something interesting:

### ONT IP Address:
```xml
<IPInterface NumberOfInstances="2">
<IPInterfaceInstance InstanceID="1" Enable="1" IPInterfaceIPAddress="192.168.1.1" IPInterfaceSubnetMask="255.255.255.0" IPInterfaceAddressingType="Static" X_HW_AddressConflictDetectionEnable="1" X_HW_RouteProtocolRx="Off" X_HW_RouteProtocolRxMode="Passive" X_HW_RouteProtocolAuthMode="Off" X_HW_RouteProtocolAuthKey=""/>
<IPInterfaceInstance InstanceID="2" Enable="1" IPInterfaceIPAddress="192.168.2.1" IPInterfaceSubnetMask="255.255.255.0" IPInterfaceAddressingType="Static" X_HW_AddressConflictDetectionEnable="1" X_HW_RouteProtocolRx="" X_HW_RouteProtocolRxMode="" X_HW_RouteProtocolAuthMode="" X_HW_RouteProtocolAuthKey=""/>
</IPInterface>
```

### ONT Services:
```xml
<AclServices HTTPLanEnable="1" HTTPWanEnable="0" FTPLanEnable="0" FTPWanEnable="0" TELNETLanEnable="0" TELNETWanEnable="0" SSHLanEnable="0" SSHWanEnable="0" HTTPPORT="80" FTPPORT="21" TELNETPORT="23" SSHPORT="22" HTTPWifiEnable="1" TELNETWifiEnable="1">
<AccessControl AccessControlListEnable="0" AccessControlListNumberOfEntries="0"/>
</AclServices>
```

### ONT Account:
```xml
<UserInterface>
<X_HW_CLIUserInfo NumberOfInstances="1">
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root" Userpassword="$211e$LpZ`P3NI3NC.+x025rO)GrxpQ!&gt;*Px,|#2q=Q|Y8F.)AEG&apos;]0\&quot;KFm4=e1lt5%&lt;g&quot;K6&apos;:&gt;D&amp;91HPei:4Y`!)3*52Q9U}XS9G$" UserGroup="" ModifyPWDFlag="0" EncryptMode="2" Salt="6545bfb1aa7bb6d13ca10c1c"/>
</X_HW_CLIUserInfo>
<X_HW_CLITelnetAccess Access="1" TelnetPort="23"/>
<X_HW_WebUserInfo NumberOfInstances="2">
<X_HW_WebUserInfoInstance InstanceID="1" UserName="tmuser" Password="$2kr/}$^n$b%*/D\5P1F:8$`*H%-aM,B3j!P29E,&quot;2gR*.8&gt;$Mi1u=s|WNH920xm;Z#g-9:L|ygt:}7^mP4q`b2%5/JKU=}rOlaeb($" UserLevel="1" Enable="1" ModifyPasswordFlag="0" Salt="aee1d0e153b5fcb505d58b1a" PassMode="3" Alias="cpe-1"/>
<X_HW_WebUserInfoInstance InstanceID="2" UserName="tmadmin" Password="$2C6gg*Ta76Y9iM$-2&quot;+}%Q$u&apos;0CKf$AE5(F.lNzRH1ylp6()9=~ORWl*,eqdSNHiL*$u&apos;%Yw0yB-e\1EE&quot;WID5HKJ[%)_qs#wQ`yH$" UserLevel="0" Enable="1" ModifyPasswordFlag="0" Salt="d8d14642ca8e3568b63abe16" PassMode="3" Alias="cpe-2"/>
</X_HW_WebUserInfo>
</UserInterface>
```

### ONT FTP
```xml
<X_HW_ServiceManage FtpEnable="0" FtpPort="21" FtpRoorDir="/mnt/usb1_1/" FtpUserNum="0"/>
```

### ONT Remote Management
```xml
<ManagementServer EnableCWMP="1" URL="http://acs.tm.com.my:8082/tmacstr069" Username="cpe" Password="$2u5-SPs=_w7V^&gt;a*6l&gt;aPZft|==e/s*d&lt;j,WEZr4V$" PeriodicInformEnable="1" PeriodicInformInterval="43200" PeriodicInformTime="" ParameterKey="0" ConnectionRequestURL="" ConnectionRequestUsername="ccs" ConnectionRequestPassword="$2#.+hWU=%ORPHK~6|E4B1~_*:&lt;9s)L2JLUN.DqVcP$" UpgradesManaged="0" KickURL="" DownloadProgressURL="" DefaultActiveNotificationThrottle="0" UDPConnectionRequestAddress="" UDPConnectionRequestAddressNotificationLimit="0" STUNEnable="0" STUNServerAddress="" STUNServerPort="0" STUNUsername="" STUNPassword="" STUNMaximumKeepAlivePeriod="0" STUNMinimumKeepAlivePeriod="0" NATDetected="0" ManageableDeviceNumberOfEntries="0" ManageableDeviceNotificationLimit="0" X_HW_EnableCertificate="0" X_HW_CertPassword="$2}=\7,O;T~V7/J+!N~t@7_R|!IW]|ZB,&apos;JS*Pus`H$" X_HW_DSCP="0" X_HW_CheckPasswordComplex="0" X_HW_PeriodicInformTime=""/>
```

### ONT Power Management
```xml
<X_HW_APMPolicy EnablePowerSavingMode="1">
<BatteryModePolicy NotUseUsbService="0" NotUseLanService="0" NotUseWlanService="0" NotUseVoiceService="0" NotUseCATVService="0" NotUseRemoteManagement="0"/>
</X_HW_APMPolicy>
```

### ONT Custom Info
```xml
<X_HW_ProductInfo originalVersion="V500R019C00SPC125A1904230116" currentVersion="V500R019" customInfo="TM" customInfoDetail="tm"/>
```

## Time to modify
Now, to modify some value and add some setting attribute, first, make a copy for modified version! Then copy these XML and replace.

### ONT IP Address:
*Change `192.168.1.1` to `192.168.100.1` also `disable` 2nd IP Address, it's useless*:
```xml
<IPInterface NumberOfInstances="2">
<IPInterfaceInstance InstanceID="1" Enable="1" IPInterfaceIPAddress="192.168.100.1" IPInterfaceSubnetMask="255.255.255.0" IPInterfaceAddressingType="Static" X_HW_AddressConflictDetectionEnable="1" X_HW_RouteProtocolRx="Off" X_HW_RouteProtocolRxMode="Passive" X_HW_RouteProtocolAuthMode="Off" X_HW_RouteProtocolAuthKey=""/>
<IPInterfaceInstance InstanceID="2" Enable="0" IPInterfaceIPAddress="192.168.2.1" IPInterfaceSubnetMask="255.255.255.0" IPInterfaceAddressingType="Static" X_HW_AddressConflictDetectionEnable="1" X_HW_RouteProtocolRx="" X_HW_RouteProtocolRxMode="" X_HW_RouteProtocolAuthMode="" X_HW_RouteProtocolAuthKey=""/>
</IPInterface>
```

### ONT Services:
*Change `0` to `1` for attribute: `FTPLanEnable="1"` `TELNETLanEnable="1"` `SSHLanEnable="1"`*
```xml
<AclServices HTTPLanEnable="1" HTTPWanEnable="0" FTPLanEnable="1" FTPWanEnable="0" TELNETLanEnable="1" TELNETWanEnable="0" SSHLanEnable="1" SSHWanEnable="0" HTTPPORT="80" FTPPORT="21" TELNETPORT="23" SSHPORT="22" HTTPWifiEnable="1" TELNETWifiEnable="1">
<AccessControl AccessControlListEnable="0" AccessControlListNumberOfEntries="0"/>
</AclServices>
```

### ONT Account:
*Add new attribute `<X_HW_CLISSHControl Enable="1" port="22" Mode="0" AluSSHAbility="0"/>` before `<X_HW_CLITelnetAccess/>`*
```xml
<UserInterface>
<X_HW_CLIUserInfo NumberOfInstances="1">
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root" Userpassword="$211e$LpZ`P3NI3NC.+x025rO)GrxpQ!&gt;*Px,|#2q=Q|Y8F.)AEG&apos;]0\&quot;KFm4=e1lt5%&lt;g&quot;K6&apos;:&gt;D&amp;91HPei:4Y`!)3*52Q9U}XS9G$" UserGroup="" ModifyPWDFlag="0" EncryptMode="2" Salt="6545bfb1aa7bb6d13ca10c1c"/>
</X_HW_CLIUserInfo>
<X_HW_CLISSHControl Enable="1" port="22" Mode="0" AluSSHAbility="0"/>
<X_HW_CLITelnetAccess Access="1" TelnetPort="23"/>
<X_HW_WebUserInfo NumberOfInstances="2">
<X_HW_WebUserInfoInstance InstanceID="1" UserName="tmuser" Password="$2kr/}$^n$b%*/D\5P1F:8$`*H%-aM,B3j!P29E,&quot;2gR*.8&gt;$Mi1u=s|WNH920xm;Z#g-9:L|ygt:}7^mP4q`b2%5/JKU=}rOlaeb($" UserLevel="1" Enable="1" ModifyPasswordFlag="0" Salt="aee1d0e153b5fcb505d58b1a" PassMode="3" Alias="cpe-1"/>
<X_HW_WebUserInfoInstance InstanceID="2" UserName="tmadmin" Password="$2C6gg*Ta76Y9iM$-2&quot;+}%Q$u&apos;0CKf$AE5(F.lNzRH1ylp6()9=~ORWl*,eqdSNHiL*$u&apos;%Yw0yB-e\1EE&quot;WID5HKJ[%)_qs#wQ`yH$" UserLevel="0" Enable="1" ModifyPasswordFlag="0" Salt="d8d14642ca8e3568b63abe16" PassMode="3" Alias="cpe-2"/>
</X_HW_WebUserInfo>
</UserInterface>
```

### ONT FTP
*Edit `FtpEnable="1"` and `FtpRoorDir="/mnt/jffs2/"`*
```xml
<X_HW_ServiceManage FtpEnable="1" FtpUserName="root" FtpPassword="admin" FtpPort="21" FtpRoorDir="/mnt/jffs2/" FtpUserNum="0"/>
```

### ONT Remote Management
*Disable Remote Management `EnableCWMP="0"`*
```xml
<ManagementServer EnableCWMP="0" URL="http://acs.tm.com.my:8082/tmacstr069" Username="cpe" Password="$2u5-SPs=_w7V^&gt;a*6l&gt;aPZft|==e/s*d&lt;j,WEZr4V$" PeriodicInformEnable="1" PeriodicInformInterval="43200" PeriodicInformTime="" ParameterKey="0" ConnectionRequestURL="" ConnectionRequestUsername="ccs" ConnectionRequestPassword="$2#.+hWU=%ORPHK~6|E4B1~_*:&lt;9s)L2JLUN.DqVcP$" UpgradesManaged="0" KickURL="" DownloadProgressURL="" DefaultActiveNotificationThrottle="0" UDPConnectionRequestAddress="" UDPConnectionRequestAddressNotificationLimit="0" STUNEnable="0" STUNServerAddress="" STUNServerPort="0" STUNUsername="" STUNPassword="" STUNMaximumKeepAlivePeriod="0" STUNMinimumKeepAlivePeriod="0" NATDetected="0" ManageableDeviceNumberOfEntries="0" ManageableDeviceNotificationLimit="0" X_HW_EnableCertificate="0" X_HW_CertPassword="$2}=\7,O;T~V7/J+!N~t@7_R|!IW]|ZB,&apos;JS*Pus`H$" X_HW_DSCP="0" X_HW_CheckPasswordComplex="0" X_HW_PeriodicInformTime=""/>
```

### ONT Power Management
*Disable Power Management `EnablePowerSavingMode="0"` for maximum performance!*
```xml
<X_HW_APMPolicy EnablePowerSavingMode="0">
<BatteryModePolicy NotUseUsbService="0" NotUseLanService="0" NotUseWlanService="0" NotUseVoiceService="0" NotUseCATVService="0" NotUseRemoteManagement="0"/>
</X_HW_APMPolicy>
```

### ONT Custom Info
*Change `isp` info to `common` device*
```xml
<X_HW_ProductInfo originalVersion="V500R019C00SPC125A1904230116" currentVersion="V500R019" customInfo="COMMON" customInfoDetail="common"/>
```

## Upload a Modification
Save modified file and upload crafted XML, ONT will reboot for take effect of this change.
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/WebGUI_005.png)

## Checking...
After ONT up and running, change to new static IP Address to `192.168.100.0/24`:
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/static%20ip%20100.png)

Time to scan port see any open:
![enter image description here](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/nmap_2_scan.png)
Yes! `ssh`, `telnet` is open, but `ftp` is closed, not sure why...

## Time to login
try to login with `root` username and `adminHW` password:
![ssh yes](https://raw.githubusercontent.com/Anime4000/Hacking_Huawei_HG8240H5_ONT/master/images/Screenshot_2020-06-14_16-11-49.png)
Yes it worked!
This not like full edge Linux, like cisco, ubiquiti, mikrotik, Huawei also have their own config command.

Available command as follow:
```
SU_WAP>?
amp add policy-stats pon
amp add policy-stats port
amp add stats gemport
amp clear policy-stats pon
amp clear policy-stats port
amp clear stats gemport
amp del policy-stats pon
amp del policy-stats port
amp del stats gemport
ampcmd show car all
ampcmd show car index
ampcmd show emac stat
ampcmd show flow all
ampcmd show flow index
ampcmd show log
ampcmd show queue all
ampcmd show queue index
ampcmd trace all
ampcmd trace cli
ampcmd trace dpoe
ampcmd trace drv
ampcmd trace emac
ampcmd trace emap
ampcmd trace eth
ampcmd trace gmac
ampcmd trace gmap
ampcmd trace onu
ampcmd trace optic
ampcmd trace qos
backtrace
bbsp add policy-stats btv
bbsp clear policy-stats btv all
bbsp clear policy-stats wan
bbsp del policy-stats btv
bbspara
bbspcmd
Broadband debug
Broadband display
btv start period-stats
btv stop period-stats
chipdebug
chipdebug clearall
chipdebug soc drop
chipdebug soc rx
chipdebug soc tx
clear amp pq-stats
clear file
clear lastword
clear pon statistics
clear poncnt dnstatistic
clear poncnt gemport upstatistic
clear poncnt upstatistic
clear port statistics
clear sfwd drop statistics
collect debug info
component delete all
debug dsp down msg
debug dsp msg
debug dsp up msg
debug ifm
debug qoscfg
debug rtp stack
debug sample mediastar
debugging dsp diagnose
debugging dsp para diagnose
debugging dsp record
debugging dsp t38diag
dect debug
dhcp client attach
dhcp client detach
dhcp client6 attach
dhcp client6 detach
dhcp server pool config
dhcp server pool disable
dhcp server pool enable
dhcp server pool lease config
dhcp server pool option add
dhcp server pool option del
dhcp server pool option flush
dhcp server pool restart
diagnose
display access mode
display access system info
display amp policy-stats pon
display amp policy-stats port
display amp pq-stats
display amp stats gemport
display apmChipStatus
display batteryStatus
display bbsp stats btv
display bbsp stats wan
display bmsxml crc
display board-temperatures
display board2Item
display boardItem
display broadband info
display connection
display connection all
display cpu info
display current-configuration
display cwmp debug
display cwmp status
display ddns info
display debug info dhcp6c
display debug info dhcp6s
display debug info pppoev6
display debug info ra
display debuglog info
display deviceInfo
display dhcp client
display dhcp client all
display dhcp client6
display dhcp client6 all
display dhcp server pool
display dhcp server pool all
display dhcp server pool option
display dhcp server static
display dhcp server user
display dhcp server user all
display dhcp_em result
display dns proxy info
display dnsserver static domain
display dsp channel para
display dsp channel running status
display dsp channel status
display dsp chip stat
display dsp codec status
display dsp interrupt stat
display dynamic route
display epon ont info
display ethoam ma info
display ethoam md info
display ethoam mep info
display ethoam mep perf
display ffwd table
display file
display filter rf
display firewall rule
display flashlock status
display flow
display ftp config status
display if
display igmp
display igmp config
display inner version
display ip interface
display ip neigh
display ip route
display ip6tables filter
display iperf client result
display iperf server result
display iptables filter
display iptables mangle
display iptables nat
display iptables raw
display jb grid status
display jb para
display lan mac filter
display lanmac
display lanport workmode
display last call log
display lastword
display log info
display mac ap
display mac ap brief
display macaddress
display macaddress timer
display machineItem
display memory detail
display memory info
display msg-queue
display nat port mapping
display nff log
display oaml2shell ethvlan
display onu info
display optic
display optmode
display patch information
display ploam-password
display plugin-board-info
display pon statistics
display poncnt dnstatistic
display poncnt gemport upstatistic
display poncnt upstatistic
display port statistics
display portstatistics
display ppp interface
display pppoe client
display pppoe client all
display pppoe_em result
display productmac
display progress load
display rf config
display rfpi
display rtp stack channel stat
display rtp stack chip stat
display rtp stack para
display rtp stack version
display sfwd drop statistics
display sfwd port statistics
display sn
display specsn
display ssh authentication-type
display ssh-hostkey fingerprint
display startup info
display swm bootstate
display swm state
display sysinfo
display syslog
display system info
display timeout
display timer
display tr069 info
display version
display voice hs status
display voip dsp jbdata
display voip dsp para diagnose state
display voip dsp para diagnose statistics
display voip dsp tonedetect
display voip dtmfdiag state
display voip dtmfsimpara
display voip info
display voip rightflag
display voip ring info
display voip rtpdiag
display voip tone info
display wan layer all
display waninfo
display waninfo all
display wanmac
display wifi calibrate mode
display wifi pa type
display wifichip
display wlanmac
display zsp version
dnsserver add static
dnsserver delete static
firewall log
firewall rule add
firewall rule delete
firewall rule flush
flush dhcp server pool
flush dnsserver cache
get battery alarm policy
get battery alarm status
get iot fwtype
get ip conntrack
get mac agingtime
get ont oamfrequency
get opm switch
get optic debug info
get optic par info
get optic phy type
get optic txmode
get poncnt upgemport
get port config
get port isolate
get rogue status
get testself
get wlan advance
get wlan associated
get wlan basic
get wlan enable
get wlan stats
get wlan wps
ifconfig
igmp add mirror filter
igmp clear statistics
igmp del mirror filter
igmp disable
igmp enable
igmp get debug switch
igmp get flow info
igmp get global cfg
igmp get iptv
igmp get mirror filter ip
igmp get multilmac
igmp get port multicast config
igmp get statistics
igmp set debug switch
igmp set iptv
ip -6 neigh
ip -6 route
ip -6 rule
ip interface config
ip neigh
ip neigh add
ip neigh delete
ip neigh flush
ip route
ip route add
ip route delete
ip rule
iperf3
lan mac filter add
lan mac filter delete
lan mac filter disable
lan mac filter enable
lan mac filter flush
load pack
load ssh-pubkey
logout
macaddress
make ssh hostkey
mgcp mg-config
mgcp mgc 1
mgcp mgc 2
mid get
mid off
mid set
napt cli
nat port mapping add
nat port mapping delete
nat port mapping flush
netstat -na
nslookup
oam show eventlog
oamcmd clear log
oamcmd debug
oamcmd error log
oamcmd pdt show log
oamcmd show flow
oamcmd show log
omcicmd alarm show
omcicmd clear log
omcicmd debug
omcicmd error log
omcicmd mib show
omcicmd pdt show log
omcicmd pm show
omcicmd show flow
omcicmd show log
omcicmd show qos
ping
ppp interface config
pppoe client attach
pppoe client detach
quit
reset
restore manufactory
save data
save log
session cli
set cwmp debug
set ethportmirror
set flashlock
set iaccess speed
set iot fwtype
set iperf client
set iperf server
set led
set opticdata
set port isolate
set portmirror
set ringchk
set timeout
set tr069 info
set userpasswd
set voice announcement
set voice dtmfmethod
set voicedebug
set voicedsploop
set voicelinetest
set voiceportloop
set voicesignalingprint
set voip clip
set voip dsptemplate
set voip dtmfdebug
set voip dtmfdetfilter
set voip dtmfdiag start
set voip dtmfdiag stop
set voip dtmfsimpara
set voip dtmfsimu start
set voip dtmfsimu stop
set voip fax T38
set voip faxmodem switch
set voip highpassfilter
set voip portgain
set voip rtpdiag
set voip sipprofile
set wlan basic
set wlan enable
sfwd port statistics
shell
show diagnose
ssh authentication-type
start diagnose
stats clear
stats display
stop diagnose
su
telnet remote
test apdev
test tr069 inform end
test tr069 inform start
traceroute
trafficdump
udm clear log
udm show log
undo debugging dsp diagnose
undo debugging dsp para diagnose
undo debugging dsp record
undo debugging dsp t38diag
undo firewall log
voice net diagnose start
voice remote diagnose server set
voice remote diagnose set
voice set dect unreg
vspa clear rtp statistics
vspa debug
vspa display conference info
vspa display digitmap info
vspa display dsp running info
vspa display dsp state
vspa display dsp template info
vspa display mg if state
vspa display mg info
vspa display mgcp config
vspa display online user info
vspa display port status
vspa display profilebody info
vspa display rtp statistics
vspa display service log
vspa display signal scene info
vspa display signal scene list
vspa display user call state
vspa display user status
vspa reset
vspa shutdown mg
wap list
wap ps
wap top
```

## Issue #3
I don't see any command about specific GEM where I can remove *hard speed limit*

I thinking, let's try open this and find UART header, see if I can access more command via UART
```
PIN:     Device     TTL
1        RX         TX
2         
3
4        GND        GND
5        TX         RX
```
And I open `sudo screen /dev/ttyUSB0 115200` command, then powering on ONT, this what I received:
```
anime4000@umiko-io:~$ sudo screen /dev/ttyUSB0 115200
Chip Type is SD5117P  
safetycode boot type: spi nand flash  
Safetycode build: (V500R019C00 Sep 7 2018 - 09:29:36)  
Select startcodeA  
startcode start at 0x1c020088  
  
  
Startcode 2017.07 (V500R019C00 Sep 07 2018 - 09:30:09 +0800 V5)  
  
NAND: SPI_NAND_FLASH_TYPE  
flash_type = [0x6]  
Nand ID: 0xC2 0x12 0xC2 0x12 0xC2 0x00 0x00 0x00  
ECC Match pagesize:2K, oobzie:64, ecctype:8bit  
Nand(Hardware): startcode select the uboot to load  
the high RAM is :8080103c  
startcode uboot boot count:0  
use the main slave_paramA area from flash, the RAM data is not OK!!!  
Use the AllsytemA to load first  
Start in Normal Mode  
Use the AllsytemA to load success  
  
  
U-Boot 2017.07 (V500R019C00 Apr 24 2019 - 06:06:56 +0800 V5)  
  
DRAM: 128 MiB  
Boot From NAND flash  
Chip Type is SD5117P  
NAND: SPI_NAND_FLASH_TYPE  
flash_type = [0x6]  
Special Nand id table Version 1.23  
Nand ID: 0xC2 0x12 0xC2 0x12 0xC2 0x00 0x00 0x00  
ECC Match pagesize:2K, oobzie:64, ecctype:8bit  
Nand(Hardware): Block:128KB Page:2KB Chip:134217728B OOB:64B ECC:8bit  
128 MiB  
128 MiB  
Using default environment  
  
[UBI-DEBUG]: all in ubi mode  
In: serial  
Out: serial  
Err: serial  
Net: phy init failure0  
PHY power down !!!  
Mbist flag = 0x0, ddr totoal size = 0x8000000  
[common/pon_chip_v5/main.c__2053]::CRC:0x3d80a8b4, Magic1:0x5a5a5a5a, Magic2:0xa 5a5a5a5, count:0, CommitedArea:0x0, Active:0x0, RunFlag:0x0  
UBI: attaching mtd1  
ubi0: scanning is finished  
ubi0: attached mtd1 (name "mtd=1", size 127 MiB)  
ubi0: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes  
ubi0: min./max. I/O unit sizes: 2048/2048, sub-page size 2048  
ubi0: VID header offset: 2048 (aligned 2048), data offset: 4096  
ubi0: good PEBs: 1016, bad PEBs: 0, corrupted PEBs: 0  
ubi0: user volume: 10, internal volumes: 1, max. volumes count: 128  
ubi0: max/mean erase counter: 3/1, WL threshold: 4096, image sequence number: 85 3105020  
ubi0: available PEBs: 5, total reserved PEBs: 1011, PEBs reserved for bad PEB ha ndling: 20  
Start from main system(0x0)!  
CRC:0x3d80a8b4, Magic1:0x5a5a5a5a, Magic2:0xa5a5a5a5, count:1, CommitedArea:0x0, Active:0x0, RunFlag:0x0  
Main area: Cert partition Found  
Slave area: Cert partition Found  
Main area (A) is OK!  
CRC:0x93e83925, Magic1:0x5a5a5a5a, Magic2:0xa5a5a5a5, count:1, CommitedArea:0x0, Active:0x0, RunFlag:0x0  
Bootcmd:ubi read 0x80907f6c allsystemA 0x1bc000 0x65000; bootm 0x80907fc0  
BootArgs:noalign mem=119M flashsize=0x8000000 console=ttyAMA1,115200 root=/dev/m tdblock6 rootflags=image_off=0x221094 rootfstype=squashfs mtdparts=hinand:0x1000 00(bootcode)raw,0x7f00000(ubilayer_v5) ubi.mtd=1 maxcpus=0 l2_cache=l2x0 coheren t_pool=4M user_debug=0x1f panic=1 skb_priv=192 debug_ll=on  
U-boot Start from NORMAL Mode!  
## Booting kernel from Legacy Image at 80907fc0 ...  
Image Name: Linux-3.10.53-HULK2  
Image Type: ARM Linux Kernel Image (uncompressed)  
Data Size: 1815084 Bytes = 1.7 MiB  
Load Address: 80e08000  
Entry Point: 80e08000  
  
Match the dtb file index : 1!  
Memory Start: 80900000  
XIP Kernel Image ... OK  
kernel loaded at 0x80908000, end = 0x80ac0478  
  
Starting kernel ...  
  
Uart base = 0x1010F000  
dtb addr = 0x80F633D8  
Uncompressing Linux... done, booting the kernel.  
Booting Linux on physical CPU 0x0  
Initializing cgroup subsys cpuset  
Initializing cgroup subsys cpu  
Initializing cgroup subsys cpuacct  
Linux version 3.10.53-HULK2 (ci@SZXRTOSCI10000) (gcc version 4.7.1 (SDK V100R005 C00SPC030B050) ) #1 SMP Fri Apr 13 19:54:43 CST 2018  
CPU: ARMv7 Processor [414fc091] revision 1 (ARMv7), cr=18c53c7d  
CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache  
Machine: Hisilicon A9, model: HISI-CA9  
skbuff priv len is 192.  
Memory policy: ECC disabled, Data cache writealloc  
On node 0 totalpages: 30464  
free_area_init_node: node 0, pgdat c04a7340, node_mem_map c04d7800  
Normal zone: 298 pages used for memmap  
Normal zone: 0 pages reserved  
Normal zone: 30464 pages, LIFO batch:7  
[dts]:cpu type is 5115  
PERCPU: Embedded 7 pages/cpu @c0605000 s7488 r8192 d12992 u32768  
pcpu-alloc: s7488 r8192 d12992 u32768 alloc=8*4096  
pcpu-alloc: [0] 0 [0] 1 [0] 2 [0] 3  
Built 1 zonelists in Zone order, mobility grouping on. Total pages: 30166  
Kernel command line: noalign mem=119M flashsize=0x8000000 console=ttyAMA1,115200 root=/dev/mtdblock6 rootflags=image_off=0x221094 rootfstype=squashfs mtdparts=h inand:0x100000(bootcode)raw,0x7f00000(ubilayer_v5) ubi.mtd=1 maxcpus=0 l2_cache= l2x0 coherent_pool=4M user_debug=0x1f panic=1 skb_priv=192 debug_ll=on  
PID hash table entries: 512 (order: -1, 2048 bytes)  
Dentry cache hash table entries: 16384 (order: 4, 65536 bytes)  
Inode-cache hash table entries: 8192 (order: 3, 32768 bytes)  
allocated 243712 bytes of page_cgroup  
please try 'cgroup_disable=memory' option if you don't want memory cgroups  
Memory: 119MB = 119MB total  
Memory: 115196k/115196k available, 6660k reserved, 0K highmem  
Virtual kernel memory layout:  
vector : 0xffff0000 - 0xffff1000 ( 4 kB)  
fixmap : 0xffe00000 - 0xfffe0000 (1920 kB)  
vmalloc : 0xc7800000 - 0xff000000 ( 888 MB)  
lowmem : 0xc0000000 - 0xc7700000 ( 119 MB)  
modules : 0xbf000000 - 0xc0000000 ( 16 MB)  
.text : 0xc0008000 - 0xc04350e0 (4277 kB)  
.init : 0xc0436000 - 0xc0462d40 ( 180 kB)  
.data : 0xc0464000 - 0xc04ab3c8 ( 285 kB)  
.bss : 0xc04ab3c8 - 0xc04d4108 ( 164 kB)  
SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1  
Hierarchical RCU implementation.  
NR_IRQS:512  
sched_clock: 32 bits at 100MHz, resolution 10ns, wraps every 42949ms  
[DTS][LED]-->WARN:Cannot find led info in dtb,make sure there is no led on board  
Calibrating delay loop... 1332.01 BogoMIPS (lpj=6660096)  
pid_max: default: 32768 minimum: 301  
Security Framework initialized  
Mount-cache hash table entries: 512  
Initializing cgroup subsys memory  
Initializing cgroup subsys devices  
Initializing cgroup subsys freezer  
Initializing cgroup subsys net_cls  
Initializing cgroup subsys blkio  
Initializing cgroup subsys net_prio  
CPU: Testing write buffer coherency: ok  
Setting up static identity map for 0xc0318498 - 0xc03184cc  
Brought up 1 CPUs  
SMP: Total of 1 processors activated (1332.01 BogoMIPS).  
CPU: All CPU(s) started in SVC mode.  
NET: Registered protocol family 16  
DMA: preallocated 4096 KiB pool for atomic coherent allocations  
SD511x chip id:0x51176100  
L310 cache controller enabled  
l2x0: 16 ways, CACHE_ID 0x410000c9, AUX_CTRL 0x02430001, Cache size: 262144 B  
bio: create slab <bio-0> at 0  
cfg80211: Calling CRDA to update world regulatory domain  
Switching to clocksource arm,sp804  
NET: Registered protocol family 2  
TCP established hash table entries: 1024 (order: 1, 8192 bytes)  
TCP bind hash table entries: 1024 (order: 2, 16384 bytes)  
TCP: Hash tables configured (established 1024 bind 1024)  
TCP: reno registered  
UDP hash table entries: 256 (order: 1, 12288 bytes)  
UDP-Lite hash table entries: 256 (order: 1, 12288 bytes)  
NET: Registered protocol family 1  
PCI: CLS 0 bytes, default 64  
squashfs: version 4.0 (2009/01/31) Phillip Lougher  
jffs2: version 2.2. © 2001-2006 Red Hat, Inc.  
fuse init (API version 7.22)  
msgmni has been set to 224  
io scheduler noop registered  
io scheduler deadline registered  
io scheduler cfq registered (default)  
brd: module loaded  
mtdoops: mtd device (mtddev=name/number) must be supplied  
Spi id table Version 1.22  
Special nand id table Version 1.33  
Hisilicon Flash Memory Controller V100 Device Driver, Version 1.0  
flash_type = 0x6  
SPI_NAND_FLASH_TYPE  
Nand ID: 0xC2 0x12 0xC2 0x12 0xC2 0x00 0x00 0x00  
ECC Match pagesize:2K, oobzie:64, ecctype:8bit  
Nand(Hardware): Block:128KB Page:2KB Chip:128MB OOB:64B ECC:8bit  
NAND device: Manufacturer ID: 0xc2, Chip ID: 0x12 (Macronix MX35LF1GE4AB), 128Mi B, page size: 2048, OOB size: 64  
NAND_ECC_NONE selected by board driver. This is not recommended!  
raw_mtd: treat mtd0 as raw mtd.  
2 cmdlinepart partitions found on MTD device hinand  
Creating 2 MTD partitions on "hinand":  
0x000000000000-0x000000100000 : "bootcode"  
0x000000100000-0x000008000000 : "ubilayer_v5"  
softdog: Software Watchdog Timer: 0.08 initialized. soft_noboot=0 soft_margin=60 sec soft_panic=0 (nowayout=0)  
TCP: cubic registered  
NET: Registered protocol family 17  
ThumbEE CPU extension supported.  
mapp kbox ddrram_address=0, ddrram_size=0 fail[WARNNING]:Kbo x device descriptor struct kbox_dev_des Intialization Failed  
kbox: init ddrram fail ret=-99  
kbox: load OK  
UBI: attaching mtd1 to ubi0  
UBI: scanning is finished  
UBI: attached mtd1 (name "ubilayer_v5", size 127 MiB) to ubi0  
UBI: PEB size: 131072 bytes (128 KiB), LEB size: 126976 bytes  
UBI: min./max. I/O unit sizes: 2048/2048, sub-page size 2048  
UBI: VID header offset: 2048 (aligned 2048), data offset: 4096  
UBI: good PEBs: 1016, bad PEBs: 0, corrupted PEBs: 0  
UBI: user volume: 10, internal volumes: 1, max. volumes count: 128  
UBI: max/mean erase counter: 3/1, WL threshold: 512, image sequence number: 8531 05020  
UBI: available PEBs: 5, total reserved PEBs: 1011, PEBs reserved for bad PEB han dling: 20  
UBI: background thread "ubi_bgt0d" started, PID 306  
Warning: unable to open an initial console.  
squashfs_cache_init: sqcachesize=8.  
VFS: Mounted root (squashfs filesystem) readonly on device 31:6.  
Freeing unused kernel memory: 176K (c0436000 - c0462000)  
******** Total Boot time: 1015 ms, uncompress initrd cost 0 ms ********  
Serial: 8250/16550 driver, 4 ports, IRQ sharing disabled  
1010e000.uart: ttyAMA0 at MMIO 0x1010e000 (irq = 77) is a 16550A
```
Seem UART not accepting any input, this more like debugging, bummer!

However, I interested with:
```
2 cmdlinepart partitions found on MTD device hinand  
Creating 2 MTD partitions on "hinand":  
0x000000000000-0x000000100000 : "bootcode"  
0x000000100000-0x000008000000 : "ubilayer_v5"
```
Have 2 partition `bootcode` and `ubilayer_v5`.
About `ubilayer_v5` seem like logical partition, trying to hide `jffs` root partition

## Issue #5
I thinking to extract flash memory, ONT I have using `MXIC MX35LF1GE4AB` 1Gb (128MiB) in size.
This flash memory have 8 pin:
```
1- CS#
2- SO/SIO1
3- WP#/SIO2
4- GND
5- SI/SIO0
6- SCLK
7- HOLD#/SIO3
8- VCC
```
At this moment, I dont have `PICkit 3` to read these

# Help
I want help from a community let's figure out to how to crack this ONT and remove any speed limit.

# To Do
1. Have `PICkit 3`
2. FS Decryption
