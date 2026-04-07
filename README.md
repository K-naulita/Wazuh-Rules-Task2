# Wazuh SIEM – Modul 2

| NRP        | Nama              |
|:-----------:|:-----------------:|
| 5025241021 | Kartika Nana Naulita           |

## Soal

1. Lakukan instalasi Wazuh Manager pada sebuah VM berbasis Linux (dianjurkan Ubuntu/Debian).
2. Lakukan instalasi Wazuh Agent pada satu perangkat lain, bebas menggunakan sistem operasi Windows atau Linux.
3. Pastikan agent berhasil terhubung ke manager dengan mengecek apakah default events/logs dari agent sudah masuk dan terlihat di dashboard Wazuh.
4. Buat/mencari dan implementasikan minimal 5 custom rules/custom alert pada agent kalian.
5. Buat dokumentasi penjelasan bagaimana kalian menyelesaikan penugasan modul 2 ini termasuk langkah instalasi manager dan agent, flow/diagram visualisasi deployment, validasi koneksi agent-manager, penjelasan masing-masing custom rule yang ditambahkan, dan screenshot hasil dari dashboard/alert yang menunjukkan rules tersebut aktif pada Github repository kalian.

---

## Jawaban

### Spesifikasi Lingkungan

| Komponen | Detail |
|----------|--------|
| **Manager** | VM Azure – IP: `20.195.8.104` |
| **Agent** | WSL – Ubuntu |
| **Dashboard** | https://20.195.8.104 |

---

## 1. Instalasi Wazuh Manager

Instalasi menggunakan script all-in-one resmi Wazuh (Manager + Indexer + Dashboard):
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

sudo bash wazuh-install.sh -a
```

Verifikasi:
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

Dashboard dapat diakses di: `https://20.195.8.104`

![img](https://i.imgur.com/bpAnMeZ.png)  
![img](https://i.imgur.com/CpKvkgb.png)  
![img](https://i.imgur.com/MqyoXGg.png)  
![img](https://i.imgur.com/2nvAIyA.png)  

---

## 2. Instalasi Wazuh Agent

Agent diinstal di WSL (Windows Subsystem for Linux):
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb && sudo WAZUH_MANAGER='20.195.8.104' WAZUH_AGENT_NAME='naulita' dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
![img](https://i.imgur.com/jKGwprN.png)  
![img](https://i.imgur.com/8T4C430.png)  
![img](https://i.imgur.com/bLJy7tr.png)  
![img](https://i.imgur.com/EKbhQft.png) 
---

## 3. Validasi Koneksi Agent-Manager

Cek dari Manager:
```bash
sudo /var/ossec/bin/agent_control -l
```
![img](https://i.imgur.com/tbk0U4B.png)

---

---

## 4. Custom Rules

Semua rule ditambahkan di Manager pada file:
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Setelah menambah/mengubah rule, selalu restart manager:
```bash
sudo systemctl restart wazuh-manager
```

---

### Rule 1 – SSH Brute Force Detection (ID: 100001)

**Deskripsi:** Mendeteksi percobaan login SSH gagal berulang (≥5 kali dalam 60 detik) dari IP yang sama.

```xml
<group name="sshd,authentication_failed,">
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_srcip />
    <description>SSH brute force: multiple failed logins from $(srcip)</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,pci_dss_10.2.4,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Tambahkan rule ke `local_rules.xml`, restart manager
2. Jalankan loop SSH gagal dari mesin lain:
```bash
for i in $(seq 1 10); do ssh -o BatchMode=yes -o ConnectTimeout=5 fakeuser@20.195.8.104; done
```
3. Cek dashboard: `rule.id:100001`

![img](https://i.imgur.com/wUM5eZI.png)
![img](https://i.imgur.com/ue3SaeL.png)
![img](https://i.imgur.com/a7oZlg5.png)
---

### Rule 2 – Sudo Privilege Escalation (ID: 100002)

**Deskripsi:** Mendeteksi user yang bukan bagian dari sudoers mencoba menjalankan perintah dengan sudo.

```xml
<group name="syslog,sudo,">
  <rule id="100002" level="10">
    <if_sid>5400</if_sid>
    <match>NOT in sudoers</match>
    <description>Sudo: unauthorized user tried to run a command as root</description>
    <mitre><id>T1548.003</id></mitre>
    <group>privilege_escalation,pci_dss_10.2.5,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Tambahkan rule ke `local_rules.xml`, restart manager
2. Buat user biasa di agent:
```bash
sudo adduser testuser
```
3. Login sebagai testuser:
```bash
su - testuser
```
4. Coba jalankan sudo:
```bash
sudo whoami
```
Muncul: `testuser is not in the sudoers file. This incident will be reported.`

5. Cek dashboard: `rule.id:100002`
6. Hapus user test:
```bash
sudo userdel -r testuser
```
![img](https://i.imgur.com/aqBrNlU.png)  
![img](https://i.imgur.com/2F2QGhp.png)  
![img](https://i.imgur.com/6It7NCQ.png)  
![img](https://i.imgur.com/BPovhwA.png)  
---

### Rule 3 – FIM Critical File Modification (ID: 100003)

**Deskripsi:** Mendeteksi modifikasi pada `/etc/passwd`, `/etc/shadow`, atau `/etc/sudoers` menggunakan modul Syscheck (FIM) Wazuh.

```xml
<group name="ossec,syscheck,">
  <rule id="100003" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/passwd|/etc/shadow|/etc/sudoers</field>
    <description>FIM: Critical auth file modified: $(file)</description>
    <mitre><id>T1098</id><id>T1003</id></mitre>
    <group>pci_dss_11.5,gdpr_II_5.1.f,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Pastikan FIM realtime aktif di `ossec.conf` agent:
```xml
<directories realtime="yes">/etc</directories>
```
2. Restart agent:
```bash
sudo systemctl restart wazuh-agent
```
3. Tambahkan rule, restart manager
4. Trigger di agent:
```bash
sudo bash -c 'echo "#test" >> /etc/passwd'
```
5. Cek dashboard: `rule.id:100003`
6. Bersihkan:
```bash
sudo sed -i '/#test/d' /etc/passwd
```
![img](https://i.imgur.com/iHedMUH.png)
---

### Rule 4 – SQL Injection Detection (ID: 100004)

**Deskripsi:** Mendeteksi pola SQL injection pada URL di log akses Apache.

```xml
<group name="web,accesslog,attack,">
  <rule id="100004" level="7">
    <if_sid>31103</if_sid>
    <url>select|union|insert|drop|update|1=1|--</url>
    <description>Web attack: possible SQL injection in request URL</description>
    <mitre><id>T1190</id></mitre>
    <group>attack,sql_injection,pci_dss_6.5.1,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Install Apache di agent:
```bash
sudo apt install apache2 -y
sudo systemctl enable --now apache2
```
2. Tambahkan log Apache ke `ossec.conf` agent:
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```
3. Fix permission:
```bash
sudo usermod -aG adm wazuh
sudo systemctl restart wazuh-agent
```
4. Tambahkan rule, restart manager
5. Trigger dari agent:
```bash
curl 'http://localhost/page?id=1%20UNION%20SELECT%201,2,3--'
```
6. Cek dashboard: `rule.id:100004`
![img](https://i.imgur.com/d0R7YGj.png)
![img](https://i.imgur.com/wg5mtUr.png)
![img](https://i.imgur.com/uO4GoGs.png)
---

### Rule 5 – Reverse Shell Detection (ID: 100005)

**Deskripsi:** Mendeteksi eksekusi perintah reverse shell seperti `bash -i` menggunakan Linux Audit (auditd).

```xml
<group name="audit,audit_command,">
  <rule id="100005" level="12">
    <if_sid>80700,80710,80711,80792</if_sid>
    <field name="audit.execve.a0">bash|sh|nc|python|perl</field>
    <field name="audit.execve.a1">-i|-e|-c</field>
    <description>Audit: possible reverse shell execution detected</description>
    <mitre><id>T1059.004</id><id>T1105</id></mitre>
    <group>attack,shell_injection,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Install auditd di agent:
```bash
sudo apt install auditd -y
sudo systemctl enable --now auditd
```
2. Tambahkan log audit ke `ossec.conf` agent:
```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```
3. Fix permission:
```bash
sudo usermod -aG adm wazuh
sudo systemctl restart wazuh-agent
```
4. Tambahkan audit rule:
```bash
sudo nano /etc/audit/rules.d/audit.rules
```
Tambahkan:
```
-a always,exit -F arch=b64 -S execve -k shell_commands
-a always,exit -F arch=b32 -S execve -k shell_commands
```
Load rules:
```bash
sudo augenrules --load
```
5. Tambahkan rule di manager, restart manager
6. Test reverse shell (2 terminal):

Terminal 1:
```bash
nc -lvp 4444
```
Terminal 2:
```bash
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
```
7. Cek dashboard: `rule.id:100005`
![img](https://i.imgur.com/1Uxg4q4.png)
![img](https://i.imgur.com/suzYwdU.png)
![img](https://i.imgur.com/trDByU1.png)
![img](https://i.imgur.com/tYR0V6W.png)
---

### Rule 6 – New User Account Created (ID: 100007)

**Deskripsi:** Mendeteksi pembuatan akun user baru di Linux via `useradd/adduser` sebagai indikasi backdoor account.

```xml
<group name="syslog,adduser,">
  <rule id="100007" level="8">
    <if_sid>5902</if_sid>
    <description>New user account created: $(dstuser)</description>
    <mitre><id>T1136.001</id></mitre>
    <group>account_management,pci_dss_10.2.5,gpg13_4.13,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Tambahkan rule, restart manager
2. Pastikan `auth.log` terpantau:
```bash
sudo grep -A2 "auth.log" /var/ossec/etc/ossec.conf
```
3. Trigger di agent:
```bash
sudo useradd -m backdooruser
```
4. Cek dashboard: `rule.id:100007`
5. Hapus user test:
```bash
sudo userdel -r backdooruser
```
![img](https://i.imgur.com/pIjfPsy.png)  
![img](https://i.imgur.com/qnv0AsV.png)
---

### Rule 7 – Rootkit/Trojan Detection (ID: 100008)

**Deskripsi:** Menggunakan modul Rootcheck Wazuh untuk mendeteksi proses tersembunyi, hidden ports, atau signature trojan.

```xml
<group name="ossec,rootcheck,">
  <rule id="100008" level="15">
    <if_sid>510,511,512,513</if_sid>
    <match>Process hiding|Rootkit|Trojan</match>
    <description>Rootcheck: possible rootkit/trojan on agent $(agent.name)</description>
    <mitre><id>T1014</id></mitre>
    <group>rootkit,gdpr_IV_35.7.d,pci_dss_11.4,</group>
  </rule>
</group>
```

**Langkah pengujian:**

1. Tambahkan rule, restart manager
2. Pastikan rootcheck aktif di `ossec.conf` agent:
```xml
<rootcheck>
  <disabled>no</disabled>
  <check_files>yes</check_files>
  <check_trojans>yes</check_trojans>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
</rootcheck>
```
3. Restart agent:
```bash
sudo systemctl restart wazuh-agent
```
4. Paksa scan dari manager:
```bash
sudo /var/ossec/bin/agent_control -r -a
```
5. Cek dashboard: `rule.id:100008`
![img](https://i.imgur.com/cHbaGm8.png)
![img](https://i.imgur.com/Liv41Zp.png)
---

## 5. Dokumentasi penjelasan pengerjaan penugasan modul 2
*Diagram Deployment*
```
┌───────────────────────────────────────┐
│        WAZUH SERVER (Manager)         |
│               VPS Azure               |
│        IP: 20.195.8.104               │
│  ┌──────────┐ ┌────────┐ ┌─────────┐  │
│  │ Indexer  │ │Manager │ │Dashboard│  │
│  │ :9200    │ │ :1514  │ │ :443    │  │
│  └──────────┘ └────────┘ └─────────┘  │
└──────────────────┬────────────────────┘
                   │ TCP 1514
          ┌────────┴────────┐
          │   WAZUH AGENT   │
          │   WSL (Local)   │
          │ 192.168.83.135  │
          └─────────────────┘
                   ^
                   │
          ┌────────┴────────┐
          │ ATTACKER/Client │ 
          └─────────────────┘
- Agent mengirim log ke manager
- Manager menganalisis menggunakan rules
- Dashboard menampilkan alert

```

## Referensi
- https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html
- https://github.com/wazuh/wazuh.git
- https://chatgpt.com/share/69d4ce4c-d79c-8323-a0dd-5360b8c3db44
