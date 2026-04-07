# Wazuh SIEM – Modul 2

## Soal

1. Lakukan instalasi Wazuh Manager pada sebuah VM berbasis Linux (dianjurkan Ubuntu/Debian).
2. Lakukan instalasi Wazuh Agent pada satu perangkat lain, bebas menggunakan sistem operasi Windows atau Linux.
3. Pastikan agent berhasil terhubung ke manager dengan mengecek apakah default events/logs dari agent sudah masuk dan terlihat di dashboard Wazuh.
4. Buat/mencari dan implementasikan minimal 5 custom rules/custom alert pada agent kalian.
5. Buat sebuah dokumentasi penjelasan bagaimana kalian menyelesaikan penugasan modul 2 ini termasuk langkah instalasi manager dan agent, flow/diagram visualisasi deployment, validasi koneksi agent-manager, penjelasan masing-masing custom rule yang ditambahkan, dan screenshot hasil dari dashboard/alert yang menunjukkan rules tersebut aktif.

---

## Jawaban

### Spesifikasi Lingkungan

| Komponen | Detail |
|----------|--------|
| **Manager** | Azure VM – Ubuntu 22.04 – IP: 20.195.8.104 |
| **Agent** | WSL Ubuntu (lokal) |
| **Wazuh Version** | 4.7.5 |
| **Dashboard** | https://20.195.8.104 |

---

## 1. Instalasi Wazuh Manager (Azure VM)

Instalasi menggunakan script all-in-one resmi Wazuh yang menginstal Manager, Indexer, dan Dashboard sekaligus.
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
# Edit config.yml sesuaikan IP
sudo bash wazuh-install.sh -a
```

Verifikasi:
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

---

## 2. Instalasi Wazuh Agent (WSL)
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb && sudo WAZUH_MANAGER='20.195.8.104' WAZUH_AGENT_NAME='naulita' dpkg -i ./wazuh-agent_4.7.5-1_amd64.deb

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## 3. Validasi Koneksi Agent-Manager

Cek dari Manager:
```bash
sudo /var/ossec/bin/agent_control -l
```

Output yang diharapkan:
---

## 4. Custom Rules

Semua rule ditambahkan di Manager pada file:
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
Setelah setiap perubahan, restart manager:
```bash
sudo systemctl restart wazuh-manager
```

---

### Rule 1 – SSH Brute Force Detection (ID: 100001)

**Deskripsi:** Mendeteksi percobaan login SSH gagal berulang (≥5 kali dalam 60 detik) dari IP yang sama.

**Sumber:**
- https://github.com/wazuh/wazuh/blob/master/ruleset/rules/0095-sshd_rules.xml
- https://documentation.wazuh.com/current/user-manual/ruleset/custom.html
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

**Langkah menjalankan:**

1. Tambahkan rule ke `local_rules.xml`, restart manager
2. Jalankan loop SSH gagal dari mesin lain:
```bash
for i in $(seq 1 10); do ssh -o BatchMode=yes -o ConnectTimeout=5 fakeuser@20.195.8.104; done
```
3. Cek Dashboard → Security Events → filter `rule.id:100001`

---

### Rule 2 – Sudo Privilege Escalation (ID: 100002)

**Deskripsi:** Mendeteksi user yang bukan bagian dari sudoers mencoba menjalankan perintah dengan sudo.

**Sumber:**
- https://github.com/wazuh/wazuh/blob/master/ruleset/rules/0280-syslog_rules.xml
- https://attack.mitre.org/techniques/T1548/003/
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

**Langkah menjalankan:**

1. Tambahkan rule, restart manager
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

5. Cek Dashboard → filter `rule.id:100002`
6. Hapus user test:
```bash
sudo userdel -r testuser
```

---

### Rule 3 – FIM Critical File Modification (ID: 100003)

**Deskripsi:** Mendeteksi modifikasi pada `/etc/passwd`, `/etc/shadow`, atau `/etc/sudoers` menggunakan modul Syscheck (FIM) Wazuh.

**Sumber:**
- https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
- https://github.com/wazuh/wazuh/blob/master/ruleset/rules/0550-syscheck_rules.xml
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

**Langkah menjalankan:**

1. Aktifkan FIM realtime di `ossec.conf` agent:
```xml
<directories realtime="yes">/etc</directories>
```
2. Restart agent:
```bash
sudo systemctl restart wazuh-agent
```
3. Tambahkan rule, restart manager
4. Tunggu 1-2 menit untuk FIM baseline, lalu trigger:
```bash
sudo bash -c 'echo "#test" >> /etc/passwd'
```
5. Cek Dashboard → filter `rule.id:100003`
6. Bersihkan setelah test:
```bash
sudo sed -i '/#test/d' /etc/passwd
```

---

### Rule 4 – SQL Injection Detection (ID: 100004)

**Deskripsi:** Mendeteksi pola SQL injection pada URL di log akses Apache.

**Sumber:**
- https://github.com/wazuh/wazuh/blob/master/ruleset/rules/0245-nginx_rules.xml
- https://owasp.org/www-community/attacks/SQL_Injection
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

**Langkah menjalankan:**

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
3. Fix permission agar Wazuh bisa baca log:
```bash
sudo usermod -aG adm wazuh
sudo systemctl restart wazuh-agent
```
4. Tambahkan rule, restart manager
5. Trigger SQL injection:
```bash
curl 'http://localhost/page?id=1%20UNION%20SELECT%201,2,3--'
```
6. Cek Dashboard → filter `rule.id:100004`

---

### Rule 5 – Reverse Shell Detection (ID: 100005)

**Deskripsi:** Memantau Linux Audit (auditd) untuk mendeteksi eksekusi perintah reverse shell seperti `bash -i`, `nc -e`.

**Sumber:**
- https://github.com/wazuh/wazuh/blob/master/ruleset/rules/0365-audit_rules.xml
- https://attack.mitre.org/techniques/T1059/004/
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

**Langkah menjalankan:**

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
