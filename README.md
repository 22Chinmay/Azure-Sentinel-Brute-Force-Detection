# Azure Sentinel – Brute Force Login Detection 🚨

## 📌 Project Overview
This project demonstrates a **cloud security monitoring solution** built using **Microsoft Sentinel** to detect and respond to **brute-force login attacks** on a Windows Virtual Machine hosted in Microsoft Azure.

The solution uses **Windows Security Event logs** and **KQL-based analytics rules** to automatically generate **high-severity security incidents**.

---

## 🛠 Technologies & Services Used
- Microsoft Azure
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Azure Virtual Machine (Windows Server)
- Kusto Query Language (KQL)

---

## 🏗 Architecture
- Windows VM generates security logs
- Logs are collected via Data Collection Rules
- Logs stored in Log Analytics Workspace
- Microsoft Sentinel analyzes logs
- Analytics rule detects brute-force attacks
- Incident is generated automatically

(Architecture diagram available in `/architecture` folder)

---

## 🔐 Detection Logic
Brute-force attacks are detected by monitoring **Event ID 4625**, which represents **failed Windows login attempts**.

If multiple failures occur from the same IP address within a short time window, a **high-severity alert** is raised.

---

## 📄 KQL Query Used
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress
| where FailedAttempts >= 5
