# Azure Storage Account Security Audit Tool 🔐

A comprehensive security auditing tool for Azure Storage Accounts that performs automated security checks, generates visual analytics, and provides detailed HTML reports across your entire Azure tenant.

![image](https://github.com/user-attachments/assets/da69e8ec-706d-49fd-92a6-5812be29a937)

## 🌟 Key Features

- **Comprehensive Security Scanning**: Audits all storage accounts across your Azure subscriptions
- **10+ Security Checks** including:
  - Secure transfer (HTTPS) requirements
  - Network access restrictions
  - TLS version verification
  - Blob public access settings
  - Encryption configurations
  - Diagnostic logging
  - Private endpoint configurations
  - Access tier optimization
  - Lifecycle management

- **Rich Visualizations & Reports**:
  - Interactive HTML dashboards
  - Risk distribution charts
  - Regional analysis
  - Subscription-level insights
  - CSV/JSON/Excel exports

## 📋 Prerequisites

```bash
Python 3.8+
Higly recommended to use Python 3.10
Azure Subscription
Azure CLI or credentials configured
```

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/azure-storage-audit.git
cd azure-storage-audit/Storage_Audit
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## 📦 Dependencies

```python
azure-identity
azure-mgmt-resource
azure-mgmt-storage
azure-mgmt-monitor
pandas
numpy
matplotlib
seaborn
colorama
tabulate
```

## 🚀 Usage

1. Ensure you're logged into Azure:
```bash
az login
```

2. Run the audit tool:
```bash
python storage_audit.py
```

3. Find reports in the `azure_storage_audit_reports` directory:
- HTML Report with interactive visualizations
- CSV export for detailed analysis
- JSON format for programmatic access
- Excel workbook with formatted results

## 📊 Sample Output

```
╭──────────────────────────────────────╮
│ 🔒 AZURE STORAGE ACCOUNT AUDIT 🔒
╰──────────────────────────────────────╯

✨ Found 150 storage accounts across 12 subscriptions
🔍 Analyzing security configurations...
📊 Generating visual reports...
```

## 🔍 Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Secure Transfer | High | Ensures HTTPS is required |
| Network Rules | High | Verifies public access restrictions |
| TLS Version | Medium | Validates minimum TLS 1.2 |
| Blob Access | High | Checks public blob access settings |
| Encryption | Medium | Verifies encryption configuration |

## 📈 Generated Reports

The tool generates comprehensive reports including:
- Risk level distribution
- Security check failure rates
- Regional distribution analysis
- Subscription risk assessment
- Detailed recommendations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Report Issues](https://github.com/Curious4Tech/azure-storage-audit/issues)
- [Feature Requests](https://github.com/Curious4Tech/azure-storage-audit/issues/new)

## ✨ Author

Created by Azizou GNANKPE - [@Curious4Tech](https://www.linkedin.com/in/azizou-gnankpe/)
