#!/usr/bin/env python3
"""
Azure Storage Account Security Audit Tool
-----------------------------------------
This script audits all storage accounts across an entire Azure tenant,
identifying security misconfigurations and providing visual analysis.
"""

import os
import sys
import json
import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.core.exceptions import HttpResponseError
from tqdm import tqdm
from colorama import init, Fore, Back, Style
from tabulate import tabulate

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

class AzureStorageAuditor:
    """Azure Storage Account Security Auditor"""
    
    def __init__(self):
        """Initialize the auditor with Azure credentials"""
        self.credential = DefaultAzureCredential()
        self.subscription_client = SubscriptionClient(self.credential)
        self.subscriptions = []
        self.storage_accounts = []
        self.audit_results = []
        self.df = None
        
        # Security check definitions with severity levels and descriptions
        self.security_checks = {
            'secure_transfer': {
                'severity': 'High',
                'description': 'Ensures secure transfer (HTTPS) is required',
                'recommendation': 'Enable the "Secure transfer required" option'
            },
            'network_acls': {
                'severity': 'High',
                'description': 'Checks if public network access is restricted',
                'recommendation': 'Configure network rules to restrict access'
            },
            'minimum_tls': {
                'severity': 'Medium',
                'description': 'Verifies minimum TLS version is 1.2',
                'recommendation': 'Set minimum TLS version to 1.2'
            },
            'blob_public_access': {
                'severity': 'High',
                'description': 'Checks if public blob access is disabled',
                'recommendation': 'Disable public access for blob containers'
            },
            'encryption_keytype': {
                'severity': 'Medium',
                'description': 'Verifies encryption with customer-managed keys',
                'recommendation': 'Consider using customer-managed keys'
            },
            'logging_enabled': {
                'severity': 'Medium', 
                'description': 'Checks if diagnostic logs are enabled',
                'recommendation': 'Enable diagnostic logging for storage accounts'
            },
            'https_only': {
                'severity': 'High',
                'description': 'Ensures that only HTTPS access is allowed',
                'recommendation': 'Enable "HTTPS Only" setting'
            },
            'private_endpoint': {
                'severity': 'Medium',
                'description': 'Checks if private endpoints are configured',
                'recommendation': 'Configure private endpoints for secure access'
            },
            'access_tier': {
                'severity': 'Low',
                'description': 'Verifies appropriate storage tier selection',
                'recommendation': 'Review access tier for cost optimization'
            },
            'lifecycle_policy': {
                'severity': 'Low',
                'description': 'Checks if lifecycle management is configured',
                'recommendation': 'Configure lifecycle policies for cost optimization'
            }
        }
  
        
    def print_welcome_message(self):
        # ASCII art for "Azure STORAGE AUDIT" in block style
        ascii_art = """
  █████╗ ███████╗██╗   ██╗██████╗ ███████╗    ███████╗████████╗ ██████╗ ██████╗  █████╗  ██████╗ ███████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██╔══██╗╚══███╔╝██║   ██║██╔══██╗██╔════╝    ██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ███████║  ███╔╝ ██║   ██║██████╔╝█████╗      ███████╗   ██║   ██║   ██║██████╔╝███████║██║  ███╗█████╗      ███████║██║   ██║██║  ██║██║   ██║   
 ██╔══██║ ███╔╝  ██║   ██║██╔══██╗██╔══╝      ╚════██║   ██║   ██║   ██║██╔══██╗██╔══██║██║   ██║██╔══╝      ██╔══██║██║   ██║██║  ██║██║   ██║   
 ██║  ██║███████╗╚██████╔╝██║  ██║███████╗    ███████║   ██║   ╚██████╔╝██║  ██║██║  ██║╚██████╔╝███████╗    ██║  ██║╚██████╔╝██████╔╝██║   ██║   
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
"""
        print(f"\n{Fore.GREEN}{ascii_art}{Style.RESET_ALL}")

    def create_rounded_box(self, text, padding=2):
        """Create a rounded box around text"""
        width = len(text) + padding * 2
        top = f"╭{'─' * width}╮"
        middle = f"│{' ' * padding}{text}{' ' * padding}│"
        bottom = f"╰{'─' * width}╯"
        return f"{top}\n{middle}\n{bottom}"

    def create_simple_rounded_header(self, text):
        """Create a simple rounded header"""
        width = len(text) + 4
        return f"╭{'─' * width}╮\n│ {text} │\n╰{'─' * width}╯"
    
    def authenticate(self):
        """Authenticate to Azure and get subscriptions"""
        print(f"{Fore.CYAN}{self.create_simple_rounded_header('🔑 Authenticating to Azure...')}{Style.RESET_ALL}")
        try:
            subscriptions = list(self.subscription_client.subscriptions.list())
            self.subscriptions = [
                {
                    'id': sub.subscription_id,
                    'name': sub.display_name,
                    'state': sub.state
                }
                for sub in subscriptions
            ]
            print(f"{Fore.GREEN}✓ Successfully authenticated. Found {len(self.subscriptions)} subscriptions.{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}✗ Authentication failed: {str(e)}{Style.RESET_ALL}")
            return False
            
    def list_storage_accounts(self):
        """List all storage accounts across all subscriptions"""
        print(f"{Fore.CYAN}Scanning storage accounts across all subscriptions...{Style.RESET_ALL}")
        total_accounts = 0
        
        # Progress bar for subscriptions
        for sub in tqdm(self.subscriptions, desc="Scanning subscriptions", unit="subscription"):
            if sub['state'] != 'Enabled':
                continue
                
            try:
                # Create client for this subscription
                storage_client = StorageManagementClient(
                    credential=self.credential,
                    subscription_id=sub['id']
                )
                
                # Get all storage accounts in this subscription
                accounts = list(storage_client.storage_accounts.list())
                
                for account in accounts:
                    self.storage_accounts.append({
                        'id': account.id,
                        'name': account.name,
                        'type': account.type,
                        'location': account.location,
                        'subscription_id': sub['id'],
                        'subscription_name': sub['name'],
                        'resource_group': account.id.split('/')[4],
                        'kind': account.kind,
                        'sku': account.sku.name,
                        'creation_time': account.creation_time,
                        'properties': account.as_dict()
                    })
                
                total_accounts += len(accounts)
                
            except Exception as e:
                print(f"{Fore.YELLOW}⚠ Error accessing subscription {sub['name']}: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}✓ Completed scan. Found {total_accounts} storage accounts across {len(self.subscriptions)} subscriptions.{Style.RESET_ALL}")
    
    def audit_storage_accounts(self):
        """Audit all storage accounts for security misconfigurations"""
        print(f"{Fore.CYAN}Auditing storage accounts for security misconfigurations...{Style.RESET_ALL}")
        
        for account in tqdm(self.storage_accounts, desc="Auditing storage accounts", unit="account"):
            try:
                storage_client = StorageManagementClient(
                    credential=self.credential,
                    subscription_id=account['subscription_id']
                )
                
                # Get detailed storage account info
                storage_account = storage_client.storage_accounts.get_properties(
                    account['resource_group'],
                    account['name']
                )
                
                # Get blob service properties
                try:
                    blob_service = storage_client.blob_services.get_service_properties(
                        account['resource_group'],
                        account['name']
                    )
                except:
                    blob_service = None
                
                # Get diagnostic settings
                try:
                    monitor_client = MonitorManagementClient(
                        credential=self.credential,
                        subscription_id=account['subscription_id']
                    )
                    diagnostic_settings = list(monitor_client.diagnostic_settings.list(account['id']))
                except:
                    diagnostic_settings = []
                
                # Perform security checks
                audit_result = {
                    'storage_account_id': account['id'],
                    'storage_account_name': account['name'],
                    'subscription_id': account['subscription_id'],
                    'subscription_name': account['subscription_name'],
                    'resource_group': account['resource_group'],
                    'location': account['location'],
                    'kind': account['kind'],
                    'sku': account['sku'],
                    'creation_time': account['creation_time'],
                    'checks': {}
                }
                
                # Check 1: Secure transfer required
                audit_result['checks']['secure_transfer'] = {
                    'passed': storage_account.enable_https_traffic_only,
                    'details': "Secure transfer is required" if storage_account.enable_https_traffic_only else "Secure transfer is not required",
                    'severity': self.security_checks['secure_transfer']['severity']
                }
                
                # Check 2: Network rules (public access)
                is_restricted = False
                if hasattr(storage_account, 'network_rule_set') and storage_account.network_rule_set:
                    is_restricted = storage_account.network_rule_set.default_action == "Deny"
                
                audit_result['checks']['network_acls'] = {
                    'passed': is_restricted,
                    'details': "Network access is restricted" if is_restricted else "Public network access is allowed",
                    'severity': self.security_checks['network_acls']['severity']
                }
                
                # Check 3: Minimum TLS version
                min_tls = getattr(storage_account, 'minimum_tls_version', None)
                is_tls12 = min_tls == 'TLS1_2'
                
                audit_result['checks']['minimum_tls'] = {
                    'passed': is_tls12,
                    'details': f"Minimum TLS version is {min_tls}" if min_tls else "Minimum TLS version not set",
                    'severity': self.security_checks['minimum_tls']['severity']
                }
                
                # Check 4: Blob public access
                allow_blob_public = getattr(storage_account, 'allow_blob_public_access', True)
                
                audit_result['checks']['blob_public_access'] = {
                    'passed': not allow_blob_public,
                    'details': "Blob public access is disabled" if not allow_blob_public else "Blob public access is enabled",
                    'severity': self.security_checks['blob_public_access']['severity']
                }
                
                # Check 5: Encryption key type
                encryption = getattr(storage_account, 'encryption', None)
                using_cmk = False
                if encryption and hasattr(encryption, 'key_source'):
                    using_cmk = encryption.key_source == 'Microsoft.Keyvault'
                
                audit_result['checks']['encryption_keytype'] = {
                    'passed': using_cmk,
                    'details': "Using customer-managed keys" if using_cmk else "Using Microsoft-managed keys",
                    'severity': self.security_checks['encryption_keytype']['severity']
                }
                
                # Check 6: Logging enabled
                has_logging = len(diagnostic_settings) > 0
                
                audit_result['checks']['logging_enabled'] = {
                    'passed': has_logging,
                    'details': f"Diagnostic settings configured ({len(diagnostic_settings)})" if has_logging else "No diagnostic settings configured",
                    'severity': self.security_checks['logging_enabled']['severity']
                }
                
                # Check 7: HTTPS only
                https_only = getattr(storage_account, 'enable_https_traffic_only', False)
                
                audit_result['checks']['https_only'] = {
                    'passed': https_only,
                    'details': "HTTPS-only traffic is enabled" if https_only else "HTTP traffic is allowed",
                    'severity': self.security_checks['https_only']['severity']
                }
                
                # Check 8: Private endpoints
                private_endpoints = []
                if hasattr(storage_account, 'private_endpoint_connections'):
                    private_endpoints = storage_account.private_endpoint_connections or []
                
                has_private_endpoints = len(private_endpoints) > 0
                
                audit_result['checks']['private_endpoint'] = {
                    'passed': has_private_endpoints,
                    'details': f"Has {len(private_endpoints)} private endpoint(s)" if has_private_endpoints else "No private endpoints configured",
                    'severity': self.security_checks['private_endpoint']['severity']
                }
                
                # Check 9: Access tier (for BlockBlobStorage and BlobStorage)
                access_tier = getattr(storage_account, 'access_tier', None)
                
                if account['kind'] in ['BlockBlobStorage', 'BlobStorage', 'StorageV2']:
                    is_appropriate = access_tier is not None  # Just checking if set for now
                    tier_info = f"Access tier is {access_tier}" if access_tier else "Access tier not set"
                else:
                    is_appropriate = True  # Not applicable
                    tier_info = "Access tier not applicable for this storage type"
                
                audit_result['checks']['access_tier'] = {
                    'passed': is_appropriate,
                    'details': tier_info,
                    'severity': self.security_checks['access_tier']['severity']
                }
                
                # Check 10: Lifecycle management
                has_lifecycle_policy = False
                if blob_service and hasattr(blob_service, 'management_policies') and blob_service.management_policies:
                    has_lifecycle_policy = True
                
                audit_result['checks']['lifecycle_policy'] = {
                    'passed': has_lifecycle_policy,
                    'details': "Lifecycle policy configured" if has_lifecycle_policy else "No lifecycle policy configured",
                    'severity': self.security_checks['lifecycle_policy']['severity']
                }
                
                # Add overall risk score (weighted by severity)
                severity_weights = {'High': 3, 'Medium': 2, 'Low': 1}
                total_weight = 0
                weighted_score = 0
                
                for check_name, check_result in audit_result['checks'].items():
                    severity = check_result['severity']
                    weight = severity_weights.get(severity, 1)
                    total_weight += weight
                    if check_result['passed']:
                        weighted_score += weight
                
                if total_weight > 0:
                    audit_result['compliance_score'] = (weighted_score / total_weight) * 100
                else:
                    audit_result['compliance_score'] = 0
                
                # Calculate risk level
                if audit_result['compliance_score'] >= 90:
                    audit_result['risk_level'] = 'Low'
                elif audit_result['compliance_score'] >= 70:
                    audit_result['risk_level'] = 'Medium'
                else:
                    audit_result['risk_level'] = 'High'
                
                self.audit_results.append(audit_result)
                
            except Exception as e:
                print(f"{Fore.YELLOW}⚠ Error auditing {account['name']}: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}✓ Completed audit of {len(self.audit_results)} storage accounts.{Style.RESET_ALL}")
    
    def analyze_results(self):
        """Convert audit results to DataFrame for analysis"""
        # Flatten the results for pandas
        flattened_results = []
        
        for result in self.audit_results:
            flat_result = {
                'storage_account_id': result['storage_account_id'],
                'storage_account_name': result['storage_account_name'],
                'subscription_id': result['subscription_id'],
                'subscription_name': result['subscription_name'],
                'resource_group': result['resource_group'],
                'location': result['location'],
                'kind': result['kind'],
                'sku': result['sku'],
                'creation_time': result['creation_time'],
                'compliance_score': result['compliance_score'],
                'risk_level': result['risk_level']
            }
            
            # Add each check as a separate column
            for check_name, check_data in result['checks'].items():
                flat_result[f'{check_name}_passed'] = check_data['passed']
                flat_result[f'{check_name}_details'] = check_data['details']
                flat_result[f'{check_name}_severity'] = check_data['severity']
            
            flattened_results.append(flat_result)
        
        # Convert to DataFrame
        self.df = pd.DataFrame(flattened_results)
        
        # Print summary
    
        print(f"Total storage accounts audited: {len(self.df)}")
        
        # Risk level distribution
        risk_counts = self.df['risk_level'].value_counts()
        print("\nRisk Level Distribution:")
        for risk, count in risk_counts.items():
            color = Fore.RED if risk == 'High' else Fore.YELLOW if risk == 'Medium' else Fore.GREEN
            print(f"{color}{risk} Risk: {count} accounts ({count/len(self.df)*100:.1f}%){Style.RESET_ALL}")
        
        # Check failure rates
        print("\nTop security issues:")
        check_columns = [col for col in self.df.columns if col.endswith('_passed')]
        for check in check_columns:
            check_name = check.replace('_passed', '')
            fail_rate = (1 - self.df[check].mean()) * 100
            if fail_rate > 0:
                severity = self.df[f'{check_name}_severity'].iloc[0]
                color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.BLUE
                print(f"{color}{self.security_checks[check_name]['description']}: {fail_rate:.1f}% fail rate ({severity} severity){Style.RESET_ALL}")
    
    def generate_visualizations(self):
        """Generate visualizations of audit results"""
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("viridis")
        
        # Create a directory for reports if it doesn't exist
        report_dir = "azure_storage_audit_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Overall compliance score distribution
        plt.figure(figsize=(10, 6))
        sns.histplot(self.df['compliance_score'], bins=10, kde=True)
        plt.axvline(x=90, color='green', linestyle='--', label='Low Risk Threshold (90%)')
        plt.axvline(x=70, color='orange', linestyle='--', label='Medium Risk Threshold (70%)')
        plt.title('Storage Account Compliance Score Distribution', fontsize=16)
        plt.xlabel('Compliance Score (%)', fontsize=12)
        plt.ylabel('Number of Storage Accounts', fontsize=12)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{report_dir}/compliance_score_distribution_{timestamp}.png", dpi=300)
        
        # 2. Risk level distribution
        plt.figure(figsize=(10, 6))
        risk_counts = self.df['risk_level'].value_counts()
        colors = ['green' if x == 'Low' else 'orange' if x == 'Medium' else 'red' for x in risk_counts.index]
        sns.barplot(x=risk_counts.index, y=risk_counts.values, hue=risk_counts.index, palette=colors, legend=False)
        plt.title('Risk Level Distribution', fontsize=16)
        plt.xlabel('Risk Level', fontsize=12)
        plt.ylabel('Number of Storage Accounts', fontsize=12)
        for i, v in enumerate(risk_counts.values):
            plt.text(i, v + 0.1, str(v), ha='center', fontsize=12)
        plt.tight_layout()
        plt.savefig(f"{report_dir}/risk_level_distribution_{timestamp}.png", dpi=300)
        
        # 3. Security check failure rates
        plt.figure(figsize=(12, 8))
        check_columns = [col for col in self.df.columns if col.endswith('_passed')]
        check_names = [col.replace('_passed', '') for col in check_columns]
        failure_rates = [(1 - self.df[col].mean()) * 100 for col in check_columns]
        
        # Create DataFrame for visualization
        check_df = pd.DataFrame({
            'check': [self.security_checks[name]['description'] for name in check_names],
            'failure_rate': failure_rates,
            'severity': [self.security_checks[name]['severity'] for name in check_names]
        })
        
        # Sort by failure rate
        check_df = check_df.sort_values('failure_rate', ascending=False)
        
        # Create colors based on severity
        colors = {'High': 'red', 'Medium': 'orange', 'Low': 'green'}
        check_colors = [colors[severity] for severity in check_df['severity']]
        
        # Create the bar chart
        ax = sns.barplot(x='failure_rate', y='check', hue='severity', data=check_df, palette=colors, legend=False)
        plt.title('Security Check Failure Rates', fontsize=16)
        plt.xlabel('Failure Rate (%)', fontsize=12)
        plt.ylabel('Security Check', fontsize=12)
        
        # Add percentage labels
        for i, v in enumerate(check_df['failure_rate']):
            if v > 0:
                ax.text(v + 0.5, i, f"{v:.1f}%", va='center', fontsize=10)
        
        # Add severity legend
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], color='red', lw=4, label='High Severity'),
            Line2D([0], [0], color='orange', lw=4, label='Medium Severity'),
            Line2D([0], [0], color='green', lw=4, label='Low Severity')
        ]
        ax.legend(handles=legend_elements, loc='lower right')
        
        plt.tight_layout()
        plt.savefig(f"{report_dir}/security_check_failures_{timestamp}.png", dpi=300)
        
        # 4. Regional distribution
        plt.figure(figsize=(12, 8))
        location_counts = self.df['location'].value_counts().head(10)  # Top 10 regions
        sns.barplot(x=location_counts.values, y=location_counts.index)
        plt.title('Storage Accounts by Region (Top 10)', fontsize=16)
        plt.xlabel('Number of Storage Accounts', fontsize=12)
        plt.ylabel('Region', fontsize=12)
        for i, v in enumerate(location_counts.values):
            plt.text(v + 0.1, i, str(v), va='center', fontsize=10)
        plt.tight_layout()
        plt.savefig(f"{report_dir}/regional_distribution_{timestamp}.png", dpi=300)
        
        # 5. Subscription distribution with risk levels
        plt.figure(figsize=(14, 10))
        sub_risk = self.df.groupby('subscription_name')['risk_level'].value_counts().unstack().fillna(0)
        
        # Sort by total number of accounts
        sub_risk['total'] = sub_risk.sum(axis=1)
        sub_risk = sub_risk.sort_values('total', ascending=False).head(10)  # Top 10 subscriptions
        sub_risk = sub_risk.drop('total', axis=1)
        
        # Ensure all risk levels are present
        for risk in ['High', 'Medium', 'Low']:
            if risk not in sub_risk.columns:
                sub_risk[risk] = 0
        
        # Plot
        ax = sub_risk[['High', 'Medium', 'Low']].plot(
            kind='barh', 
            stacked=True, 
            color=['red', 'orange', 'green'],
            figsize=(14, 10)
        )
        plt.title('Risk Distribution by Subscription (Top 10)', fontsize=16)
        plt.xlabel('Number of Storage Accounts', fontsize=12)
        plt.ylabel('Subscription', fontsize=12)
        plt.legend(title='Risk Level')
        
        # Add total count labels
        for i, subscription in enumerate(sub_risk.index):
            total = sub_risk.loc[subscription].sum()
            plt.text(total + 0.1, i, f"Total: {int(total)}", va='center', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(f"{report_dir}/subscription_risk_distribution_{timestamp}.png", dpi=300)
        
        # 6. Storage account types with compliance scores
        plt.figure(figsize=(10, 6))
        sns.boxplot(x='kind', y='compliance_score', data=self.df)
        plt.title('Compliance Score by Storage Account Type', fontsize=16)
        plt.xlabel('Storage Account Type', fontsize=12)
        plt.ylabel('Compliance Score (%)', fontsize=12)
        plt.axhline(y=90, color='green', linestyle='--', label='Low Risk Threshold (90%)')
        plt.axhline(y=70, color='orange', linestyle='--', label='Medium Risk Threshold (70%)')
        plt.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{report_dir}/compliance_by_type_{timestamp}.png", dpi=300)
        
        print(f"{Fore.GREEN}✓ Visualizations saved to '{report_dir}' directory.{Style.RESET_ALL}")
    
    def export_results(self):
        """Export audit results to various formats"""
        print(f"\n{Fore.CYAN}{self.create_simple_rounded_header('📤 Exporting Audit Results...')}{Style.RESET_ALL}")
        
        # Create a directory for reports if it doesn't exist
        report_dir = "azure_storage_audit_reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # 1. Export to CSV
        csv_file = f"{report_dir}/azure_storage_audit_{timestamp}.csv"
        self.df.to_csv(csv_file, index=False)
        
        # 2. Export to Excel with formatting
        try:
            excel_file = f"{report_dir}/azure_storage_audit_{timestamp}.xlsx"
            writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')
            self.df.to_excel(writer, sheet_name='Audit Results', index=False)
            
            # Get the xlsxwriter workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Audit Results']
            
            # Add formats
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'bg_color': '#4472C4',
                'font_color': 'white',
                'border': 1
            })
            
            pass_format = workbook.add_format({'bg_color': '#C6EFCE'})
            fail_format = workbook.add_format({'bg_color': '#FFC7CE'})
            
            # Apply header format
            for col_num, value in enumerate(self.df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Set column widths
            worksheet.set_column('A:Z', 20)
            
            # Add conditional formatting for pass/fail columns
            for col_num, column in enumerate(self.df.columns):
                if column.endswith('_passed'):
                    worksheet.conditional_format(1, col_num, len(self.df), col_num, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': True,
                        'format': pass_format
                    })
                    worksheet.conditional_format(1, col_num, len(self.df), col_num, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': False,
                        'format': fail_format
                    })
            
            writer._save()
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Error creating Excel report: {str(e)}{Style.RESET_ALL}")
        
        # 3. Export to JSON
        json_file = f"{report_dir}/azure_storage_audit_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.audit_results, f, default=str, indent=2)
        
        # 4. Generate HTML report
        html_file = f"{report_dir}/azure_storage_audit_{timestamp}.html"
        
        # Create a copy of the DataFrame for HTML display
        html_df = self.df.copy()
        
        # Create HTML content
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Azure Storage Account Security Audit Report</title>
            <style>
            body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; margin: 0; padding: 20px; }}
            h1, h2, h3 {{ color: #0078D4; font-weight: 600; }}
            .summary {{ margin-bottom: 30px; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .summary-table {{ border-collapse: collapse; width: 50%; border-radius: 8px; overflow: hidden; box-shadow: 0 0 20px rgba(0,0,0,0.05); }}
            .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .summary-table th {{ background-color: #0078D4; color: white; text-transform: uppercase; font-size: 0.875rem; }}
            .high {{ color: #E81123; font-weight: bold; }}
            .medium {{ color: #FF8C00; font-weight: bold; }}
            .low {{ color: #107C10; font-weight: bold; }}
            .pass {{ background-color: #DFF0D8; }}
            .fail {{ background-color: #F2DEDE; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; overflow-x: auto; border-radius: 8px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px 8px; text-align: left; }}
            th {{ background-color: #0078D4; color: white; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            tr:hover {{ background-color: #f0f0f0; }}
            .report-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
            .report-header img {{ height: 50px; }}
            .timestamp {{ font-style: italic; color: #666; font-size: 0.9rem; }}
            .section {{ margin-top: 40px; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .chart-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; margin: 20px 0; }}
            .chart {{ background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .chart img {{ max-width: 100%; height: auto; border-radius: 8px; }}
            .recommendation {{ background-color: #E5F1FB; padding: 15px; border-left: 4px solid #0078D4; margin-top: 20px; border-radius: 0 10px 10px 0; }}
            @media (max-width: 768px) {{
                .summary-table {{ width: 100%; }}
                .chart-container {{ grid-template-columns: 1fr; }}
            }}
        </style>
        </head>
        <body>
            <div class="report-header">
                <div>
                    <h1>Azure Storage Account Security Audit Report</h1>
                    <p class="timestamp">Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </div>
            
            <div class="summary section">
                <h2>Executive Summary</h2>
                <p>This report presents the results of a security audit performed on {len(self.df)} storage accounts across {len(self.df['subscription_id'].unique())} Azure subscriptions.</p>
                
                <table class="summary-table">
                    <tr>
                        <th>Risk Level</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
        """

        # Add risk level rows
        for risk, count in self.df['risk_level'].value_counts().items():
            percentage = count/len(self.df)*100
            html_content += f"""
                    <tr>
                        <td class="{risk.lower()}">{risk} Risk</td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
        """

        html_content += """
                </table>
                
                <h3>Top Security Issues</h3>
                <ul>
        """

        # Add security issues
        for check_name in [col for col in self.df.columns if col.endswith('_passed')]:
            base_name = check_name.replace('_passed', '')
            failure_rate = (1-self.df[check_name].mean())*100
            if failure_rate > 0:
                severity = self.df[f'{base_name}_severity'].iloc[0].lower()
                description = self.security_checks[base_name]['description']
                severity_label = self.df[f'{base_name}_severity'].iloc[0]
                html_content += f"""
                    <li class="{severity}">
                        {description}: 
                        {failure_rate:.1f}% fail rate 
                        ({severity_label} severity)
                    </li>
        """
        
        html_content += f"""
                 <div class="recommendations section">
                <h2>Security Recommendations</h2>
        """

        # Add recommendations
        for check_name in self.security_checks.keys():
            failure_rate = (1-self.df[f'{check_name}_passed'].mean())*100
            if failure_rate > 0:
                html_content += f"""
                <div class="recommendation">
                    <h3>{self.security_checks[check_name]['description']}</h3>
                    <p><strong>Severity:</strong> {self.security_checks[check_name]['severity']}</p>
                    <p><strong>Failure Rate:</strong> {failure_rate:.1f}%</p>
                    <p><strong>Recommendation:</strong> {self.security_checks[check_name]['recommendation']}</p>
                </div>
        """

        html_content += """
            </div>
            
            <div class="detailed-results section">
                <h2>Detailed Audit Results</h2>
                <p>The table below presents detailed audit results for all storage accounts.</p>
        """

        # Add the DataFrame HTML table
        html_content += self.df.to_html(
            columns=['storage_account_name', 'subscription_name', 'resource_group', 'location', 'compliance_score', 'risk_level'],
            classes='dataframe',
            index=False
        )

        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}✓ Audit results exported to '{report_dir}' directory:{Style.RESET_ALL}")
        print(f"  - CSV: {os.path.basename(csv_file)}")
        print(f"  - JSON: {os.path.basename(json_file)}")
        print(f"  - HTML Report: {os.path.basename(html_file)}")
        if 'excel_file' in locals():
            print(f"  - Excel: {os.path.basename(excel_file)}")
    
    def print_high_risk_accounts(self):
        """Print details of high-risk storage accounts"""
        high_risk = self.df[self.df['risk_level'] == 'High']
        
        if len(high_risk) == 0:
            print(f"{Fore.GREEN}✓ No high-risk storage accounts found.{Style.RESET_ALL}")
            return
        
        # Create a simplified table for display
        display_columns = ['storage_account_name', 'subscription_name', 'resource_group', 'compliance_score']
        table = high_risk[display_columns].sort_values('compliance_score')
        
        # Add failed checks column
        def get_failed_checks(row):
            failed_checks = []
            for col in [c for c in self.df.columns if c.endswith('_passed')]:
                check_name = col.replace('_passed', '')
                if not row[col]:
                    severity = row[f'{check_name}_severity']
                    failed_checks.append(f"{check_name} ({severity})")
            return ", ".join(failed_checks)
        
        table['failed_checks'] = high_risk.apply(get_failed_checks, axis=1)
        
        # Print table
        print(tabulate(table, headers='keys', tablefmt='grid'))
        
        print(f"\n{Fore.YELLOW}Recommendation: Address security issues in these high-risk storage accounts as a priority.{Style.RESET_ALL}")
    
    def run_audit(self):
        """Run the complete audit process"""
        # Welcome message with current date/time and user info
        current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\nCurrent Date and Time (UTC): {current_time}")
        print(f"Current User's Login: {os.getenv('USERNAME', 'Unknown')}\n")
  
        print(f"{Fore.CYAN}Starting comprehensive security audit of Azure storage accounts...{Style.RESET_ALL}")
        
        if not self.authenticate():
            print(f"{Fore.RED}Authentication failed. Exiting audit.{Style.RESET_ALL}")
            return
        
        # Authentication header
        print(f"{Fore.CYAN}{self.create_simple_rounded_header('🔍 Scanning Storage Accounts ...')}{Style.RESET_ALL}")
        
        self.list_storage_accounts()
        
        if len(self.storage_accounts) == 0:
            print(f"{Fore.YELLOW}No storage accounts found. Exiting audit.{Style.RESET_ALL}")
            return
        
        # Scanning header
        print(f"{Fore.CYAN}{self.create_simple_rounded_header('🔍 Auditing Storage Accounts ...')}{Style.RESET_ALL}")
        
        self.audit_storage_accounts()
        
        # Analysis header
        print(f"\n{Fore.CYAN}{self.create_rounded_box('📋 AUDIT SUMMARY')}{Style.RESET_ALL}")
        
        self.analyze_results()
        
        # Visualizations header
        print(f"{Fore.CYAN}{self.create_simple_rounded_header('📊 Generating Visualizations...')}{Style.RESET_ALL}")
        
        self.generate_visualizations()
        
        # High risk accounts header
        high_risk_count = len(self.df[self.df['risk_level'] == 'High'])
        print(f"\n{Fore.RED}{self.create_rounded_box(f'⚠️ HIGH RISK STORAGE ACCOUNTS ({high_risk_count})')}{Style.RESET_ALL}")
        
        self.print_high_risk_accounts()
        self.export_results()
        
        # Completion message
        print(f"\n{Fore.GREEN}{self.create_rounded_box('✅ AUDIT COMPLETED SUCCESSFULLY')}{Style.RESET_ALL}")
        print(f"Audit reports and visualizations are available in the 'azure_storage_audit_reports' directory.")
        print(f"\n{Fore.CYAN}{self.create_simple_rounded_header('🙏 Thank you for using Azure Storage Account Security Audit Tool developped by Curious4tech')}{Style.RESET_ALL}")
if __name__ == "__main__":
    try:
        auditor = AzureStorageAuditor()
        auditor.print_welcome_message()
        auditor.run_audit()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Audit process interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error during audit process: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()