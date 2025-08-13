# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Configuration migration utility for Google Ads OneShop.

This module provides utilities to migrate from single-email to multi-email
authentication configurations and validate the migration process.
"""

import os
import shutil
import yaml
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class MigrationError(Exception):
    """Raised when migration fails."""
    pass


class ConfigMigrator:
    """Handles migration between single-email and multi-email configurations."""
    
    def __init__(self, config_path: str):
        """Initialize the migrator.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.backup_dir = os.path.join(os.path.dirname(config_path), 'config_backups')
    
    def backup_existing_config(self) -> str:
        """Create backup of existing configuration.
        
        Returns:
            Path to the backup file
        """
        if not os.path.exists(self.config_path):
            raise MigrationError(f"Configuration file not found: {self.config_path}")
        
        # Create backup directory if it doesn't exist
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"appsecrets_backup_{timestamp}.yaml"
        backup_path = os.path.join(self.backup_dir, backup_filename)
        
        # Copy the file
        shutil.copy2(self.config_path, backup_path)
        logger.info(f"Configuration backed up to: {backup_path}")
        
        return backup_path
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file.
        
        Args:
            config_path: Path to config file (uses instance path if None)
            
        Returns:
            Configuration dictionary
        """
        path = config_path or self.config_path
        
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise MigrationError(f"Configuration file not found: {path}")
        except yaml.YAMLError as e:
            raise MigrationError(f"Invalid YAML in configuration file: {e}")
    
    def save_config(self, config: Dict[str, Any], config_path: Optional[str] = None) -> None:
        """Save configuration to file.
        
        Args:
            config: Configuration dictionary to save
            config_path: Path to save to (uses instance path if None)
        """
        path = config_path or self.config_path
        
        try:
            with open(path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration saved to: {path}")
        except Exception as e:
            raise MigrationError(f"Failed to save configuration: {e}")
    
    def detect_config_type(self, config: Optional[Dict[str, Any]] = None) -> str:
        """Detect the type of configuration.
        
        Args:
            config: Configuration dictionary (loads from file if None)
            
        Returns:
            Configuration type: 'single_email', 'multi_email', or 'unknown'
        """
        if config is None:
            config = self.load_config()
        
        # Check for explicit auth_mode
        auth_mode = config.get('auth_mode')
        if auth_mode in ['single_email', 'multi_email']:
            return auth_mode
        
        # Auto-detect based on structure
        has_service_sections = 'google_ads' in config or 'merchant_center' in config
        has_legacy_fields = all(field in config for field in ['client_id', 'client_secret'])
        
        if has_service_sections:
            return 'multi_email'
        elif has_legacy_fields:
            return 'single_email'
        else:
            return 'unknown'
    
    def migrate_single_to_multi_config(self, 
                                     google_ads_refresh_token: str,
                                     merchant_center_refresh_token: str,
                                     developer_token: Optional[str] = None) -> Dict[str, Any]:
        """Migrate single-email config to multi-email format.
        
        Args:
            google_ads_refresh_token: Refresh token for Google Ads
            merchant_center_refresh_token: Refresh token for Merchant Center
            developer_token: Google Ads developer token (optional)
            
        Returns:
            New multi-email configuration dictionary
        """
        current_config = self.load_config()
        config_type = self.detect_config_type(current_config)
        
        if config_type == 'multi_email':
            raise MigrationError("Configuration is already in multi-email format")
        elif config_type == 'unknown':
            raise MigrationError("Cannot migrate unknown configuration format")
        
        # Extract legacy credentials
        client_id = current_config.get('client_id')
        client_secret = current_config.get('client_secret')
        current_developer_token = current_config.get('developer_token', '')
        
        if not client_id or not client_secret:
            raise MigrationError("Legacy configuration is missing required fields")
        
        # Use provided developer token or fall back to current one
        final_developer_token = developer_token or current_developer_token
        
        # Create new multi-email configuration
        new_config = {
            'auth_mode': 'multi_email',
            'google_ads': {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': google_ads_refresh_token,
                'developer_token': final_developer_token
            },
            'merchant_center': {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': merchant_center_refresh_token
            }
        }
        
        # Preserve any additional fields from original config
        for key, value in current_config.items():
            if key not in ['client_id', 'client_secret', 'developer_token', 'auth_mode']:
                new_config[key] = value
        
        return new_config
    
    def migrate_multi_to_single_config(self, 
                                     refresh_token: str,
                                     developer_token: Optional[str] = None) -> Dict[str, Any]:
        """Migrate multi-email config to single-email format.
        
        Args:
            refresh_token: Single refresh token for both services
            developer_token: Google Ads developer token (optional)
            
        Returns:
            New single-email configuration dictionary
        """
        current_config = self.load_config()
        config_type = self.detect_config_type(current_config)
        
        if config_type == 'single_email':
            raise MigrationError("Configuration is already in single-email format")
        elif config_type == 'unknown':
            raise MigrationError("Cannot migrate unknown configuration format")
        
        # Extract credentials from multi-email config
        google_ads_config = current_config.get('google_ads', {})
        client_id = google_ads_config.get('client_id')
        client_secret = google_ads_config.get('client_secret')
        current_developer_token = google_ads_config.get('developer_token', '')
        
        if not client_id or not client_secret:
            # Try merchant_center config as fallback
            merchant_center_config = current_config.get('merchant_center', {})
            client_id = client_id or merchant_center_config.get('client_id')
            client_secret = client_secret or merchant_center_config.get('client_secret')
        
        if not client_id or not client_secret:
            raise MigrationError("Multi-email configuration is missing required credentials")
        
        # Use provided developer token or fall back to current one
        final_developer_token = developer_token or current_developer_token
        
        # Create new single-email configuration
        new_config = {
            'client_id': client_id,
            'client_secret': client_secret,
            'developer_token': final_developer_token,
            'refresh_token': refresh_token,
            'auth_mode': 'single_email'
        }
        
        # Preserve any additional fields from original config
        for key, value in current_config.items():
            if key not in ['google_ads', 'merchant_center', 'auth_mode']:
                new_config[key] = value
        
        return new_config
    
    def validate_migration(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate that migration preserves functionality.
        
        Args:
            old_config: Original configuration
            new_config: New configuration after migration
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        old_type = self.detect_config_type(old_config)
        new_type = self.detect_config_type(new_config)
        
        # Check that migration changed the type
        if old_type == new_type:
            issues.append(f"Configuration type did not change (still {old_type})")
        
        # Validate required fields based on new type
        if new_type == 'single_email':
            required_fields = ['client_id', 'client_secret', 'refresh_token']
            for field in required_fields:
                if field not in new_config or not new_config[field]:
                    issues.append(f"Missing required field for single-email: {field}")
        
        elif new_type == 'multi_email':
            # Check Google Ads section
            if 'google_ads' not in new_config:
                issues.append("Missing google_ads section in multi-email config")
            else:
                ga_config = new_config['google_ads']
                required_ga_fields = ['client_id', 'client_secret', 'refresh_token']
                for field in required_ga_fields:
                    if field not in ga_config or not ga_config[field]:
                        issues.append(f"Missing required Google Ads field: {field}")
            
            # Check Merchant Center section
            if 'merchant_center' not in new_config:
                issues.append("Missing merchant_center section in multi-email config")
            else:
                mc_config = new_config['merchant_center']
                required_mc_fields = ['client_id', 'client_secret', 'refresh_token']
                for field in required_mc_fields:
                    if field not in mc_config or not mc_config[field]:
                        issues.append(f"Missing required Merchant Center field: {field}")
        
        return len(issues) == 0, issues
    
    def perform_migration(self, 
                         target_type: str,
                         **kwargs) -> Dict[str, Any]:
        """Perform complete migration with backup and validation.
        
        Args:
            target_type: Target configuration type ('single_email' or 'multi_email')
            **kwargs: Additional arguments for migration functions
            
        Returns:
            Migration result dictionary
        """
        result = {
            'success': False,
            'backup_path': None,
            'old_config_type': None,
            'new_config_type': None,
            'issues': []
        }
        
        try:
            # Load current configuration
            old_config = self.load_config()
            result['old_config_type'] = self.detect_config_type(old_config)
            
            # Create backup
            result['backup_path'] = self.backup_existing_config()
            
            # Perform migration based on target type
            if target_type == 'multi_email':
                if 'google_ads_refresh_token' not in kwargs or 'merchant_center_refresh_token' not in kwargs:
                    raise MigrationError("Multi-email migration requires google_ads_refresh_token and merchant_center_refresh_token")
                
                new_config = self.migrate_single_to_multi_config(
                    kwargs['google_ads_refresh_token'],
                    kwargs['merchant_center_refresh_token'],
                    kwargs.get('developer_token')
                )
            
            elif target_type == 'single_email':
                if 'refresh_token' not in kwargs:
                    raise MigrationError("Single-email migration requires refresh_token")
                
                new_config = self.migrate_multi_to_single_config(
                    kwargs['refresh_token'],
                    kwargs.get('developer_token')
                )
            
            else:
                raise MigrationError(f"Unsupported target type: {target_type}")
            
            # Validate migration
            is_valid, issues = self.validate_migration(old_config, new_config)
            result['issues'] = issues
            
            if not is_valid:
                raise MigrationError(f"Migration validation failed: {', '.join(issues)}")
            
            # Save new configuration
            self.save_config(new_config)
            result['new_config_type'] = self.detect_config_type(new_config)
            result['success'] = True
            
            logger.info(f"Successfully migrated from {result['old_config_type']} to {result['new_config_type']}")
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Migration failed: {e}")
        
        return result
    
    def rollback_migration(self, backup_path: str) -> bool:
        """Rollback to a previous configuration backup.
        
        Args:
            backup_path: Path to the backup file
            
        Returns:
            True if rollback successful, False otherwise
        """
        try:
            if not os.path.exists(backup_path):
                raise MigrationError(f"Backup file not found: {backup_path}")
            
            # Validate backup file
            backup_config = self.load_config(backup_path)
            if not backup_config:
                raise MigrationError("Backup file is empty or invalid")
            
            # Copy backup to current config location
            shutil.copy2(backup_path, self.config_path)
            logger.info(f"Successfully rolled back to backup: {backup_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


def main():
    """Command-line interface for configuration migration."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Google Ads OneShop Configuration Migration Utility")
    parser.add_argument("config_path", help="Path to appsecrets.yaml file")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Detect configuration type")
    
    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Create configuration backup")
    
    # Migrate to multi-email command
    multi_parser = subparsers.add_parser("to-multi", help="Migrate to multi-email configuration")
    multi_parser.add_argument("--google-ads-token", required=True, help="Google Ads refresh token")
    multi_parser.add_argument("--merchant-center-token", required=True, help="Merchant Center refresh token")
    multi_parser.add_argument("--developer-token", help="Google Ads developer token")
    
    # Migrate to single-email command
    single_parser = subparsers.add_parser("to-single", help="Migrate to single-email configuration")
    single_parser.add_argument("--refresh-token", required=True, help="Combined refresh token")
    single_parser.add_argument("--developer-token", help="Google Ads developer token")
    
    # Rollback command
    rollback_parser = subparsers.add_parser("rollback", help="Rollback to backup configuration")
    rollback_parser.add_argument("backup_path", help="Path to backup file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    migrator = ConfigMigrator(args.config_path)
    
    try:
        if args.command == "detect":
            config_type = migrator.detect_config_type()
            print(f"Configuration type: {config_type}")
        
        elif args.command == "backup":
            backup_path = migrator.backup_existing_config()
            print(f"Backup created: {backup_path}")
        
        elif args.command == "to-multi":
            result = migrator.perform_migration(
                'multi_email',
                google_ads_refresh_token=args.google_ads_token,
                merchant_center_refresh_token=args.merchant_center_token,
                developer_token=args.developer_token
            )
            
            if result['success']:
                print("Migration to multi-email configuration successful!")
                print(f"Backup created: {result['backup_path']}")
            else:
                print(f"Migration failed: {result.get('error', 'Unknown error')}")
                if result['issues']:
                    print("Issues found:")
                    for issue in result['issues']:
                        print(f"  - {issue}")
        
        elif args.command == "to-single":
            result = migrator.perform_migration(
                'single_email',
                refresh_token=args.refresh_token,
                developer_token=args.developer_token
            )
            
            if result['success']:
                print("Migration to single-email configuration successful!")
                print(f"Backup created: {result['backup_path']}")
            else:
                print(f"Migration failed: {result.get('error', 'Unknown error')}")
                if result['issues']:
                    print("Issues found:")
                    for issue in result['issues']:
                        print(f"  - {issue}")
        
        elif args.command == "rollback":
            success = migrator.rollback_migration(args.backup_path)
            if success:
                print("Rollback successful!")
            else:
                print("Rollback failed!")
    
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
