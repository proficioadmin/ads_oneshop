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

"""Dual Authentication Manager for Google Ads OneShop.

This module provides a unified authentication interface that supports both
single-email and multi-email authentication modes for Google Ads and 
Merchant Center APIs.
"""

import json
import os
import yaml
from typing import Dict, Optional, Any, Union
from google.ads.googleads.client import GoogleAdsClient
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import Resource
import logging

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


class DualAuthManager:
    """Manages authentication for both Google Ads and Merchant Center APIs.
    
    This class provides a unified interface for obtaining authenticated clients
    while supporting both single-email (legacy) and multi-email authentication modes.
    """
    
    def __init__(self, config_path: str):
        """Initialize the authentication manager.
        
        Args:
            config_path: Path to the configuration file (appsecrets.yaml)
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.auth_mode = self._determine_auth_mode()
        self._google_ads_client = None
        self._merchant_center_service = None
        
        logger.info(f"Initialized DualAuthManager in {self.auth_mode} mode")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file.
        
        Returns:
            Dictionary containing configuration data
            
        Raises:
            ConfigurationError: If config file cannot be loaded or is invalid
        """
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config:
                raise ConfigurationError("Configuration file is empty")
                
            return config
            
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
    
    def _determine_auth_mode(self) -> str:
        """Determine authentication mode based on configuration.
        
        Returns:
            Either 'single_email' or 'multi_email'
        """
        # Check if auth_mode is explicitly set
        if 'auth_mode' in self.config:
            mode = self.config['auth_mode']
            if mode in ['single_email', 'multi_email']:
                return mode
            else:
                logger.warning(f"Invalid auth_mode '{mode}', auto-detecting...")
        
        # Auto-detect based on configuration structure
        has_service_sections = 'google_ads' in self.config or 'merchant_center' in self.config
        has_legacy_fields = 'client_id' in self.config and 'client_secret' in self.config
        
        if has_service_sections:
            return 'multi_email'
        elif has_legacy_fields:
            return 'single_email'
        else:
            raise ConfigurationError(
                "Cannot determine authentication mode. Configuration must contain either "
                "legacy fields (client_id, client_secret) or service-specific sections "
                "(google_ads, merchant_center)"
            )
    
    def _get_credentials_for_service(self, service: str) -> Dict[str, str]:
        """Get credentials for a specific service.
        
        Args:
            service: Either 'google_ads' or 'merchant_center'
            
        Returns:
            Dictionary containing credentials for the service
            
        Raises:
            ConfigurationError: If credentials are not available for the service
        """
        if self.auth_mode == 'multi_email':
            # Try service-specific credentials first
            if service in self.config:
                service_config = self.config[service]
                required_fields = ['client_id', 'client_secret', 'refresh_token']
                
                # Check if all required fields are present
                missing_fields = [field for field in required_fields 
                                if field not in service_config or not service_config[field]]
                
                if not missing_fields:
                    return service_config
                else:
                    logger.warning(f"Missing fields for {service}: {missing_fields}")
            
            # Fallback to legacy credentials if available
            if self._has_legacy_credentials():
                logger.info(f"Using legacy credentials for {service}")
                return self._get_legacy_credentials()
            
            raise ConfigurationError(
                f"No valid credentials found for {service}. "
                f"Please configure service-specific credentials or ensure legacy credentials are complete."
            )
        
        else:  # single_email mode
            if not self._has_legacy_credentials():
                raise ConfigurationError(
                    "Legacy credentials are incomplete. "
                    "Please ensure client_id, client_secret, and refresh_token are configured."
                )
            return self._get_legacy_credentials()
    
    def _has_legacy_credentials(self) -> bool:
        """Check if legacy credentials are available and complete."""
        required_fields = ['client_id', 'client_secret']
        return all(field in self.config and self.config[field] for field in required_fields)
    
    def _get_legacy_credentials(self) -> Dict[str, str]:
        """Get legacy credentials from configuration."""
        # Try to get refresh_token from file if not in config
        refresh_token = self.config.get('refresh_token')
        if not refresh_token:
            refresh_token_file = os.path.join(os.path.dirname(self.config_path), 'refresh_token.txt')
            if os.path.exists(refresh_token_file):
                with open(refresh_token_file, 'r') as f:
                    refresh_token = f.read().strip()
        
        return {
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'refresh_token': refresh_token,
            'developer_token': self.config.get('developer_token', '')
        }
    
    def _create_oauth_credentials(self, credentials_dict: Dict[str, str]) -> Credentials:
        """Create OAuth2 credentials object.
        
        Args:
            credentials_dict: Dictionary containing OAuth credentials
            
        Returns:
            Google OAuth2 Credentials object
        """
        return Credentials(
            token=None,
            refresh_token=credentials_dict['refresh_token'],
            token_uri='https://oauth2.googleapis.com/token',
            client_id=credentials_dict['client_id'],
            client_secret=credentials_dict['client_secret']
        )
    
    def get_google_ads_client(self) -> GoogleAdsClient:
        """Get authenticated Google Ads client.
        
        Returns:
            Authenticated GoogleAdsClient instance
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if self._google_ads_client is not None:
            return self._google_ads_client
        
        try:
            credentials_dict = self._get_credentials_for_service('google_ads')
            
            # Create Google Ads client configuration
            google_ads_config = {
                'developer_token': credentials_dict.get('developer_token', ''),
                'client_id': credentials_dict['client_id'],
                'client_secret': credentials_dict['client_secret'],
                'refresh_token': credentials_dict['refresh_token'],
                'use_proto_plus': True
            }
            
            # Create and cache the client
            self._google_ads_client = GoogleAdsClient.load_from_dict(google_ads_config)
            logger.info("Successfully created Google Ads client")
            
            return self._google_ads_client
            
        except Exception as e:
            raise AuthenticationError(f"Failed to create Google Ads client: {e}")
    
    def get_merchant_center_service(self, version: str = 'v2.1') -> Resource:
        """Get authenticated Merchant Center service.
        
        Args:
            version: API version to use (default: v2.1)
            
        Returns:
            Authenticated Merchant Center service resource
            
        Raises:
            AuthenticationError: If authentication fails
        """
        if self._merchant_center_service is not None:
            return self._merchant_center_service
        
        try:
            credentials_dict = self._get_credentials_for_service('merchant_center')
            oauth_credentials = self._create_oauth_credentials(credentials_dict)
            
            # Create Merchant Center service
            self._merchant_center_service = build(
                'content',
                version,
                credentials=oauth_credentials,
                cache_discovery=False
            )
            
            logger.info(f"Successfully created Merchant Center service (v{version})")
            
            return self._merchant_center_service
            
        except Exception as e:
            raise AuthenticationError(f"Failed to create Merchant Center service: {e}")
    
    def validate_all_credentials(self) -> Dict[str, Dict[str, Any]]:
        """Validate all configured credentials.
        
        Returns:
            Dictionary with validation results for each service
        """
        results = {}
        
        # Validate Google Ads credentials
        try:
            client = self.get_google_ads_client()
            # Try a simple API call to validate
            customer_service = client.get_service("CustomerService")
            results['google_ads'] = {
                'valid': True,
                'message': 'Google Ads credentials are valid',
                'client_available': True
            }
        except Exception as e:
            results['google_ads'] = {
                'valid': False,
                'message': f'Google Ads credentials validation failed: {e}',
                'client_available': False
            }
        
        # Validate Merchant Center credentials
        try:
            service = self.get_merchant_center_service()
            # Try a simple API call to validate
            accounts = service.accounts()
            results['merchant_center'] = {
                'valid': True,
                'message': 'Merchant Center credentials are valid',
                'service_available': True
            }
        except Exception as e:
            results['merchant_center'] = {
                'valid': False,
                'message': f'Merchant Center credentials validation failed: {e}',
                'service_available': False
            }
        
        return results
    
    def get_auth_mode(self) -> str:
        """Get current authentication mode.
        
        Returns:
            Current authentication mode ('single_email' or 'multi_email')
        """
        return self.auth_mode
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of current configuration.
        
        Returns:
            Dictionary containing configuration summary (without sensitive data)
        """
        summary = {
            'auth_mode': self.auth_mode,
            'config_file': self.config_path,
            'services_configured': []
        }
        
        if self.auth_mode == 'multi_email':
            if 'google_ads' in self.config:
                summary['services_configured'].append('google_ads')
            if 'merchant_center' in self.config:
                summary['services_configured'].append('merchant_center')
        else:
            if self._has_legacy_credentials():
                summary['services_configured'] = ['google_ads', 'merchant_center']
        
        return summary


def create_auth_manager(config_path: Optional[str] = None) -> DualAuthManager:
    """Factory function to create authentication manager.
    
    Args:
        config_path: Path to configuration file. If None, uses default location.
        
    Returns:
        Configured DualAuthManager instance
    """
    if config_path is None:
        # Default to appsecrets.yaml in current directory
        config_path = 'appsecrets.yaml'
    
    return DualAuthManager(config_path)

