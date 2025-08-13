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

"""Enhanced OAuth utility for Google Ads OneShop multi-service authentication.

This module extends the original OAuth functionality to support generating
separate OAuth flows and tokens for Google Ads and Merchant Center services.
"""

import json
import sys
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, quote_via_parse

# OAuth configuration
_OAUTH_PLAYGROUND_URL = 'https://developers.google.com/oauthplayground'
_STEP_1_URL = _OAUTH_PLAYGROUND_URL + '/#step1'

# Service-specific scope mappings
SERVICE_SCOPES = {
    'google_ads': ['https://www.googleapis.com/auth/adwords'],
    'merchant_center': ['https://www.googleapis.com/auth/content'],
    'both': [
        'https://www.googleapis.com/auth/adwords',
        'https://www.googleapis.com/auth/content'
    ]
}

# Scope prefix for OAuth playground
_SCOPES_PREFIX = 'https://www.googleapis.com/auth/'


def get_secrets_dict(secrets_path: str) -> Dict[str, str]:
    """Get the secrets dictionary from stored web credentials.
    
    Args:
        secrets_path: The path to the secrets file.
        
    Returns:
        A dictionary representing the secrets.
    """
    with open(secrets_path) as f:
        secrets = json.loads(f.read().strip() or '{}').get('web', {})
    return secrets


def get_client_id_and_secret(secrets: Dict[str, str]) -> Tuple[str, str]:
    """Get the client ID and secret.
    
    Args:
        secrets: The secrets dict to parse
        
    Returns:
        A tuple of client_id and client_secret
    """
    client_id = secrets.get('client_id', '')
    client_secret = secrets.get('client_secret', '')
    return client_id, client_secret


def get_oauth_url_for_service(secrets_path: str, service: str) -> str:
    """Generate OAuth URL for specific service.
    
    Args:
        secrets_path: Path to the client secrets file
        service: Service name ('google_ads', 'merchant_center', or 'both')
        
    Returns:
        The fully-formed OAuth playground URL for the specified service
        
    Raises:
        ValueError: If service is not supported
        AssertionError: If any of the secrets are missing
    """
    if service not in SERVICE_SCOPES:
        raise ValueError(f"Unsupported service: {service}. Must be one of: {list(SERVICE_SCOPES.keys())}")
    
    secrets = get_secrets_dict(secrets_path)
    client_id, client_secret = get_client_id_and_secret(secrets)
    
    if not client_id or not client_secret:
        raise AssertionError('No client ID or secret found')
    
    redirect_uris = secrets.get('redirect_uris', [])
    if _OAUTH_PLAYGROUND_URL not in redirect_uris:
        raise AssertionError('OAuth Playground not found in redirect URIs')
    
    # Get scopes for the specified service
    scopes = SERVICE_SCOPES[service]
    scope_str = ' '.join([_SCOPES_PREFIX + scope.split('/')[-1] for scope in scopes])
    
    query_params = {
        'oauthClientId': client_id,
        'oauthClientSecret': client_secret,
        'scopes': scope_str,
        'useDefaultOauthCred': 'checked',
    }
    
    query_str = urlencode(query_params, quote_via=quote_via_parse.quote)
    
    # OAuth Playground only prepopulates if I use an ampersand here
    return f'{_STEP_1_URL}&{query_str}'


def get_oauth_url(secrets_path: str, scopes: List[str]) -> str:
    """Get the OAuth Playground URL (legacy function for backward compatibility).
    
    Args:
        secrets_path: The path to the client secrets file, relative to invocation.
        scopes: The scopes to request.
        
    Returns:
        The fully-formed playground URL.
        
    Raises:
        AssertionError: If any of the secrets are missing.
    """
    secrets = get_secrets_dict(secrets_path)
    client_id, client_secret = get_client_id_and_secret(secrets)
    
    if not client_id or not client_secret:
        raise AssertionError('No client ID or secret found')
    
    redirect_uris = secrets.get('redirect_uris', [])
    if _OAUTH_PLAYGROUND_URL not in redirect_uris:
        raise AssertionError('OAuth Playground not found in redirect URIs')
    
    # scopes are space-delimited
    scope_str = ' '.join([_SCOPES_PREFIX + scope for scope in scopes])
    
    query_params = {
        'oauthClientId': client_id,
        'oauthClientSecret': client_secret,
        'scopes': scope_str,
        'useDefaultOauthCred': 'checked',
    }
    
    query_str = urlencode(query_params, quote_via=quote_via_parse.quote)
    
    # OAuth Playground only prepopulates if I use an ampersand here
    return f'{_STEP_1_URL}&{query_str}'


def generate_separate_tokens_interactive(secrets_path: str) -> Dict[str, str]:
    """Interactive function to generate separate refresh tokens for both services.
    
    Args:
        secrets_path: Path to the client secrets file
        
    Returns:
        Dictionary containing URLs for generating tokens for each service
    """
    print("=== Google Ads OneShop Multi-Service OAuth Setup ===\n")
    
    results = {}
    
    # Generate URLs for each service
    for service in ['google_ads', 'merchant_center']:
        try:
            url = get_oauth_url_for_service(secrets_path, service)
            service_name = service.replace('_', ' ').title()
            
            print(f"{service_name} OAuth URL:")
            print(f"Please visit: {url}")
            print(f"1. Click 'Authorize APIs'")
            print(f"2. Authorize with the Google account for {service_name}")
            print(f"3. Click 'Exchange authorization code for tokens'")
            print(f"4. Copy the refresh_token value (without quotes)")
            print()
            
            results[service] = {
                'url': url,
                'service_name': service_name
            }
            
        except Exception as e:
            print(f"Error generating URL for {service}: {e}")
            results[service] = {
                'error': str(e)
            }
    
    return results


def validate_service_credentials(service: str, credentials: Dict[str, str]) -> bool:
    """Validate that credentials work for the specified service.
    
    Args:
        service: Service name ('google_ads' or 'merchant_center')
        credentials: Dictionary containing client_id, client_secret, refresh_token
        
    Returns:
        True if credentials are valid, False otherwise
    """
    try:
        if service == 'google_ads':
            from google.ads.googleads.client import GoogleAdsClient
            
            config = {
                'developer_token': credentials.get('developer_token', ''),
                'client_id': credentials['client_id'],
                'client_secret': credentials['client_secret'],
                'refresh_token': credentials['refresh_token'],
                'use_proto_plus': True
            }
            
            client = GoogleAdsClient.load_from_dict(config)
            # Try to get customer service to validate
            customer_service = client.get_service("CustomerService")
            return True
            
        elif service == 'merchant_center':
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
            
            oauth_credentials = Credentials(
                token=None,
                refresh_token=credentials['refresh_token'],
                token_uri='https://oauth2.googleapis.com/token',
                client_id=credentials['client_id'],
                client_secret=credentials['client_secret']
            )
            
            service_obj = build('content', 'v2.1', credentials=oauth_credentials, cache_discovery=False)
            # Try to get accounts service to validate
            accounts = service_obj.accounts()
            return True
            
        else:
            return False
            
    except Exception as e:
        print(f"Validation failed for {service}: {e}")
        return False


def create_multi_service_config(secrets_path: str, 
                              google_ads_token: str, 
                              merchant_center_token: str,
                              developer_token: str) -> Dict[str, any]:
    """Create multi-service configuration dictionary.
    
    Args:
        secrets_path: Path to client secrets file
        google_ads_token: Refresh token for Google Ads
        merchant_center_token: Refresh token for Merchant Center
        developer_token: Google Ads developer token
        
    Returns:
        Configuration dictionary for appsecrets.yaml
    """
    secrets = get_secrets_dict(secrets_path)
    client_id, client_secret = get_client_id_and_secret(secrets)
    
    config = {
        'auth_mode': 'multi_email',
        'google_ads': {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': google_ads_token,
            'developer_token': developer_token
        },
        'merchant_center': {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': merchant_center_token
        }
    }
    
    return config


def print_usage():
    """Print usage information."""
    print("Enhanced OAuth Utility for Google Ads OneShop")
    print()
    print("Usage:")
    print("  python enhanced_oauth.py <client_secrets.json> [options]")
    print()
    print("Options:")
    print("  --service <service>    Generate OAuth URL for specific service")
    print("                        Options: google_ads, merchant_center, both")
    print("  --interactive         Interactive mode for generating separate tokens")
    print("  --legacy <scopes>     Legacy mode (backward compatibility)")
    print()
    print("Examples:")
    print("  # Generate OAuth URL for Google Ads only")
    print("  python enhanced_oauth.py client_secrets.json --service google_ads")
    print()
    print("  # Generate OAuth URL for Merchant Center only")
    print("  python enhanced_oauth.py client_secrets.json --service merchant_center")
    print()
    print("  # Interactive mode for both services")
    print("  python enhanced_oauth.py client_secrets.json --interactive")
    print()
    print("  # Legacy mode (original behavior)")
    print("  python enhanced_oauth.py client_secrets.json --legacy adwords content")


def main(argv: Sequence[str]) -> None:
    """Main function with enhanced command-line interface."""
    if len(argv) < 2:
        print_usage()
        return
    
    secrets_path = argv[1]
    
    # Check for help flag
    if '--help' in argv or '-h' in argv:
        print_usage()
        return
    
    try:
        # Interactive mode
        if '--interactive' in argv:
            results = generate_separate_tokens_interactive(secrets_path)
            print("\n=== Summary ===")
            for service, result in results.items():
                if 'error' in result:
                    print(f"{service}: ERROR - {result['error']}")
                else:
                    print(f"{service}: URL generated successfully")
            return
        
        # Service-specific mode
        if '--service' in argv:
            service_idx = argv.index('--service') + 1
            if service_idx >= len(argv):
                print("Error: --service requires a service name")
                print_usage()
                return
            
            service = argv[service_idx]
            url = get_oauth_url_for_service(secrets_path, service)
            service_name = service.replace('_', ' ').title()
            
            print(f"{service_name} OAuth URL:")
            print(f"Please visit: {url}")
            return
        
        # Legacy mode
        if '--legacy' in argv:
            legacy_idx = argv.index('--legacy') + 1
            if legacy_idx >= len(argv):
                print("Error: --legacy requires scope arguments")
                print_usage()
                return
            
            scopes = argv[legacy_idx:]
            url = get_oauth_url(secrets_path, scopes)
            print(f'Please visit: {url}')
            return
        
        # Default behavior (backward compatibility)
        if len(argv) >= 3:
            scopes = argv[2:]
            url = get_oauth_url(secrets_path, scopes)
            print(f'Please visit: {url}')
        else:
            print_usage()
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
