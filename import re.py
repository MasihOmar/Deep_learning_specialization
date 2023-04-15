import re
from typing import Dict

def validate_name(name: str, max_length: int, min_length: int) -> bool:
    """Helper function to validate name"""
    name = name.strip()
    return min_length <= len(name) <= max_length

def validate_email_addr(email_addr: str) -> bool:
    """Helper function to validate email address"""
    email_addr = email_addr.strip()
    if len(email_addr) > 254 or email_addr.count('@') != 1:
        return False
    local_part, domain_part = email_addr.split('@')
    if len(local_part) > 64 or len(domain_part) > 251:
        return False
    if '.' not in domain_part or domain_part[-4:] not in ('.com', '.net', '.org'):
        return False
    for c in local_part:
        if c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@-.':
            return False
    if local_part[0] == '-' or local_part[-1] == '-' or local_part[0] == '.' or local_part[-1] == '.':
        return False
    if '..' in local_part or local_part.count('.') > 1 and not local_part.endswith('.com'):
        return False
    return True

def validate_email_payload(sender_name: str, sender_addr: str, receiver_name: str, receiver_addr: str, html: str, replacements: Dict[str, str]) -> bool:
    """Validate email payload"""
    if not validate_name(sender_name, 30, 5) or not validate_name(receiver_name, 60, 5):
        raise ValueError("Invalid sender or receiver name")
    if not validate_email_addr(sender_addr) or not validate_email_addr(receiver_addr):
        raise ValueError("Invalid sender or receiver email address")
    for key in replacements.keys():
        if key not in html:
            raise ValueError(f"Replacement key '{key}' not found in HTML")
    for match in re.findall(r'{(\w+)}', html):
        if match not in replacements:
            raise ValueError(f"Replacement key '{match}' not provided")
    return True
