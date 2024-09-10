from datetime import datetime

def check_iso_27001_compliance(security_headers, ssl_info):
    compliance_issues = []

    # Check the security headers
    if security_headers['Content-Security-Policy'] == 'Not found':
        compliance_issues.append("Missing Content-Security-Policy header")
    if security_headers['X-Content-Type-Options'] == 'Not found':
        compliance_issues.append("Missing X-Content-Type-Options header")
    if security_headers['X-Frame-Options'] == 'Not found':
        compliance_issues.append("Missing X-Frame-Options header")
    if security_headers['Strict-Transport-Security'] == 'Not found':
        compliance_issues.append("Missing Strict-Transport-Security header")
    
    # Check SSL info, ensuring there are valid values before accessing
    expiration_date = ssl_info[2] if ssl_info[2] else None

    if isinstance(expiration_date, str):
        # If expiration_date is a string, attempt to parse it back to a datetime object
        try:
            expiration_date = datetime.fromisoformat(expiration_date)
        except ValueError:
            compliance_issues.append("Invalid SSL expiration date format")
            expiration_date = None
    
    if expiration_date:
        if expiration_date.tzinfo is not None:
            # Convert expiration_date to naive (strip timezone)
            expiration_date = expiration_date.replace(tzinfo=None)
    
    now = datetime.now()  # Naive datetime
    if expiration_date and expiration_date < now:
        compliance_issues.append("SSL certificate is expired")

    ssl_protocol_version = ssl_info[3] if len(ssl_info) > 3 and ssl_info[3] else None
    if ssl_protocol_version in ['TLSv1', 'TLSv1.1']:
        compliance_issues.append(f"Weak TLS version detected: {ssl_protocol_version}")
    
    compliance_status = "No Risks Found. Well Done." if not compliance_issues else "Risks Found"
    
    return compliance_status, compliance_issues
