from datetime import datetime

def check_iso_27001_compliance(security_headers, ssl_info):
    compliance_issues = []

    if security_headers['Content-Security-Policy'] == 'Not found':
        compliance_issues.append("Missing Content-Security-Policy header")
    if security_headers['X-Content-Type-Options'] == 'Not found':
        compliance_issues.append("Missing X-Content-Type-Options header")
    if security_headers['X-Frame-Options'] == 'Not found':
        compliance_issues.append("Missing X-Frame-Options header")
    if security_headers['Strict-Transport-Security'] == 'Not found':
        compliance_issues.append("Missing Strict-Transport-Security header")
    
    expiration_date = ssl_info[2]
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.fromisoformat(expiration_date)
        except ValueError:
            compliance_issues.append("Invalid SSL expiration date format")
    
    if expiration_date and expiration_date.tzinfo is not None:
        expiration_date = expiration_date.replace(tzinfo=None)

    now = datetime.now()
    if now.tzinfo is not None:
        now = now.replace(tzinfo=None)

    if expiration_date and expiration_date < now:
        compliance_issues.append("SSL certificate is expired")
    
    compliance_status = "Compliant" if not compliance_issues else "Non-Compliant"
    
    return compliance_status, compliance_issues
