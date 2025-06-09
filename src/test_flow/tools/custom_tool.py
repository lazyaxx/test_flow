# tools/custom_tool.py
from crewai.tools import BaseTool
import os
from typing import Dict, Any, Union

class SOCCommunicationTool(BaseTool):
    name: str = "soc_communicator"
    description: str = "Communicates with SOC admin server for severity assessment"
    
    def _run(self, analysis_data: Union[dict, str]) -> str:
        """Send analysis to SOC admin and get severity assessment with enhanced trust level checking"""
        
        try:
            # Parse input data - handle both dict and JSON string formats
            if isinstance(analysis_data, str):
                try:
                    import json
                    parsed_data = json.loads(analysis_data)
                except json.JSONDecodeError:
                    # Fallback to original keyword-based analysis for plain text
                    return self._legacy_keyword_analysis(analysis_data)
            elif isinstance(analysis_data, dict):
                parsed_data = analysis_data
            else:
                return "Invalid input: analysis_data must be a dictionary or a string."
            
            # Extract security indicators with defaults
            trust_level = parsed_data.get("trust_level", 5)  # Default to medium trust
            url = parsed_data.get("url", "")
            virus_total = parsed_data.get("virus_total", {})
            phishtank = parsed_data.get("phishtank", False)
            mdl = parsed_data.get("mdl", False)
            
            # Initialize threat scoring
            threat_score = 0
            threat_reasons = []
            
            # Trust level assessment (1-2 = low trust, should be blocked)
            if trust_level <= 2:
                threat_score += 50
                threat_reasons.append(f"Low trust level ({trust_level})")
            
            # VirusTotal analysis
            if virus_total:
                scans = virus_total.get("scans", 0)
                malicious = virus_total.get("malicious", 0)
                if malicious > 0:
                    threat_score += 70
                    threat_reasons.append(f"VirusTotal detections: {malicious}/{scans}")
                elif scans > 0 and malicious == 0:
                    threat_score -= 10  # Good reputation
            
            # PhishTank detection
            if phishtank:
                threat_score += 60
                threat_reasons.append("PhishTank flagged")
            
            # MDL (Malware Domain List) detection  
            if mdl:
                threat_score += 40
                threat_reasons.append("Malware Domain List flagged")
            
            # URL pattern analysis for additional context
            suspicious_patterns = [".exe", "malware", "phish", "hack", "exploit"]
            if url and any(pattern in url.lower() for pattern in suspicious_patterns):
                threat_score += 20
                threat_reasons.append("Suspicious URL pattern")
            
            # Determine final action based on threat score
            if threat_score >= 50:
                severity = "HIGH"
                action = "BLOCK"
                reason = "Multiple threat indicators: " + ", ".join(threat_reasons)
            elif threat_score >= 25:
                severity = "MEDIUM" 
                action = "REVIEW"
                reason = "Potential threats detected: " + ", ".join(threat_reasons)
            else:
                severity = "LOW"
                action = "ALLOW"
                reason = "No significant threats detected"
                if threat_reasons:
                    reason += f" (Minor flags: {', '.join(threat_reasons)})"
            
            # Format response
            response = f"""SOC Admin Response:
    - Severity: {severity}
    - Recommended Action: {action}
    - Reason: {reason}
    - Threat Score: {threat_score}
    - Communication Status: SUCCESS"""
            
            return response
                
        except Exception as e:
            return f"SOC communication error: {str(e)}. Defaulting to BLOCK action for security."

    def _legacy_keyword_analysis(self, analysis_content: str) -> str:
        """Fallback method for plain text analysis"""
        analysis_lower = analysis_content.lower()
        
        if any(keyword in analysis_lower for keyword in ["malicious", "malware", "blacklist", "trust_level: 1", "trust_level: 2"]):
            severity = "HIGH"
            action = "BLOCK"
            reason = "High-risk content or low trust level detected"
        elif any(keyword in analysis_lower for keyword in ["suspicious", "phishing", "unknown"]):
            severity = "MEDIUM"
            action = "REVIEW" 
            reason = "Suspicious activity requires review"
        else:
            severity = "LOW"
            action = "ALLOW"
            reason = "No significant threats detected"
        
        return f"""SOC Admin Response:
    - Severity: {severity}
    - Recommended Action: {action}
    - Reason: {reason}
    - Communication Status: SUCCESS"""
