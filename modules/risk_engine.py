class RiskEngine:
    """
    Transparent rule-based scoring engine for URL & Domain Intelligence.
    Calculates numerical risk score (0-100), risk tier (Low, Medium, High),
    and aggregates actionable recommendations with technical explanations.
    """
    
    @staticmethod
    def evaluate(indicators_triggered):
        """
        Receives a list of indicator objects:
        [
            {
                "id": "IP_AS_HOST",
                "title": "IP Address Used as Hostname",
                "severity": "High",
                "points": 25,
                "description": "...",
                "recommendation": "..."
            },
            ...
        ]
        """
        score = 0
        for ind in indicators_triggered:
            score += ind.get("points", 0)
            
        # Clamp score between 0 and 100
        score = min(max(score, 0), 100)
        
        if score >= 70:
            level = "High"
            badge_class = "danger"
            summary_desc = "High Risk Detected: Multiple significant suspicious indicators or anomalous structural patterns were identified. Proceed with extreme caution."
        elif score >= 30:
            level = "Medium"
            badge_class = "warning"
            summary_desc = "Medium Risk Detected: Heuristic analysis identified potential security anomalies or non-standard configurations. Review findings carefully."
        else:
            level = "Low"
            badge_class = "success"
            summary_desc = "Low Risk Profile: No significant malicious patterns or immediate structural anomalies detected. Standard precautions apply."
            
        # Generate cohesive list of precautions
        precautions = []
        for ind in indicators_triggered:
            rec = ind.get("recommendation")
            if rec and rec not in precautions:
                precautions.append(rec)
                
        if not precautions:
            precautions.append("Always verify SSL padlock and domain authenticity before entering credentials.")
            precautions.append("Ensure your operating system and web browser security definitions remain updated.")
            
        return {
            "score": score,
            "level": level,
            "badge_class": badge_class,
            "summary_desc": summary_desc,
            "indicators_count": len(indicators_triggered),
            "indicators": indicators_triggered,
            "precautions": precautions,
            "disclaimer": "This score represents a heuristic, rule-based structural and network analysis. It is an analytical indicator and does not constitute a definitive verdict of malware or malicious intent."
        }

