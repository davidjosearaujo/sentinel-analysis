import datetime

def printReport(alerts, intro=None):
    if isinstance(alerts, list):
        text = ""
        for alert in alerts:
            text += alert.markdownCard()
        return text
    
    text = ""
    for key in alerts:
        text += printReport(alerts[key])  
      
    intro += "# Alerts Detected\n"
    intro += text
    
    filepath = f"report_{str(datetime.datetime.now().timestamp()).replace('.','')}"
    
    open(f"{filepath}.md", "w").write(intro)