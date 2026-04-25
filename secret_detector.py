import re
from config_manager import ConfigManager

class SecretDetector:
    """Detects secrets and sensitive information in commands"""
    
    def __init__(self, config_manager=None):
        if config_manager is None:
            config_manager = ConfigManager()
        
        self.config_manager = config_manager
        self.patterns = self.config_manager.get_patterns()
    
    def reload_patterns(self):
        """Reload patterns from config file"""
        import sys
        self.config_manager.reload_config()
        self.patterns = self.config_manager.get_patterns()
        print(f"[DETECTOR] Reloaded {len(self.patterns)} detection patterns", file=sys.stderr)
    
    def detect(self, command):
        """
        Scan a command for secrets
        Returns: list of detected secrets with their types
        """
        # Check if detection is enabled
        if not self.config_manager.is_detection_enabled():
            return []
        
        # Check if command is whitelisted
        if self.config_manager.is_whitelisted(command):
            return []
        
        detected = []
        
        for secret_type, pattern_info in self.patterns.items():
            matches = pattern_info['regex'].finditer(command)
            for match in matches:
                detected.append({
                    'type': secret_type,
                    'match': match.group(0),
                    'position': match.span(),
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity']
                })
        
        return detected
    
    def has_secrets(self, command):
        """Check if command contains any secrets"""
        return len(self.detect(command)) > 0
