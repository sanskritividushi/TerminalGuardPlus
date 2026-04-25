import yaml
import os
import re

class ConfigManager:
    """Manages configuration loading and reloading"""
    
    def __init__(self, config_file='config.yaml'):
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # If config_file is just a filename, make it relative to script directory
        if not os.path.isabs(config_file):
            self.config_file = os.path.join(script_dir, config_file)
        else:
            self.config_file = config_file
        
        self.config = None
        self.load_config()
    
    def load_config(self):
        """Load configuration from YAML file"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file not found: {self.config_file}")
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        import sys
        print(f"[CONFIG] Loaded configuration from {self.config_file}", file=sys.stderr)
        return self.config

    def reload_config(self):
        """Reload configuration from file"""
        import sys
        print("[CONFIG] Reloading configuration...", file=sys.stderr)
        return self.load_config()
    
    def get_patterns(self):
        """Get all detection patterns as compiled regex objects"""
        patterns = {}
        detection_config = self.config.get('detection', {})
        if 'patterns' in detection_config:
            for name, pattern_info in detection_config['patterns'].items():
                patterns[name] = {
                    'regex': re.compile(pattern_info['regex']),
                    'description': pattern_info.get('description', ''),
                    'severity': pattern_info.get('severity', 'medium')
                }
        return patterns
    
    def is_detection_enabled(self):
        """Check if detection is enabled"""
        return self.config.get('detection', {}).get('enabled', True)
    
    def get_whitelist(self):
        """Get whitelist commands and patterns"""
        whitelist = self.config.get('whitelist', {})
        return {
            'commands': whitelist.get('commands', []),
            'patterns': [re.compile(p) for p in whitelist.get('patterns', [])]
        }
    
    def is_whitelisted(self, command):
        """Check if a command is whitelisted"""
        whitelist = self.get_whitelist()
        
        # Check exact command matches
        if command.strip() in whitelist['commands']:
            return True
        
        # Check pattern matches
        for pattern in whitelist['patterns']:
            if pattern.search(command.strip()):
                return True
        
        return False
    
    def get_audit_settings(self):
        """Get audit logging settings"""
        return self.config.get('audit', {
            'enabled': True,
            'log_file': 'audit.log',
            'max_size_mb': 10
        })
