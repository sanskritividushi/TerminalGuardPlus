import sys
from secret_detector import SecretDetector
from audit_logger import AuditLogger
from config_manager import ConfigManager
from terminal_handler import TerminalHandler
from ml.cascade_entropy_detector import CascadeEnsembleDetector

def get_user_confirmation():
    """Ask user if they want to proceed despite warning"""
    while True:
        response = input("Do you want to run this command anyway? (y/n): ").lower().strip()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")

def main():
    print("=" * 60)
    print("TerminalGuard - Cross-Platform Secret Detection")
    print("=" * 60)
    print("Type 'exit' to quit")
    print("Type 'logs' to view recent audit logs")
    print("Type 'reload' to reload configuration\n")
    
    # Initialize components
    try:
        config_manager = ConfigManager()
        detector = SecretDetector(config_manager)
        cascade = CascadeEnsembleDetector()
        logger = AuditLogger()
        terminal = TerminalHandler()
    except Exception as e:
        print(f"Error initializing components: {e}")
        return
    
    while True:
        try:
            user_input = input(">> ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break
        
        # Handle special commands
        if user_input.lower() in ['exit', 'quit']:
            print("Goodbye!")
            break
        
        if user_input.lower() == 'logs':
            print("\n--- Recent Audit Logs ---")
            logs = logger.get_recent_logs(5)
            for log in logs:
                print(f"{log['timestamp']} | {log['action']} | {log['command'][:50]}")
            print()
            continue
        
        if user_input.lower() == 'reload':
            detector.reload_patterns()
            print("[SYSTEM] Configuration reloaded successfully!\n")
            continue
        
        if not user_input.strip():
            continue
        
        # Intercept and check for secrets using cascade detector
        print(f"[INTERCEPTED] {user_input}")
        
        cascade_result = cascade.detect(user_input)
        regex_secrets = detector.detect(user_input)
        
        blocked = cascade_result["decision"]
        cascade_level = cascade_result["cascade_level"]
        confidence = cascade_result["confidence"]
        reason = cascade_result["reasoning"]
        
        if blocked or regex_secrets:
            # Secret detected - show warning
            print("\n" + "!" * 60)
            print("⚠️  WARNING: SENSITIVE INFORMATION DETECTED!")
            print("!" * 60)
            print(f"   Cascade Level: L{cascade_level}")
            print(f"   Confidence: {confidence:.3f}")
            print(f"   Reason: {reason}")
            if regex_secrets:
                print(f"\n   Regex hits:")
                for secret in regex_secrets:
                    print(f"     Type: {secret['type']}")
                    print(f"     Description: {secret['description']}")
                    print(f"     Severity: {secret['severity'].upper()}")
                    print(f"     Found: {secret['match'][:60]}")
            print("!" * 60)
            
            # Ask user for confirmation
            proceed = get_user_confirmation()
            
            if proceed:
                print("\n[ALLOWED] Running command with warning logged...")
                logger.log_event(user_input, regex_secrets, 'ALLOWED', 'yes',
                                 extra={"cascade_level": cascade_level,
                                        "cascade_confidence": confidence,
                                        "cascade_reason": reason})
                terminal.run_command(user_input)
            else:
                print("\n[BLOCKED] Command execution cancelled for security.")
                logger.log_event(user_input, regex_secrets, 'BLOCKED', 'no',
                                 extra={"cascade_level": cascade_level,
                                        "cascade_confidence": confidence,
                                        "cascade_reason": reason})
        else:
            # No secrets - run normally
            logger.log_event(user_input, [], 'ALLOWED', None,
                             extra={"cascade_level": cascade_level,
                                    "cascade_confidence": confidence,
                                    "cascade_reason": reason})
            terminal.run_command(user_input)

if __name__ == '__main__':
    main()
