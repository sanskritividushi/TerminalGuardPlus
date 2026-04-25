import json
from datetime import datetime
import os
import sys

from mongo_handler import MongoDBHandler

class AuditLogger:
    """Logs all command interceptions and security events to MongoDB"""

    def __init__(self, use_mongodb=True):
        print("[DEBUG] Initializing AuditLogger with use_mongodb =", use_mongodb, file=sys.stderr)
        self.use_mongodb = use_mongodb
        self.mongo_handler = None  # Initialize to None

        # File logging fallback setup
        log_file = 'audit.log'
        if not os.path.isabs(log_file):
            log_file = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                log_file
            )
        self.log_file = log_file  # Always set this

        if self.use_mongodb:
            try:
                mongodb_uri = os.getenv('MONGODB_URI')
                print(f"[AUDIT_LOGGER] Checking MONGODB_URI... {'Found' if mongodb_uri else 'NOT FOUND'}", file=sys.stderr)
                self.mongo_handler = MongoDBHandler()
                print("[AUDIT_LOGGER] ✅ Successfully initialized MongoDB logging", file=sys.stderr)
                self.use_mongodb = True
            except Exception as e:
                print(f"[AUDIT_LOGGER] ❌ MongoDB initialization failed, falling back to file: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
                self.use_mongodb = False
                self.mongo_handler = None
        else:
            print("[AUDIT_LOGGER] MongoDB logging disabled, using file fallback only", file=sys.stderr)

    def log_event(self, command, secrets_detected, action, user_choice=None, latency_ms=None, extra=None):
        """Log a command execution event"""
        timestamp = datetime.now().isoformat()

        log_entry = {
            'timestamp': timestamp,
            'command': command,
            'action': action,
            'secrets_found': len(secrets_detected),
            'secret_types': [s['type'] for s in secrets_detected],
            'secret_severities': [s.get('severity', 'unknown') for s in secrets_detected],
            'user_choice': user_choice,
            'latency_ms': latency_ms,
            # For user feedback / annotation (true/false positive etc.)
            'mark_detection': None,
        }

        # Attach extra analytics fields (e.g., cascade metrics)
        if extra:
            try:
                log_entry.update(extra)
            except Exception as e:
                print(f"[AUDIT_LOGGER] Failed to merge extra fields: {e}", file=sys.stderr)

        logged = False

        if self.use_mongodb and self.mongo_handler:
            try:
                print(f"[AUDIT_LOGGER] 📤 Attempting MongoDB insert for action: {action}", file=sys.stderr, flush=True)
                result = self.mongo_handler.insert_log(log_entry)
                if result is not None:
                    print(f"[AUDIT_LOGGER] ✅ MongoDB logged successfully: {action} - {command[:50]}...", file=sys.stderr, flush=True)
                    logged = True
                else:
                    print(f"[AUDIT_LOGGER] ⚠️ MongoDB insert returned None, falling back to file", file=sys.stderr, flush=True)
            except Exception as e:
                print(f"[AUDIT_LOGGER] ❌ MongoDB write failed: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc(file=sys.stderr)
        else:
            if self.use_mongodb:
                print(f"[AUDIT_LOGGER] ⚠️ MongoDB handler not available, using file", file=sys.stderr, flush=True)

        # Fallback to file if MongoDB disabled or failed
        if not logged:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + '\n')
                    f.flush()
                print(f"[AUDIT_LOGGER] 📝 File logged: {action} - {command[:50]}...", file=sys.stderr, flush=True)
                logged = True
            except Exception as e:
                print(f"[AUDIT_LOGGER] ❌ File write failed: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc(file=sys.stderr)

        if not logged:
            print("[AUDIT_LOGGER] 🚨 CRITICAL: Failed to log event anywhere!", file=sys.stderr, flush=True)

        return log_entry

    def update_mark_detection(self, log_id, mark):
        if self.use_mongodb and self.mongo_handler:
            try:
                return self.mongo_handler.update_mark_detection(log_id, mark)
            except Exception as e:
                print("[AUDIT_LOGGER] Failed to update mark_detection:", e, file=sys.stderr)
                return False
        return False

    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        if self.use_mongodb and self.mongo_handler:
            try:
                return self.mongo_handler.get_recent_logs(count)
            except Exception as e:
                print(f"[AUDIT_LOGGER ERROR] Failed to read from MongoDB: {e}", file=sys.stderr)

        # Fallback to file reading
        if not os.path.exists(self.log_file):
            return []

        entries = []
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    try:
                        entries.append(json.loads(line.strip()))
                    except Exception:
                        continue
        except Exception as e:
            print(f"[AUDIT_LOGGER ERROR] Failed to read log: {e}", file=sys.stderr)

        return entries
