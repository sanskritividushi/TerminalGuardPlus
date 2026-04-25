from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from audit_logger import AuditLogger
from fastapi.responses import JSONResponse, FileResponse
from collections import defaultdict
from datetime import datetime
import sys, os, pymongo, certifi, psutil

app = FastAPI(title="TerminalGuard Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],

)

# Serve the dashboard frontend
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/dashboard.js")
def serve_dashboard_js():
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.js"), media_type="application/javascript")

@app.get("/style.css")
def serve_dashboard_css():
    return FileResponse(os.path.join(STATIC_DIR, "style.css"), media_type="text/css")

logger = AuditLogger(use_mongodb=True)

@app.get("/")
def root():
    return {"message": "Welcome to the TerminalGuard Dashboard API!"}

@app.get("/health")
def health_check():
    try:
        if hasattr(logger, "mongo_handler") and logger.mongo_handler:
            logger.mongo_handler.client.admin.command("ping")
            return {"status": "healthy", "mongodb": "connected"}
        else:
            return {"status": "degraded", "message": "MongoDB logging not in use"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/logs")
def get_logs(
    count: int = Query(20, ge=1, le=100),
    action_filter: str = Query(None),
):
    all_logs = logger.get_recent_logs(1000)

    if action_filter:
        filtered = [log for log in all_logs if log["action"] == action_filter.upper()]
    else:
        filtered = all_logs

    result_logs = []
    for log in filtered[:count]:
        result_logs.append({
            "id": str(log.get("_id", log.get("id"))),
            "_id": str(log.get("_id", log.get("id"))),
            "timestamp": log.get("timestamp"),
            "command": log.get("command", ""),
            "action": log.get("action"),
            "secrets_found": log.get("secrets_found"),
            "mark_detection": log.get("mark_detection", None),
            # NEW: cascade metrics per log
            "cascade_level": log.get("cascade_level"),
            "cascade_confidence": log.get("cascade_confidence"),
        })

    return {"total_logs": len(result_logs), "logs": result_logs}

@app.post("/logs/mark_detection")
def mark_detection(
    log_id: str = Body(...),
    mark: str = Body(...),  # "true" or "false"
):
    result = logger.update_mark_detection(log_id, mark)
    if result:
        return {"status": "success"}
    return {"status": "failed", "error": "Could not update marking"}

@app.get("/statistics")
def get_statistics():
    logs = logger.get_recent_logs(1000)
    total = len(logs)
    blocked = sum(1 for log in logs if log.get("action") == "BLOCKED")
    allowed = total - blocked
    secrets_count = sum(log.get("secrets_found", 0) for log in logs)

    TP = FP = TN = FN = 0
    for log in logs:
        mark = log.get("mark_detection")
        secret_found = log.get("secrets_found", 0) > 0
        if mark == "true":
            # User confirms detection was correct
            if secret_found:
                TP += 1   # System found secret, correctly
            else:
                TN += 1   # System found nothing, correctly
        elif mark == "false":
            # User says detection was wrong
            if secret_found:
                FP += 1   # System flagged secret, but it wasn't one
            else:
                FN += 1   # System missed a secret

    fp_rate = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    fn_rate = FN / (FN + TP) if (FN + TP) > 0 else 0.0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0.0
    secret_types = {}
    for log in logs:
        for stype in log.get("secret_types", []):
            secret_types[stype] = secret_types.get(stype, 0) + 1

    block_rate = (blocked / total * 100) if total > 0 else 0.0

    return {
        "total_commands": total,
        "blocked_commands": blocked,
        "allowed_commands": allowed,
        "total_secrets_detected": secrets_count,
        "secret_types_breakdown": secret_types,
        "block_rate_percent": round(block_rate, 2),
        "false_positive_rate": round(fp_rate * 100, 2),
        "false_negative_rate": round(fn_rate * 100, 2),
        "accuracy_percent": round(accuracy * 100, 2),
    }

@app.get("/performance")
def get_performance():
    """Get latency and performance metrics"""
    logs = logger.get_recent_logs(1000)
    latencies = [log.get("latency_ms", 0) for log in logs if log.get("latency_ms")]
    if not latencies:
        return {
            "note": "No latency data yet - new logs will include latency",
            "avg_latency_ms": 0,
            "min_latency_ms": 0,
            "max_latency_ms": 0,
            "total_detections": len(logs),
        }

    latencies_sorted = sorted(latencies)
    return {
        "avg_latency_ms": round(sum(latencies) / len(latencies), 4),
        "min_latency_ms": round(min(latencies), 4),
        "max_latency_ms": round(max(latencies), 4),
        "p95_latency_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.95)], 4) if len(latencies) >= 20 else None,
        "total_detections": len(logs),
        "detections_with_latency": len(latencies),
    }

@app.get("/severity")
def get_severity_breakdown():
    """Get detection breakdown by severity level"""
    logs = logger.get_recent_logs(1000)
    severity_counts = defaultdict(int)
    for log in logs:
        for sev in log.get("secret_severities", []):
            severity_counts[sev] += 1

    if not severity_counts:
        return {
            "note": "No severity data yet - new logs will include severity",
            "by_severity": {},
            "total_secrets": 0,
        }

    return {
        "by_severity": dict(severity_counts),
        "total_secrets": sum(severity_counts.values()),
    }

@app.get("/trends")
def get_trends():
    """Get time-based detection trends"""
    logs = logger.get_recent_logs(1000)
    hourly = defaultdict(int)
    daily = defaultdict(int)

    for log in logs:
        try:
            ts_str = log.get("timestamp", "")
            ts = datetime.fromisoformat(ts_str) if "T" in ts_str else datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            hourly[ts.hour] += 1
            daily[ts.strftime("%Y-%m-%d")] += 1
        except Exception:
            continue

    return {
        "by_hour": dict(sorted(hourly.items())),
        "by_day": dict(sorted(daily.items())[-30:]),
    }

@app.get("/resources")
def get_resources():
    """Get system resource usage (CPU, Memory)"""
    try:
        process = psutil.Process()
        return {
            "cpu_percent": round(process.cpu_percent(), 2),
            "memory_mb": round(process.memory_info().rss / 1024 / 1024, 2),
            "threads": process.num_threads(),
            "uptime_seconds": round((datetime.now() - datetime.fromtimestamp(process.create_time())).total_seconds(), 0),
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/cascade")
def get_cascade_stats():
    """Get distribution of cascade decisions by level."""
    logs = logger.get_recent_logs(1000)

    level_counts = defaultdict(int)
    level_conf_sum = defaultdict(float)
    level_conf_n = defaultdict(int)

    for log in logs:
        level = log.get("cascade_level")
        conf = log.get("cascade_confidence")
        if level is None:
            continue
        level_counts[level] += 1
        if isinstance(conf, (int, float)):
            level_conf_sum[level] += conf
            level_conf_n[level] += 1

    avg_conf = {}
    for lvl, n in level_conf_n.items():
        if n:
            avg_conf[lvl] = round(level_conf_sum[lvl] / n, 4)

    return {
        "level_counts": dict(level_counts),
        "avg_confidence": avg_conf,
        "total_with_cascade": sum(level_counts.values()),
    }

@app.get("/full-report")
def get_full_report():
    """Get comprehensive analytics report"""
    logs = logger.get_recent_logs(1000)
    # ... keep your existing full-report logic here; you can optionally
    # add cascade aggregation similar to /cascade if you like.

    # (Leaving rest unchanged for brevity)
    # ...
    return JSONResponse({"detail": "Implement cascade aggregation here if needed"})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("dashboard_api:app", host="0.0.0.0", port=port, reload=False)
