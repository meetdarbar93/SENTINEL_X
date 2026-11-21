import sqlite3
import json
import os
from datetime import datetime, timedelta
from config import Config

def get_connection():
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Investigations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        investigation_type TEXT NOT NULL,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'Low',
        summary TEXT,
        details_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Activity logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        target TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Application settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Indexes for rapid retrieval
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inv_type ON investigations(investigation_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inv_risk ON investigations(risk_score)")
    
    conn.commit()
    conn.close()

def save_investigation(target, inv_type, risk_score=0, risk_level="Low", summary="", details=None):
    conn = get_connection()
    cursor = conn.cursor()
    details_str = json.dumps(details) if isinstance(details, (dict, list)) else str(details or "{}")
    
    cursor.execute("""
        INSERT INTO investigations (target, investigation_type, risk_score, risk_level, summary, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
    """, (target, inv_type, int(risk_score), risk_level, summary, details_str))
    
    inv_id = cursor.lastrowid
    
    # Log corresponding activity
    cursor.execute("""
        INSERT INTO activity_logs (event_type, target, description, created_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
    """, (f"{inv_type.upper()}_COMPLETED", target, f"Analysis executed. Risk: {risk_level} ({risk_score}/100)"))
    
    conn.commit()
    conn.close()
    return inv_id

def get_investigations(limit=50, offset=0, inv_type=None, risk_level=None, search=None, sort_order="desc"):
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT id, target, investigation_type, risk_score, risk_level, summary, created_at FROM investigations WHERE 1=1"
    params = []
    
    if inv_type and inv_type != "all":
        query += " AND investigation_type = ?"
        params.append(inv_type)
        
    if risk_level and risk_level != "all":
        query += " AND risk_level = ?"
        params.append(risk_level)
        
    if search:
        query += " AND (target LIKE ? OR summary LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard])
        
    order = "DESC" if sort_order.lower() == "desc" else "ASC"
    query += f" ORDER BY id {order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

def get_investigation_by_id(inv_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    try:
        res["details"] = json.loads(res["details_json"])
    except Exception:
        res["details"] = {}
    return res

def delete_investigation(inv_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_all_investigations():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM investigations")
    cursor.execute("DELETE FROM activity_logs")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('investigations', 'activity_logs')")
    conn.commit()
    conn.close()
    return True

def get_statistics():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Total URLs Analyzed
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE investigation_type IN ('url_analysis', 'redirect_inspection', 'threat_scan')")
    total_urls = cursor.fetchone()[0]
    
    # 2. Total Domains Investigated
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE investigation_type = 'domain_intelligence'")
    total_domains = cursor.fetchone()[0]
    
    # 3. Total OSINT Queries Generated
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE investigation_type = 'osint_query'")
    total_queries_runs = cursor.fetchone()[0]
    
    # Calculate total individual queries by summing count from json or baseline
    cursor.execute("SELECT details_json FROM investigations WHERE investigation_type = 'osint_query'")
    query_rows = cursor.fetchall()
    total_queries = 0
    for r in query_rows:
        try:
            d = json.loads(r[0])
            total_queries += d.get("total_queries", 10)
        except Exception:
            total_queries += 10
            
    # 4. Suspicious URLs Detected (risk_score >= 30)
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_score >= 30")
    suspicious_count = cursor.fetchone()[0]
    
    # 5. Risk Distribution
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_level = 'Low'")
    low_risk = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_level = 'Medium'")
    med_risk = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_level = 'High'")
    high_risk = cursor.fetchone()[0]
    
    # 6. Activity Timeline (last 7 days)
    today = datetime.now().date()
    date_labels = []
    url_counts = []
    domain_counts = []
    osint_counts = []
    
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        date_labels.append(day.strftime("%b %d"))
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE date(created_at) = ? AND investigation_type IN ('url_analysis', 'redirect_inspection', 'threat_scan')", (day_str,))
        url_counts.append(cursor.fetchone()[0])
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE date(created_at) = ? AND investigation_type = 'domain_intelligence'", (day_str,))
        domain_counts.append(cursor.fetchone()[0])
        
        cursor.execute("SELECT COUNT(*) FROM investigations WHERE date(created_at) = ? AND investigation_type = 'osint_query'", (day_str,))
        osint_counts.append(cursor.fetchone()[0])
        
    # 7. Total investigations count
    cursor.execute("SELECT COUNT(*) FROM investigations")
    total_investigations = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total_urls": total_urls,
        "total_domains": total_domains,
        "total_queries": total_queries,
        "suspicious_count": suspicious_count,
        "total_investigations": total_investigations,
        "risk_distribution": {
            "low": low_risk,
            "medium": med_risk,
            "high": high_risk
        },
        "timeline": {
            "labels": date_labels,
            "urls": url_counts,
            "domains": domain_counts,
            "osint": osint_counts
        }
    }

def log_activity(event_type, target, description):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO activity_logs (event_type, target, description, created_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
    """, (event_type, target, description))
    conn.commit()
    conn.close()

def get_recent_activities(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, event_type, target, description, created_at 
        FROM activity_logs 
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_setting(key, default=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key, value):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO app_settings (setting_key, setting_value, updated_at)
        VALUES (?, ?, datetime('now', 'localtime'))
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at
    """, (key, str(value)))
    conn.commit()
    conn.close()

