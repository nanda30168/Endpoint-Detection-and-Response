from datetime import datetime
from extensions import db

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50))
    process_name = db.Column(db.String(100))
    pid = db.Column(db.Integer)
    ppid = db.Column(db.Integer)
    user = db.Column(db.String(50))
    command_line = db.Column(db.String(200))
    local_address = db.Column(db.String(50))
    local_port = db.Column(db.Integer)
    remote_address = db.Column(db.String(50))
    remote_port = db.Column(db.Integer)
    file_path = db.Column(db.String(200))
    file_size = db.Column(db.Integer)
    last_modified = db.Column(db.DateTime)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    severity = db.Column(db.String(20))
    hostname = db.Column(db.String(100))
    mitre_technique = db.Column(db.String(100))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    log_entry = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    condition = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="connected")