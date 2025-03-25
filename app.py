import subprocess
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, Response
from flask_migrate import Migrate
from datetime import datetime, timedelta, timezone
from pytz import timezone, utc
from models import db, Log, Alert, Rule, Agent
import psutil
import json
import time
import logging
import os
import ctypes
import sys
import smtplib
from email.mime.text import MIMEText
import getpass
from rule_engine import RuleEngine
import requests

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # Better to use environment variable
db.init_app(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Dummy admin credentials for demonstration - Better to use environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password')

# Email configuration - Better to use environment variables
EMAIL_FROM = os.environ.get('EMAIL_FROM', "your_email@gmail.com")
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', "your_app_password")
EMAIL_TO = os.environ.get('EMAIL_TO', "admin@example.com")

rules = [
    {
        "id": 1,
        "name": "High Severity Process Start",
        "condition": '{"event_type": "process_start", "severity": "high"}',
        "severity": "high"
    },
    {
        "id": 2,
        "name": "Suspicious Remote Connection",
        "condition": '{"event_type": "network_connection", "remote_address": "10.0.0.1"}',
        "severity": "medium"
    }
]

rule_engine = RuleEngine(rules, debug=False)

def parse_datetime(datetime_str):
    return datetime.fromisoformat(datetime_str)

def convert_utc_to_ist(utc_dt):
    ist = timezone('Asia/Kolkata')
    utc_dt = utc_dt.replace(tzinfo=utc)
    ist_dt = utc_dt.astimezone(ist)
    return ist_dt.strftime('%Y-%m-%d %H:%M:%S')

def send_email(subject, body, to_email):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = to_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
        logging.info("Email sent successfully.")
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication Error: Invalid email credentials.")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

@app.route('/')
def home():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    # Convert alert timestamps to IST
    for alert in alerts:
        alert.timestamp = convert_utc_to_ist(alert.timestamp)
    return render_template('home.html', alerts=alerts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/disconnect_agent', methods=['POST'])
def disconnect_agent():
    # Check authentication
    if 'logged_in' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    logging.debug("Disconnect agent endpoint hit")

    # Hardcoded hostname
    hostname = "DESKTOP-TFFCF9K"  # Replace with the actual hostname
    logging.debug(f"Using hardcoded hostname: {hostname}")

    agent = Agent.query.filter_by(hostname=hostname).first()
    if agent:
        agent.status = "disconnected"
        db.session.commit()
        logging.debug(f"Agent {hostname} disconnected in database")

        # Notify the agent to block traffic
        try:
            response = requests.post(
                f"http://192.168.29.131:5001/block_traffic",  # Use the agent's correct IP address
                json={},  # No additional data needed
                timeout=5
            )
            if response.status_code == 200:
                logging.info(f"Agent {hostname} blocked traffic successfully.")
            else:
                logging.error(f"Failed to notify agent to block traffic: {response.text}")
        except Exception as e:
            logging.error(f"Error notifying agent to block traffic: {e}")

        return jsonify({"status": "success", "message": f"Agent {hostname} disconnected"}), 200
    else:
        logging.debug(f"Agent {hostname} not found")
        return jsonify({"status": "error", "message": f"Agent {hostname} not found"}), 404

@app.route('/reconnect_agent', methods=['POST'])
def reconnect_agent():
    # Check authentication
    if 'logged_in' not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    logging.debug("Reconnect agent endpoint hit")

    # Hardcoded hostname
    hostname = "DESKTOP-TFFCF9K"  # Replace with the actual hostname
    logging.debug(f"Using hardcoded hostname: {hostname}")

    agent = Agent.query.filter_by(hostname=hostname).first()
    if agent:
        agent.status = "connected"
        db.session.commit()
        logging.debug(f"Agent {hostname} reconnected in database")

        # Notify the agent to unblock traffic
        try:
            response = requests.post(
                f"http://192.168.29.131:5001/unblock_traffic",  # Use the agent's correct IP address
                json={},  # No additional data needed
                timeout=5
            )
            if response.status_code == 200:
                logging.info(f"Agent {hostname} unblocked traffic successfully.")
            else:
                logging.error(f"Failed to notify agent to unblock traffic: {response.text}")
        except Exception as e:
            logging.error(f"Error notifying agent to unblock traffic: {e}")

        return jsonify({"status": "success", "message": f"Agent {hostname} reconnected"}), 200
    else:
        logging.debug(f"Agent {hostname} not found")
        return jsonify({"status": "error", "message": f"Agent {hostname} not found"}), 404
@app.route('/logs')
def get_logs():  # This was missing the @app.route decorator
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    selected_date = request.args.get('date', None)

    query = Log.query.order_by(Log.timestamp.desc())

    if selected_date:
        try:
            # Parse date and create datetime range in UTC
            start_of_day = datetime.strptime(selected_date, '%Y-%m-%d').replace(
                tzinfo=timezone('UTC'))
            end_of_day = start_of_day + timedelta(days=1)
            query = query.filter(Log.timestamp >= start_of_day, 
                               Log.timestamp < end_of_day)
        except ValueError as e:
            app.logger.error(f"Error parsing date: {e}")

    paginated_logs = query.paginate(page=page, per_page=per_page, error_out=False)

    logs_data = []
    for log in paginated_logs.items:
        try:
            logs_data.append({
                'timestamp': convert_utc_to_ist(log.timestamp),
                'event_type': log.event_type,
                'process_name': log.process_name,
                'user': log.user,
                'command_line': log.command_line,
                'local_address': log.local_address,
                'local_port': log.local_port,
                'remote_address': log.remote_address,
                'remote_port': log.remote_port,
                'file_path': log.file_path,
                'file_size': log.file_size,
                'last_modified': convert_utc_to_ist(log.last_modified) if log.last_modified else None,
                'severity': log.severity,
                'hostname': log.hostname,
                'mitre_technique': log.mitre_technique,
                'network_connection': log.network_connection
            })
        except Exception as e:
            app.logger.error(f"Error processing log {log.id}: {e}")
            continue

    return jsonify({
        'logs': logs_data,
        'total_logs': paginated_logs.total,
        'current_page': paginated_logs.page,
        'per_page': paginated_logs.per_page
    })

@app.route('/export_logs')
def export_logs():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    selected_date = request.args.get('date', None)
    query = Log.query.order_by(Log.timestamp.desc())

    if selected_date:
        try:
            start_of_day = datetime.strptime(selected_date, '%Y-%m-%d').replace(
                tzinfo=timezone('UTC'))
            end_of_day = start_of_day + timedelta(days=1)
            query = query.filter(Log.timestamp >= start_of_day, 
                               Log.timestamp < end_of_day)
        except ValueError as e:
            app.logger.error(f"Error parsing date: {e}")

    logs = query.all()
    # ... rest of CSV generation code ...
         

@app.route('/view_logs')
def view_logs():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('logs.html')

@app.route('/view_processes')
def view_processes():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('processes.html')

@app.route('/system-stats')
def system_stats():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    net_io = psutil.net_io_counters()
    stats = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "network_sent": net_io.bytes_sent,
        "network_received": net_io.bytes_recv,
        "activeAgents": 1,  # Dummy data
        "disconnectedAgents": 0,  # Dummy data
        "criticalAlerts": 0,  # Dummy data
        "highAlerts": 0,  # Dummy data
        "mediumAlerts": 0   # Dummy data
    }
    return jsonify(stats)

@app.route('/process-stats')
def process_stats():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        processes.append(proc.info)

    return jsonify(processes)

@app.route('/alerts/stream')
def alert_stream():
    def generate():
        with app.app_context():
            while True:
                alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
                alert_data = [{
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "log_entry": json.loads(alert.log_entry),  # Deserialize JSON string
                    "timestamp": convert_utc_to_ist(alert.timestamp)  # Convert to IST
                } for alert in alerts]
                yield f"data: {json.dumps(alert_data)}\n\n"
                time.sleep(5)  # Send updates every 5 seconds
    return Response(generate(), mimetype='text/event-stream')

@app.route('/ingest', methods=['POST'])
def ingest_logs():
    data = request.json
    alerts = []
    for item in data:
        log = Log(
            timestamp=parse_datetime(item['timestamp']),  # Assuming parse_datetime returns UTC
            event_type=item.get('event_type'),
            process_name=item.get('process_name'),
            pid=item.get('pid'),
            ppid=item.get('ppid'),
            user=item.get('user'),
            command_line=item.get('command_line'),
            local_address=item.get('local_address'),
            local_port=item.get('local_port'),
            remote_address=item.get('remote_address'),
            network_connection=item.get('network_connection'),
            remote_port=item.get('remote_port'),
            file_path=item.get('file_path'),
            file_size=item.get('file_size'),
            last_modified=parse_datetime(item.get('last_modified')) if item.get('last_modified') else None,
            cpu_usage=item.get('cpu_usage'),
            memory_usage=item.get('memory_usage'),
            disk_usage=item.get('disk_usage'),
            severity=item.get('severity'),
            hostname=item.get('hostname'),
            mitre_technique=item.get('mitre_technique')
        )
        
        db.session.add(log)
        generated_alerts = rule_engine.evaluate(item)
        for alert in generated_alerts:
            # Serialize the log_entry dictionary into a JSON string
            log_entry_json = json.dumps(alert['log_entry'])
            alert_entry = Alert(
                rule_id=alert['rule_id'],
                rule_name=alert['rule_name'],
                severity=alert['severity'],
                log_entry=log_entry_json,  # Store as JSON string
                timestamp=datetime.utcnow()  # Add a timestamp
            )
            db.session.add(alert_entry)
            alerts.append(alert)

            # Send email notification for high/critical alerts
            if alert['severity'] in ["high", "critical"]:
                subject = f"EDR Alert: {alert['rule_name']}"
                body = f"An alert was triggered:\n\nRule: {alert['rule_name']}\nSeverity: {alert['severity']}\nLog Entry: {alert['log_entry']}"
                send_email(subject, body, EMAIL_TO)

    db.session.commit()
    return jsonify({"status": "success", "alerts": alerts}), 200

@app.route('/rules', methods=['GET'])
def get_rules():
    rules = Rule.query.all()
    return jsonify([{
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "condition": rule.condition,
        "severity": rule.severity
    } for rule in rules])

@app.route('/rules', methods=['POST'])
def add_rule():
    data = request.json
    new_rule = Rule(
        id=data['id'],
        name=data['name'],
        description=data.get('description'),
        condition=data['condition'],
        severity=data['severity']
    )
    db.session.add(new_rule)
    db.session.commit()
    return jsonify({"status": "success", "message": "Rule added"}), 201

@app.route('/register_agent', methods=['POST'])
def register_agent():
    """
    Register a new agent with the server.
    """
    data = request.json
    hostname = data.get('hostname')
    ip_address = request.remote_addr  # Get the IP address of the agent

    if not hostname:
        return jsonify({"status": "error", "message": "Hostname is required"}), 400

    # Check if the agent already exists
    agent = Agent.query.filter_by(hostname=hostname).first()
    if agent:
        return jsonify({"status": "success", "message": "Agent already registered"}), 200

    # Create a new agent
    new_agent = Agent(hostname=hostname, ip_address=ip_address, status="connected")
    db.session.add(new_agent)
    db.session.commit()

    return jsonify({"status": "success", "message": "Agent registered successfully"}), 200

@app.route('/rules/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    rule = Rule.query.get(rule_id)
    if not rule:
        return jsonify({"status": "error", "message": "Rule not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"status": "success", "message": "Rule deleted"}), 200

if __name__ == '__main__':
    # Check if the script is running with admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Relaunch the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        # Log the user context
        logging.info(f"Running as user: {getpass.getuser()}")
        logging.info(f"Environment: {os.environ}")
        logging.info(f"Path: {os.environ['PATH']}")

        # Create database tables and start the Flask app
        with app.app_context():
            db.create_all()
        
        # Use environment variables for host and debug mode
        debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
        host = os.environ.get('HOST', '0.0.0.0')  # Default to localhost for security
        port = int(os.environ.get('PORT', 5000))  # Default to port 5000

        # Start the Flask app
        try:
            app.run(debug=debug_mode, host=host, port=port)
        except Exception as e:
            logging.error(f"Failed to start Flask app: {e}")
            if "Address already in use" in str(e):
                logging.error(f"Port {port} is already in use. Please choose a different port.")